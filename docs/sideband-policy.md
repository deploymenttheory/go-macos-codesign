# Sideband policy: dependency and research

This phase prepares strict sideband verification and attribute stripping. It does
not enable `--strict=sideband`, plain/all strict selectors or
`--strip-disallowed-xattrs`. Codesign now pins published APFS v0.14.0. The shared
operations introduced in [APFS PR #131](https://github.com/deploymenttheory/go-apfs-v2/pull/131)
are available in `hostdata`; the subsequent AppleDouble/resource-fork work and
package refactor completed in APFS PR182/PR183. macOS-pkg PR72 has adopted that
release and passed its required downstream CI. The optional live notarization
step lacked signing secrets and did not execute.

This dependency phase migrates existing codesign writers to `hostdata` and
`hostdata/accesstime`, retaining their behavior and existing compatibility gates.
It supplies the published prerequisite for sideband integration; it does not
enable a CLI policy solely because the underlying filesystem API is available.

The adoption is currently [blocked by the production dependency guard](apfs-dependency.md):
v0.14.0 adds a transitive Darwin `purego` dependency, including reachable
creation-time behavior. A corrected upstream dependency boundary and published
release are required before this integration can pass codesign qualification.

## Shared API contract

The dependency supplies size, bounded read and removal operations in `hostdata`, each
with a held `*os.File` form and a final-component no-follow pathname form:

| Operation | Held descriptor | Final-component no-follow |
| --- | --- | --- |
| Size/presence | `XattrSize` | `XattrSizeNoFollow` |
| Bounded value | `ReadXattr` | `ReadXattrNoFollow` |
| Removal | `RemoveXattr` | `RemoveXattrNoFollow` |

Only the native missing-attribute result means absence. Empty values remain
present; successful empty reads return a non-nil empty slice. Permission and I/O
errors survive. Unsupported hosts/filesystems return `ErrXattrUnsupported`;
native errno remains available where applicable. Reads accept a caller limit of
zero through 8 MiB. Oversized values return `ErrXattrTooLarge` before allocation.
Observed size changes, disappearance or range errors during reading return
`ErrXattrChanged`, without retries or partial values. Same-size concurrent changes
are not detectable.

Descriptor calls hold `SyscallConn.Control` across the operation, including both
read syscalls. They never reopen `File.Name`, close the caller's file or advance
its position. Darwin `O_SYMLINK` identifies the link; ordinary `os.Open` has
already followed it. Linux `O_PATH` fails with `EBADF` without a fallback.
Path operations only avoid following the final link. They neither contain
intermediate links nor pin the name across calls; production callers need an
appropriately opened descriptor when object identity matters.

Linux, macOS and Windows implement all six operations using supported `x/sys`
wrappers without CGo, helper processes, new native bindings or direct syscalls.
Windows queries and removes native EAs with `NtQueryEaFile`/`NtSetEaFile`,
reopening held objects by an empty relative NT name. Path opens explicitly retain
the final reparse point. The original Windows-unsupported proposal was rejected
and replaced; it is not an acceptable compatibility boundary for this feature.
Windows names follow native case-insensitive ASCII rules and EA size limits;
zero-length assignment deletes an EA. Native queries require a complete record,
so size queries use at most 65,799 bytes of scratch space. Alternate data streams
remain separate and untouched. Attribute
removal is one filesystem operation, not a transaction: hard links share it,
change time may advance, and attribute-specific compression/ACL effects belong
to the filesystem. Ordinary read invisibility is not a guarantee of safe removal.

The existing `ListXattrs` remains best effort and its legacy compression-aware
Darwin implementation is unchanged. A successful map from that API cannot prove
attribute absence. Codesign must not duplicate the APFS implementation or use
that reader to suppress security-relevant errors.

## Apple source and Clang evidence

[The Go extractor](../scripts/extract-sideband.go) verifies the full source hashes
at Security revision `db15acbe6a7f257a859ad9a3bb86097bfe0679d9` and compiles eight
complete verbatim bodies into Clang ASTs for arm64 and x86_64 macOS 27:

- `FileDesc::getAttrLength`, buffer-form `getAttr` and `removeAttr`.
- `checkFork`, `filehasExtendedAttribute` and `FileDesc::hasExtendedAttribute`.
- `SingleDiskRep::strictValidate` and `BundleDiskRep::strictValidateStructure`.

[The manifest](../spec/apple-sideband.json) retains source URLs and hashes,
excerpt/driver/translation-unit hashes, compiler, SDK and per-function AST facts.
SDK filesystem, CoreFoundation and Security declarations are real. Private
interfaces and the strip flag are declaration-only shims. This is source analysis,
not decompilation of the current private CLI or a native production dependency.

The attribute presence helpers pass **options zero**, using ordinary visible
metadata. They do not request `XATTR_SHOWCOMPRESSION`. `checkFork` ignores
zero-length values and both `ENOATTR` and `EPERM`; its comment attributes the
latter to HFS+ ResourceFork queries on non-regular objects. Other failures throw.
The generic size/read/remove helpers have different error semantics. Therefore
the shared APFS API preserves `EPERM`; codesign's later policy layer must apply
only the measured native exception, without treating arbitrary read failure as
absence.

Both strict bodies inspect ResourceFork before FinderInfo and strip before
rejecting prohibited sideband data. Single-file rejection respects tolerated
`errSecCSInvalidAssociatedFileData`; the bundle-root branch does not make that
same tolerance check. The bundle scans its signature metadata directory before
root attributes unless quick-check is selected. It then handles accumulated
structure errors and app-like policy. The single-file code-limit check follows
its attribute handling.

Resource traversal remains a separate integration problem. Pinned
[`SecStaticCode::validateResource`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/StaticCode.cpp)
opens a resource path before sideband checking when both strict validation and
sideband restriction are set. This follows resource links and can fail before
link-text validation. That source review is **not** an additional complete body
in this phase's eight-body AST manifest. The earlier
[native async crash controls](strict-verification.md#native-asynchronous-verification-crash-on-xcode-27)
remain in force.

## Native observations

Run `go run scripts/probe-sideband.go -check` on the reference Mac. It constructs private
standalone/app fixtures from the pinned unsigned arm64 executable, signs them
with `/usr/bin/codesign`, and records verbose verification under seven policies:
default, sideband, all, sideband with ignore-resources, sideband with no-strict,
sideband with strip, and sideband with strip/dry-run. It places clean, empty,
ResourceFork and FinderInfo states on the standalone file, bundle root,
main executable, ordinary resource and signature directory.

`artifacts/sideband/native.json` retains raw arguments, exit/stdout/stderr, host
and native binary identity, fixture/driver hashes and full before/after ordinary
file hashes, modes and the three selected attribute values. Presence of an empty
value differs from an absent map key. Directory ResourceFork setup returning
`EPERM` is recorded as unavailable, without running or counting a codesign
comparison. Signals, timeouts, unexpected setup errors and snapshot read errors
fail the driver. Results characterize native behavior; they do not assert Go
equivalence. Snapshots do not claim timestamp, ACL or every-xattr preservation.

The reference Mac executed 203 commands: 156 accepted and 47 rejected. Another
42 planned policy combinations were unavailable because their directory fork
fixtures could not be created. `-check` requires those counts, exact raw
status/stdout/stderr and unchanged snapshots; CI runs it on the Mac producer.
Omitting `-check` permits exploratory recording without asserting the current
policy outcomes. Both modes reject signals and unexpected setup/snapshot failures.

In this bounded verification corpus, default/no-strict accepted all constructed
attribute states. Sideband/all rejected nonempty prohibited attributes on code,
the bundle root and ordinary resources. Ignore-resources suppressed the resource
case, retaining root/executable checks. FinderInfo on the signature directory
was accepted. Both attributes on a resource produced two stdout details in fork
then FinderInfo order; code objects reported the first fork only.

The native **verification CLI** did not remove attributes with
`--strip-disallowed-xattrs`, with or without `--dryrun`; all byte/mode/selected-attr
snapshots were unchanged. This prevents inferring CLI flag dispatch from the
lower-level AST branch alone. Signing-time stripping and its partial effects
still require a separate corpus.

The independent APFS tests also use native `xattr` creation/read/removal and real
ACL denial. APFS normalizes empty ResourceFork and all-zero FinderInfo values to
absence, while ordinary empty attributes remain present. Its Linux tests cover
permission denial and `O_PATH`; Windows tests require real file/directory EA
lifecycle operations, values through 60,000 bytes, moved handles, old-name decoys,
hard links, held/dangling symlinks, retained streams and six DACL-denial checks.
Windows rename fixtures open with delete-sharing so their held object can move.
No Windows operation is replaced by an unsupported assertion or skip. Hosted
CI enforces over 95% statement coverage specifically in the new strict API and
uploads raw tests, coverage and source hashes. Portable lifecycle values fit
ext4's attribute storage overhead; Mac also exercises 4 KiB values. An 8 MiB API
allocation limit does not promise that a host filesystem can store that value.

The corrected dependency head `6fb41077cb3a863c462f43b15f48b4308d951579`
was tested at PR merge revision `17f38c5ea4e9194c2a4aefe950de6b67b4ae3aa5` in
[run 36333046033](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/36333046033).
Its downloaded strict-API evidence has 86/87 statements (98.85%) covered on both
Mac and Linux and 151/153 (98.69%) on Windows. All 49, 36 and 43 named test records,
respectively, passed with zero skips. An independent audit checked all 14 source
hashes per producer, allowing the 14 recorded Windows CRLF conversions, and
recomputed the counts from the raw coverage profiles. These numbers cover the
new shared API, not the whole APFS repository. The full workflow passed all three
OS unit/image acceptance suites, six builds, three-platform lint, race and
vulnerability checks; associated fuzz checks also passed. The failed Windows rename fixture remains part
of the history; correcting delete-sharing did not remove the identity assertion.

## Production integration sequence

1. The shared API, AppleDouble qualification and package refactor are released in
   APFS v0.14.0. This branch pins that module without an APFS replacement/workspace
   and migrates existing metadata/access-time imports. Complete codesign's own
   native, portable, coverage and artifact gates for this dependency upgrade.
2. Add a codesign policy adapter over the shared size/removal operations. Keep
   present-empty semantics in APFS and native nonempty/EPERM policy here. Decide
   explicit host-filesystem behavior while implementing the feature on Linux,
   macOS and Windows. Never infer absence from an operation failure. Add
   deterministic error-policy tests alongside native fixtures.
3. Extend standalone, main executable, bundle-root and ordinary resource checks
   in measured order. Cover Info.plist and signature metadata separately. Include
   app/framework versions, nested shallow/deep checks and selected architectures.
   Retain code/CMS/requirements checks under ignore-resources and disabled strict.
4. Measure actual resource-link follow behavior and failures before enabling
   sideband/all selectors. Cover aliases, dangling/cyclic links, denied access,
   custom rules, root containment and native error scheduling. Extend retained
   unsupported plain/all observations only when their complete profile is proven.
5. Implement strip as a separately reviewed mutation phase. Measure sign, verify,
   force, dry-run, read-only/ACL denial and multiple-attribute partial failure;
   retain byte/attribute/object-identity evidence. Do not assume `--dryrun` prevents
   changes, that ignored resources are traversed, or that native removal rolls back.
6. Run native differential cases, portable unit/CLI coverage above 95%, three-OS
   CI, race/fuzz, foreign-signature imports and six GoReleaser package checks on
   the released dependency. Audit exact source and downloaded package provenance.

The SDK's completed compression and metadata qualification does not establish
codesign's policy integration. Exposing hidden compression metadata is not a
prerequisite inferred from these options-zero sideband checks. No inventory
status is upgraded by dependency adoption alone.
