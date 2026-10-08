# Sideband metadata and verification policy

Sideband data is metadata attached to code or resources outside their ordinary
file bytes. Apple's strict sideband policy rejects nonempty ResourceFork and
FinderInfo attributes on applicable objects. Reading those attributes correctly
is a prerequisite for matching its verification decisions and diagnostics.

Codesign uses the [shared APFS filesystem metadata view](apfs-dependency.md)
for storage selection, held queries and mutations, and its AppleDouble codec for
explicit library snapshots. Filesystem selection is automatic; metadata-routing
CLI flags are not part of the command interface.

The [read-only adapter](../internal/sideband/sideband.go) is connected to
standalone and bundle verification. `--strict=sideband`, plain `--strict`, `--strict=all`
and equivalent numeric masks reject prohibited metadata on standalone Mach-O
inputs. UDIF inputs retain Apple's behavior: strict verification checks their
signature/trailer but does not reject sideband metadata. Bundle traversal checks
the supported resource-envelope/layout profiles, including nested code and framework
versions. [Signing preflight and stripping](signing-sideband.md) now use the same
metadata policy, with separately qualified mutation and failure ordering.

```sh
macoscodesign --verify --strict=sideband --verbose=1 executable
```

The CLI observes the metadata exposed by the selected filesystem. macOS uses
native filesystem dispatch; Linux and Windows FAT/exFAT volumes associate
`._name` with the held object. On other filesystems a neighboring file does not
change native attributes. Library callers may additionally supply
`VerifyOptions.AppleDouble` and retain ownership of that snapshot.
Byte-only Mach-O verification rejects enabled sideband policy because it cannot
observe a native object. UDIF byte verification needs no sideband observation.

## Bundle traversal and library metadata bindings

Bundle verification checks signed code and special slots, then included resources,
then the canonical bundle root and main executable. Resource checks follow links
before comparing their sealed text, including under `--strict=sideband` alone.
Both prohibited attributes can be reported on a resource; root/executable checks
stop at the first one. Local resource errors accumulate, while nested exceptions
propagate with the native subcomponent diagnostic. Other framework-version errors
use Apple's aggregate invalid-version diagnostic without leaking child details.

Shallow verification checks immediate nested code and its root/executable, but
does not descend into its resources. `--deep` extends the traversal. Nested
frameworks check every physical version; an outer framework checks its selected
version. `--ignore-resources` suppresses resources and children, retaining the
outer root/executable checks. `--strict=none` and `--no-strict` disable sideband
policy. Ordinary directory metadata, omitted resources and signature files are
not blanket-rejected. Framework `Resources/Info.plist` is an included resource;
app `Contents/Info.plist` is excluded. A versioned framework's canonical root is
its selected version, with `Versions/Current/.` retained in native diagnostics.

Library `VerifyOptions.AppleDoubleFiles` maps object paths to caller-owned
`appledouble.Value` sources. Bindings resolve by filesystem identity, including
supported symbolic and hard-link aliases; conflicting aliases are rejected.
The verifier captures filesystem queries while holding each resource used for
hashing and defers policy errors until its validation stage. This bounds open
handles while preserving integrity-error precedence. Inputs and bindings must
remain stable; held identity does not provide an atomic content snapshot.

Resource opens reproduce Darwin's 32-link limit on all three hosts, including
framework selection aliases. Strict destination validation separately retains its
33-link realpath limit. ENOENT, ELOOP and ENOTDIR preserve their native diagnostic
precedence over seal-text mismatches. Sources are the host SDK's `sys/param.h`,
[XNU's MAXSYMLINKS definition](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/param.h)
and the pinned Security bodies in `spec/apple-sideband.json` and
`spec/apple-resource-verification.json`. The Clang extractor checks MAXSYMLINKS
on both targets and includes complete bundle-root-to-executable delegation.

`acceptance/sideband_bundle_test.go` runs native-filesystem matrices on Linux, macOS
and Windows. macOS additionally compares Apple's output, preserves raw observations
and checks input preservation. Resource detail arrays are compared as complete
multisets because Apple's workers/CF collections do not provide a stable ordering;
status, diagnostic text, paths and multiplicity must match. Link-failure observations
retain the previously qualified native `--strict=4096` reference control to avoid
the recorded Apple asynchronous crash; no policy is disabled and no retry hides a
failure. Existing native-signing strict tests now compare all implemented selectors.

## Standalone ordering and lifetime

`Verify` resolves aliases and reads code bytes and native metadata through the
same held file. It does not reopen the operand after signature verification.
Symbolic aliases report the resolved target in attached-data details; hard links
retain their selected path. A caller-supplied AppleDouble source is borrowed;
the library caller owns its lifetime. The filesystem view borrows the held file
and releases its independently acquired association handles.
Inputs must remain stable: holding the object prevents pathname substitution
between these reads, but does not create an atomic snapshot of concurrent edits.

Code pages, CMS/trust and signed slots are checked before sideband inspection.
ResourceFork is checked before FinderInfo; the first nonempty attribute produces
one attached-data detail, with no architecture line. A positive native ResourceFork
rejects immediately, without reading FinderInfo or a carrier. Otherwise the carrier
is decoded when needed to establish the first matching attribute. Errors from
required observations propagate. Remaining Mach-O layout checks run afterwards.
`--ignore-resources` leaves this standalone check active; `--no-strict` and
`--strict=none` disable it without disabling signature verification.

`DiskImageRep::strictValidate` calls `DiskRep` directly, bypassing the
`SingleDiskRep` sideband branch. The Go implementation therefore does not query or
decode sideband inputs for UDIF verification, even when a carrier is supplied.
The native corpus proves acceptance with fork/FinderInfo data and continued
rejection of corrupted signed DMG bytes. This is a representation-specific native
policy, not a missing Linux or Windows implementation.

The standalone acceptance matrix has 386 cases: 378 combinations of representation,
state, metadata transport and policy, two aliases, and six selected-architecture
cases. Each runs on every host; macOS additionally compares exact native status
and output (only the separate native fixture's path prefix is normalized).
Byte/mode/link archives, complete visible attribute values and carrier bytes are
checked for preservation. Test signatures are ad-hoc and require no keychain.
Portable unit tests additionally cover certificate trust precedence, malformed
carriers, JSON/quiet diagnostics, cancellation and moved held objects through the
shared APFS opener, including Windows delete-sharing.

## Explicit AppleDouble input

Library callers may supply an explicit additional snapshot on all three hosts.
Filesystem-selected attributes are also inspected, so an empty snapshot cannot
conceal a visible native or FAT-backed value. APFS owns discovery of genuine
filesystem storage; the snapshot API never changes that selection.

| Input | Inspection contract |
| --- | --- |
| macOS native | APFS held size queries, ordinary visible namespace; only Darwin EPERM is ignored by the measured Apple presence policy |
| Windows native | APFS held native EA queries with Windows name semantics; failures propagate |
| Linux native | APFS complete strict name inventory; query canonical names only when listed; no `user.com.apple.*` remapping |
| Linux/Windows FAT storage | APFS binds the held object to its associated VFS carrier; names are case-sensitive and invalid-header size queries report absence |
| Explicit AppleDouble | APFS streaming decode validates the complete header and referenced spans; nonempty fork, nonzero fixed FinderInfo, and every nonempty special-name ATTR record are additional observations |

The fixed FinderInfo field is mandatory padding even when absent; an all-zero
field does not declare an attribute. A named FinderInfo ATTR record explicitly
declares a 32-byte attribute, including an all-zero value. Duplicate records are
all inspected: a later empty record cannot cancel an earlier positive observation.
This is inspection of a supplied metadata snapshot, **not a simulation of
copyfile restore**, whose cleanup, ordered writes, zero-value normalization,
authorization and partial failures belong to APFS. Ordinary attribute payloads
are not read or applied. Standalone association and bundle object maps are explicit;
the latter also bind followed resource links by identity.

The native and carrier results are combined only after successful reads. Inventory,
size, decode, budget, cancellation and I/O failures return an error with its cause
and no partial success. Native inspection ignores zero lengths. The Darwin EPERM
exception does not apply to Linux inventory failures, Windows errors or EACCES.
The caller owns input stability; cancellation cannot interrupt an in-flight native
syscall. Streaming checks accept the full uint32 fork length without allocating
the fork. Successful indexing proves valid declared spans, not that every payload
byte can subsequently be read or restored.

Unit tests cover additive inputs, duplicates, malformed/truncated carriers, native
failure distinctions, cancellation, held-file lifetime and offsets, native attribute
preservation, and the 4 GiB format boundary. The same 29 native-derived snapshots
run on Linux, Windows and macOS; see [fixture provenance](../testdata/sideband/README.md).
The existing per-production-package coverage gate also applies to this adapter.

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

`ListXattrNames` provides a complete bounded inventory or an error; the adapter
uses it on Linux to avoid illegal unnamespaced queries. The existing `ListXattrs`
remains best effort and its legacy compression-aware
Darwin implementation is unchanged. A successful map from that API cannot prove
attribute absence. Codesign must not duplicate the APFS implementation or use
that reader to suppress security-relevant errors.

## Apple source and Clang evidence

[The Go extractor](../scripts/extract-sideband.go) verifies the full source hashes
at Security revision `db15acbe6a7f257a859ad9a3bb86097bfe0679d9` and compiles ten
complete verbatim bodies into Clang ASTs for arm64 and x86_64 macOS 27:

- `FileDesc::getAttrLength`, buffer-form `getAttr` and `removeAttr`.
- `checkFork`, `filehasExtendedAttribute` and `FileDesc::hasExtendedAttribute`.
- `SingleDiskRep::strictValidate` and `BundleDiskRep::strictValidateStructure`.
- `MachORep::strictValidate` and `DiskImageRep::strictValidate`.

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

Bundle integration follows the pinned
[`SecStaticCode::validateResource`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/StaticCode.cpp)
opens a resource path before sideband checking when both strict validation and
sideband restriction are set. This follows resource links and can fail before
link-text validation. That body is retained in the separate
[resource verification AST manifest](../spec/apple-resource-verification.json),
not counted again in the sideband manifest's twelve bodies. The earlier
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
fail the driver. Each executed case additionally compares the Go adapter's native
and explicit-carrier observations against the raw captured attribute values.
Results qualify metadata inspection; they do not assert Go CLI or traversal
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
lower-level AST branch alone. The separate [signing corpus](signing-sideband.md)
now qualifies signing-time stripping and measured partial effects.

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

1. **Merged:** qualify published APFS v0.15.0 and downstream users without a local
   replacement, preserving native, portable, coverage and artifact gates.
2. **Merged in PR71:** the read-only metadata adapter over
   shared strict size/inventory and streaming codec operations, with the explicit
   additive AppleDouble contract above. Native nonempty/EPERM policy lives here;
   platform operations and wire parsing remain in APFS. No mutation is introduced.
3. **Merged in PR72 with green CI:** standalone Mach-O
   metadata policy, explicit carrier binding, selected architectures, aliases,
   diagnostic ordering and the UDIF exception. **Merged in PR73:** main executable,
   bundle-root and resource checks in measured order, with Info.plist/signature
   exclusions, framework versions, nested shallow/deep checks and universal code.
   Retain code/CMS/requirements checks under ignore-resources and disabled strict.
4. **Merged in PR73:** resource-link follow behavior, link-count boundaries,
   dangling/cyclic targets, seal-mismatch precedence, explicit alias binding and
   sideband/all selectors. Existing native-signing plain/all observations now
   require matching portable results. Broader permission/ACL failures, custom rules,
   concurrent mutations, reparse/case/Unicode behavior and native scheduling remain open.
5. **Signing mutation phase:** default preflight, force/already-signed order,
   native and explicit-carrier stripping, dry-run mutations and independent-child
   completion are implemented. See [the signing contract](signing-sideband.md).
   Broader read-only/ACL denial and concurrent-mutation profiles remain open;
   retain byte/attribute/object-identity evidence and all strict CI gates.
6. Run native differential cases, portable unit/CLI coverage above 95%, three-OS
   CI, race/fuzz, foreign-signature imports and six GoReleaser package checks on
   the released dependency. Audit exact source and downloaded package provenance.

The SDK's completed compression and metadata qualification does not establish
codesign's policy integration. Exposing hidden compression metadata is not a
prerequisite inferred from these options-zero sideband checks. No inventory
status is upgraded by dependency adoption alone.
