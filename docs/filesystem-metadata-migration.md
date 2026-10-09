# Filesystem metadata integration and acceptance migration

Ordinary codesign invocations use APFS's filesystem-selected metadata view. There
is no CLI setting for a carrier file or metadata map. macOS delegates selection
to the filesystem; Linux and Windows FAT/exFAT storage uses the associated
`._name`. Other filesystems keep their native namespaces. Explicit snapshots and
object bindings remain supported library inputs.

This branch is still being qualified. Removing the parser switches does not by
itself close Phase 2 or establish acceptance on foreign FAT volumes.

## Removed CLI contracts and retained requirements

| Former CLI test | Disposition and retained coverage |
| --- | --- |
| `TestAppleDoubleArguments`, `TestAppleDoubleMapArguments` | Retire routing-switch combinations. `TestMetadataRoutingFlagsRejected` requires both switches to be rejected, including attached values, and absent from help. |
| `TestAppleDoubleManifest` | Retire the CLI JSON manifest parser and its size/binding-count limits. Library bindings remain covered by `TestBundleSidebandBindingValidation`, `TestBundleSidebandHardLinkBinding` and `TestBundleSidebandDeferredErrors`. |
| `TestAppleDoubleCLIDiagnostics` | Replace explicit-carrier CLI invocation with filesystem-selected metadata acceptance. Existing object/error policy remains covered by `TestSidebandOptionsAndErrorOrder` and the sideband policy tests. CLI filesystem acceptance remains a required migration below. |
| `TestSigningMetadataInputErrors` | Retire errors for opening a caller-selected CLI metadata file/map. Preserve real filesystem acquisition/identity errors in APFS and explicit library carrier failures in `TestCarrierFailures` and `TestStripCarrierLifecycle`. |
| `TestMutableCarrierCommit` | Retire the CLI-owned canonical snapshot commit helper. Filesystem storage uses APFS's in-place VFS mutation tests; explicit library callers own their mutable-carrier implementation. `TestRewriteCarrierValues` retains the canonical library rewrite contract. |
| `TestCarrierCancellationAndSharedManifest` | Retire shared CLI-manifest semantics. Keep mutation cancellation and partial effects in `TestStripCarrierLifecycle`, `TestGenericSignatureProtocol`, and APFS's `TestFilesystemMetadataRemovalFailures`. |
| Strip-option argument checks in the removed files | Retain them in `TestStripDisallowedArguments`. |

APFS's retained native replay covers 360 FAT removal cases and both snapshots of
1,440 FAT read cases from macOS 15, 26 and 27. Mutation codec comparisons include
180 valid-carrier byte outcomes. These tests establish the shared API's captured
behavior; they are not substitutes for invoking the codesign CLI on real volumes.

## Qualified local integration and remaining acceptance

The dependency pins `9ab5cf856eb5` from draft
[APFS #222](https://github.com/deploymenttheory/go-apfs-v2/pull/222), including
merged main through `5c7222ef9172`, without a local module replacement. Both
repositories' final-revision CI and the upstream merge remain required.

Standalone and bundle executable writes use APFS's `PublishContext` after
metadata restoration. Foreign FAT/exFAT replacements privately reconstruct the
native filesystem carrier, then publish both entries. This fixes the observed
203-byte retained carrier versus Apple's fresh 4096-byte carrier after stripping
disallowed metadata. The SDK retains identity checks and reports metadata
publication failures after a committed data rename explicitly. No CLI routing
option is introduced.

`TestFilesystemMetadataCLI` passes locally against Apple's codesign on real
FAT32 and exFAT volumes for verification, stripping before signing, and removal.
The standalone sideband verification, alias and architecture-selection matrices
also pass locally with ordinary CLI arguments. Their existing policy, corruption,
identity and preservation assertions remain. AppleDouble verification and
architecture cases use actual exFAT storage and the Clang-produced seeds in
[`testdata/filesystem-metadata`](../testdata/filesystem-metadata/README.md).
The ordinary-filesystem control also checks that a neighboring `._fixture` is
not automatically interpreted as metadata.

The 24 `TestFilesystemMetadataBundles` cases compare real FAT32/exFAT bundle
signing at the root, executable and resource locations, with and without
stripping, both with minimal contents and with native-produced attribute files.
Local comparisons include complete post-operation tree archives, root carriers,
diagnostics and native verification. Failure cases retain partial filesystem
effects in the exported result as well as successful signatures. Native readback
requires all 24 results from each foreign producer and compares them with fresh
Apple operations on the same filesystem profile.
Bundle root validation only exempts valid companions on attribute-file storage.
Signing still encounters attribute files in nested-code locations; verification
can exempt present, valid attribute files while retaining missing-resource checks.
Signing preserves filesystem enumeration order because stripping a resource can
change the bytes of a later-enumerated companion before sealing it. These rules
are backed by the complete Apple bodies in `spec/apple-nested-apps.json` and the
existing Clang extractor, with explicit declaration shims.

Generic removal's seventeen-shape matrix, alias, write-denial and dry-run cases use actual host
attributes and ordinary CLI arguments. They retain object identity, unrelated
attribute preservation, effective-denial controls and macOS comparisons. Linux
`user.com.apple.cs.*` values remain unrelated namespace values; actual macOS
signature attributes on FAT use the filesystem metadata tests.

`TestFilesystemMetadataRemoval` adds 54 native comparisons: nine representable
shapes, three attribute states and both FAT filesystems. The genuine packed-empty
input exposes native namespace rejection, including the partial removal of bundle
signature components before the later attribute-enumeration failure. The test
retains every attribute value, raw carrier bytes, data bytes, held-object identity,
diagnostic and envelope result. APFS #219 supplies the matching filesystem decoder;
the lossless snapshot decoder still accepts those captured bytes.

`TestFilesystemMetadataDiscovery` adds 80 native comparisons across the complete
flat app/framework empty-info and platform-plist selection cases on both FAT
filesystems. These prove canonical signature removal on the selected object using
ordinary CLI arguments. Versioned frameworks require symlinks and remain in the
ordinary-filesystem suite and full library corpus replay.

The plist CLI matrices use actual host attributes. Linux `user.com.apple.cs.*`
values must survive removal; treating them as canonical macOS signature slots
would introduce a false filesystem behavior. Foreign readback recreates each
producer's actual namespace on macOS, rejects duplicate/unknown producers and
requires both Linux and Windows outcomes. All captured plist-selection cases
also retain the canonical-signature assertions in the library replay; the FAT
CLI matrix independently exercises filesystem-selected canonical attributes.

Foreign export membership adds 164 records per producer: six standalone CLI
outcomes, 24 bundle outcomes, 54 generic removals and 80 discovery cases. The
standalone comparisons retain exact signed data and carrier bytes with identical
fixture basenames, preserving Apple's default identifier derivation.

These local macOS results do not establish Linux/Windows runtime acceptance or
complete macOS 15/26 qualification. CI provisioning, foreign artifact readback
and the following qualification remains required.

The foreign runtime matrix exposed a further dependency correction tracked in
[APFS #220](https://github.com/deploymenttheory/go-apfs-v2/pull/220): a metadata
query on a regular attribute file must retain native `EPERM`, distinct from
`EACCES`. The consumer applies Apple's presence-query exception to the
filesystem-selected AppleDouble backend while retaining fatal removal errors.
The merged #220 commit is now pinned. The affected resource-signing cases remain
required in the downstream Linux/Windows runtime and native readback gates.

Windows executable replacement retains a staged read handle through rename and
refreshes its identity through that handle, because FAT file IDs can change on
rename. Subsequent pathname checks still reject substitution. Mach-O removal
retains its native purge order; canonical component removal before attribute
flush belongs to generic FileDiskRep removal. Both regression matrices remain
required. Discovery fixture setup removes only incidental macOS-created attribute
files before installing captured inputs; full post-operation tree comparisons
remain unchanged.

Verification also obtains each directory entry's identity with APFS's existing
rooted metadata query. Go's Windows directory enumeration can omit file IDs on
FAT/exFAT; comparing those incomplete records with held files falsely reports
unchanged resources as replacements. Rooted metadata queries avoid that mismatch
without requesting unrelated data or EA rights. Verification keeps lexical
traversal order, while signing keeps the native filesystem order.

No acceptance invocation uses the removed routing switches. Bundle verification,
signing, paths, fallback removal and plist discovery now use ordinary CLI arguments.
Their native object, policy, alias, authorization and preservation assertions
remain; real-volume tests replace caller-selected carrier routing. The obsolete
second run of the same native case through a CLI metadata map is removed.

- Complete the old-case-to-native-requirement audit, including remaining valid
  FAT signing/verification combinations, instead of assuming the smaller real-volume
  matrix covers every formerly caller-selected combination.
- Qualify native verification of Linux/Windows-produced results and reconcile
  exact case, export and attestation inventories in the strict CI plan.
- Recapture module-bound native evidence after dependency or producer changes;
  never rewrite old source hashes to make provenance checks pass.

Real FAT/exFAT volume creation and cleanup must be qualified on all three CI
hosts. No private test selector or direct library call may stand in for CLI
filesystem acceptance. Broader APFS creation/assignment, authorization and
association requirements remain in the Phase 2 completion ledger.

### Versioned signing results

The native CLI uses APFS `osversion.Detect` to select macOS 15, 26 or 27 signing
behavior. Linux and Windows use the macOS 27 reference default. Library callers
can set `SignOptions.MacOSProfile` on any host; zero retains the macOS 27 default.
No additional CLI option or environment override is introduced. Unknown native
macOS major versions are rejected rather than silently assigned another profile.

The qualified version differences are ad-hoc CMS space reservation (15/26) and
default ARM64 signing pages (4 KiB on 15, 16 KiB on 26/27).
Resource-preflight errors follow actual traversal and reached nested work;
they are not selected by OS major version. This is not complete per-version signing parity. Retained native
archives, source provenance and SDK ASTs are in
[`testdata/filesystem-metadata/profiles`](../testdata/filesystem-metadata/profiles/README.md).
All hosts replay the native signature bytes. The existing macOS 15/26 jobs and
macOS 27 suite additionally require live allocation-alignment comparisons and
repeated default/serial resource-error probes. These add assertions without
relaxing the existing whole-bundle comparisons or foreign readback requirements.

### Traversal and partial work

PR107 incorrectly assigned the competing resource/nested error to an OS major
version. The same final file bytes can occupy different directory positions.
Native-created attribute files can leave reusable FAT slots when fixture cleanup
removes them; later attribute files can reuse those slots. SDK `fts_read` and Go's
unsorted rooted enumeration observe this input difference.

The resource-order probe uses Apple's `ResourceBuilder` FTS flags with the real
SDK declarations and records attribute sizes, traversal, source hashes and both
architecture ASTs. The native test predicts the first failure from this independent
trace; it still requires the exact diagnostic and unchanged complete data tree.
Additional Linux/macOS/Windows cases establish both resource-first and nested-first
creation sequences and require their distinct outcomes. Native default and serial
observations remain separate. Shallow signing stops at the first reached resource
failure. Deep signing retains its existing, independently captured nested partial
results. Exact admission, stop and completion behavior for parallel and serial
deep signing remains outstanding in P02-SCHED; shallow traversal evidence does
not close that workstream.
