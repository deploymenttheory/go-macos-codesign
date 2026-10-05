# Portable I/O and lifecycle phase

Phase 02 covers streaming, filesystem behavior, metadata profiles, cancellation,
partial failures and commit order. It starts from merged PR97
(`12b40468f39d040d66776d3eed6c18b8cd090d48`). The complete scope remains in the
[remaining roadmap](implementation_plan.md#phase-02); none of its seven feature
owners is promoted to full parity by the prerequisite work below.

## Agreed file-processing architecture

Phase 02 includes re-architecting the path-based file-processing pipeline to
remove the arbitrary 1 GiB ceiling. Standalone read-only range integration is described [here](source-range-io.md);
[DMG signing](dmg-streaming.md) now shares range hashing; Mach-O and bundle
builders still hold whole-file byte slices. The signing policy, codecs, APFS
integration and existing acceptance harness remain the foundation.

| Component | Required implementation |
| --- | --- |
| Sources | Held files with known size, checked 64-bit ranges, identity tracking and explicit descriptor ownership |
| Parsing | Read required headers/metadata and bounded subranges; avoid whole-file payload allocations and unbounded metadata tables |
| Hashing | Consume held file ranges incrementally for code pages, special slots and resources |
| Planning/output | Stream source ranges and generated sections according to checked offsets, sizes and alignment |
| Working storage | Share an initial 128 MiB managed-buffer budget across the operation, nested code and concurrent workers; spill or schedule work when it is exhausted |
| Commit/cleanup | Preserve native replacement/in-place differences, metadata, partial failures, Windows handle semantics and temporary-file cleanup |
| APIs | Integrate path operations while retaining byte APIs and their caller ownership/complete-output contracts |

The 128 MiB value is a starting budget to benchmark, not a file-size threshold
or a total-process memory guarantee. Payload size alone must not cause rejection
when streaming or temporary storage can handle it. Runtime/metadata overhead and
caller-owned byte buffers require separate accounting and measurement. Library
operations must not enforce the budget by changing process-global Go settings.

The [Phase 02 implementation sequence](implementation_plan.md#pipeline-implementation-sequence)
specifies six workstreams: native/API audit, held sources and parsing, shared
budgets and hashing, write plans and spill storage, API/CLI integration and ceiling
removal, then scale/failure qualification. Shared filesystem prerequisites belong
in APFS and must be released before consumption. New implementation phases start
from merged main; the current hashing draft is groundwork, not completion of this
pipeline.

Qualification must include real sparse and populated multi-gigabyte files,
boundaries around 1/2/4 GiB, aggregate bundle size, output growth, measured memory
and temporary-storage use, source changes, cancellation and cleanup. Linux and
Windows execute the same supported operations; the macOS harness captures native
behavior and verifies foreign results. Virtual high-offset tests cannot replace
real-file acceptance. All existing exact-case/artifact, >95% per-package/per-OS
coverage, race, fuzz and native CI requirements remain in force.

## Confirmed shared-library prerequisite

The [original six native observations](../testdata/research/filesystem-prerequisite-v0.17.0.json)
compare disposable APFS and HFS+ images using the existing independently produced
unsigned Mach-O fixture. They retain native argv, separate stdout/stderr, exits,
input/output hashes, the native binary hash and the released SDK identity.

| Filesystem | Operations | Native result | Codesign with APFS v0.17.0 |
| --- | --- | --- | --- |
| APFS | Sign, dry-run sign, remove | All succeed | All succeed; complete output bytes match for these controls |
| HFS+ | Sign, dry-run sign, remove | All succeed | All fail during replacement preparation with `operation not supported` |

HFS+ dry-run bytes remain unchanged on both sides, but the Go failure still
counts as a behavioral gap. Matching bytes alone cannot establish success.
This is prerequisite discovery, not a complete filesystem/permission profile.

Reproduce on a Mac without accessing a signing identity or keychain:

```sh
go run scripts/capture-filesystem-prerequisite.go -output artifacts/filesystem-prerequisite.json
```

The probe creates and detaches its own images and uses ad-hoc signing. It records
Go failures rather than treating them as passing parity assertions. The existing
[Apple writer AST evidence](../spec/apple-writer.json) includes the complete
`MachOEditor::commit` body: metadata copying does not depend on filesystem cloning.
Production filesystem mechanics continue to belong in APFS.

[Merged APFS PR194](https://github.com/deploymenttheory/go-apfs-v2/pull/194) adds
non-cloning replacement to both shared APIs. It preserves the writable staging
and deferred ACL-restoration contract, copies metadata through held descriptors,
and streams resource forks. Its own CI adds strict per-file coverage, portable
failure/boundary tests, native-corpus replay on every host, and mounted APFS/HFS+
comparisons with a Clang-built C oracle. Existing APFS qualification remains required.

The [final APFS CI run](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/37189517986)
passed all 63 applicable checks. New fallback files reached 100% statement coverage
on each applicable OS; retained source hashes matched the pushed branch. Eight
native cases passed on the macOS 26.6.2 runner alongside the local macOS 27.0.1
capture, including independently observed quarantine process contexts. The fix
was published in [v0.17.1](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.17.1)
and this branch consumes that release directly.

## Released integration

The [v0.17.1 recapture](../testdata/research/filesystem-prerequisite.json) succeeds
for all six operations, including SDK replacement preparation. Complete output
bytes match native in every case. The original failing capture is retained
unchanged and hash-pinned separately; the current capture validator also rejects
nonempty Go/SDK errors, so equal dry-run bytes cannot hide a failure.

[Mounted filesystem acceptance](../acceptance/filesystem_writer_darwin_test.go)
adds 108 native comparisons: APFS/HFS+ × standalone/bundle × arm64/x86_64/universal
× ordinary/readonly/deny-write ACL × sign/dry-run/remove. Each mount is checked
with `statfs`. Both producers use independent identical fixtures and native-signed
removal input. Checks cover full tree bytes, diagnostics, replacement identity,
hard-link neighbours, source mode, dry-run preservation and staging cleanup.
Successful signatures are verified by both CLIs. Image creation, mounting and
detachment are mandatory; failure does not skip a case.

These 108 comparisons passed locally on macOS 27.0.1. CI retains every previous
case and artifact expectation and adds 111 terminal outcomes (108 cases, two
filesystem groups and their parent) and 108 attestations on macOS. Existing
Linux/Windows writer execution, foreign-producer native verification, per-package
coverage above 95%, race, fuzz and GoReleaser gates remain required.
[PR98](https://github.com/deploymenttheory/go-macos-codesign/pull/98) merged at
`41da4e52b4bd588781c689e06e5146a35637d2d0` after its
[complete CI run](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/37192438601)
passed, including all three OS aggregates and foreign-signature verification.

The dependency bump also required fresh execution of the eleven plist operation
corpora that pin `go.mod` and `go.sum`. The [recapture audit](../testdata/research/apfs-v0.17.1-recapture.json)
retains prior/fresh hashes and confirms all 8,340 complete native observations
are unchanged. The dependent 1,294-value `plutil` corpus is recaptured separately;
expected values and case membership are not regenerated from Go output.

The v0.17.2 integration repeats these dependency-pinned captures, including all
8,340 plist operations, 1,294 native values, six filesystem controls and nine
large-DMG controls. The [release recapture audit](../testdata/research/apfs-v0.17.2-recapture.json)
records the unchanged observations and updated provenance.

The generic SDK replacement contract preserves source creation time, ACL and raw
quarantine bytes. Raw native `copyfile` can instead retain destination creation
time, merge inherited ACLs and normalize quarantine agent/timestamp fields. APFS
records and checks these separately. Codesign must still qualify and apply its
operation-specific metadata policy; changing the SDK transport does not settle it.

## Remaining integration work

Merged PR99 integrates [bounded operation I/O and cancellation](operation-io.md)
across existing writers. Merged PR100 extends incremental hashing and its evidence. Standalone
inspection/verification now use [source ranges](source-range-io.md), as does
[DMG signing](dmg-streaming.md). [Mach-O mutation](macho-streaming.md) and [bundle processing](bundle-streaming.md)
now use held sources and streamed output plans; metadata builders remain bounded
and materialized.

Complete the agreed pipeline above and the rest of Phase 02:
metadata/compression profiles, cancellation, partial failures, source identity,
asynchronous siblings and `--single-threaded-signing`.

Codesign depends on released APFS v0.17.2 without a local module replacement.
This release also supplies sparse rooted replacement on Windows; every large
bundle control remains mandatory in the downstream matrix.
These filesystem controls do not complete any whole Phase 02 family or settle
operation-specific metadata policy.
