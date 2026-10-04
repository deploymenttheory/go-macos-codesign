# Portable I/O and lifecycle phase

Phase 02 covers streaming, filesystem behavior, metadata profiles, cancellation,
partial failures and commit order. It starts from merged PR97
(`12b40468f39d040d66776d3eed6c18b8cd090d48`). The complete scope remains in the
[remaining roadmap](implementation_plan.md#phase-02); none of its seven feature
owners is promoted to full parity by the prerequisite work below.

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
coverage above 95%, race, fuzz and GoReleaser gates remain required. Three-OS CI
for this branch is still required before merge.

The dependency bump also required fresh execution of the eleven plist operation
corpora that pin `go.mod` and `go.sum`. The [recapture audit](../testdata/research/apfs-v0.17.1-recapture.json)
retains prior/fresh hashes and confirms all 8,340 complete native observations
are unchanged. The dependent 1,294-value `plutil` corpus is recaptured separately;
expected values and case membership are not regenerated from Go output.

The generic SDK replacement contract preserves source creation time, ACL and raw
quarantine bytes. Raw native `copyfile` can instead retain destination creation
time, merge inherited ACLs and normalize quarantine agent/timestamp fields. APFS
records and checks these separately. Codesign must still qualify and apply its
operation-specific metadata policy; changing the SDK transport does not settle it.

## Remaining integration work

1. Qualify the dependency integration with the full three-OS CI harness.
2. Complete the rest of Phase 02 as one cohesive implementation: streaming/budgets,
   metadata/compression profiles, cancellation, partial failures, source identity,
   asynchronous siblings and `--single-threaded-signing`.

Codesign depends on released APFS v0.17.1 without a local module replacement.
These filesystem controls do not complete any whole Phase 02 family or settle
operation-specific metadata policy.
