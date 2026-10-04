# Portable I/O and lifecycle phase

Phase 02 covers streaming, filesystem behavior, metadata profiles, cancellation,
partial failures and commit order. It starts from merged PR97
(`12b40468f39d040d66776d3eed6c18b8cd090d48`). The complete scope remains in the
[remaining roadmap](implementation_plan.md#phase-02); none of its seven feature
owners is promoted to full parity by the prerequisite work below.

## Confirmed shared-library prerequisite

The [six native observations](../testdata/research/filesystem-prerequisite.json)
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

[APFS draft PR194](https://github.com/deploymenttheory/go-apfs-v2/pull/194) adds
non-cloning replacement to both shared APIs. It preserves the writable staging
and deferred ACL-restoration contract, copies metadata through held descriptors,
and streams resource forks. Its own CI adds strict per-file coverage, portable
failure/boundary tests, native-corpus replay on every host, and mounted APFS/HFS+
comparisons with a Clang-built C oracle. Existing APFS qualification remains required.

The generic SDK replacement contract preserves source creation time, ACL and raw
quarantine bytes. Raw native `copyfile` can instead retain destination creation
time, merge inherited ACLs and normalize quarantine agent/timestamp fields. APFS
records and checks these separately. Codesign must still qualify and apply its
operation-specific metadata policy; changing the SDK transport does not settle it.

## Required integration order

1. Obtain green APFS CI, user merge and a published release of the prerequisite.
2. Consume that released version here and update the pinned API audit. Do not use
   a local module replacement or duplicate the fallback in codesign.
3. Promote the HFS+ controls into the existing strict acceptance harness, including
   standalone and rooted bundle writers, and preserve every previous case.
4. Complete the rest of Phase 02 as one cohesive implementation: streaming/budgets,
   metadata/compression profiles, cancellation, partial failures, source identity,
   asynchronous siblings and `--single-threaded-signing`.

Codesign still depends on released APFS v0.17.0. The upstream draft, local native
results and cross-compilation are not substitutes for final three-OS CI or for
finishing the remaining lifecycle phase.
