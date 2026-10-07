# Held-file inspection and verification

`VisitInspection` and `VisitVerification` consume signature components through
held ranges while a callback runs. Non-JSON CLI display and verification use
these scoped APIs. CodeDirectory hash tables and opaque components remain ranges;
the existing spillable indexes check duplicate slots and overlapping blobs.
Page and special-slot validation read the required ranges, and certificate
binding hashes directory ranges directly. The cryptographic and trust policies
are shared with the owned-byte APIs.

The callback receives the operation error even when no report could be produced,
and runs exactly once. Its error is joined with operation and subsequent cleanup
errors. Borrowed reports have no `Signature.Blobs` or `Directory.Raw` arrays;
use `BlobReader`, `BlobSize`, `ReadBlob` and `Directory.Size` instead. Report
methods for requirements, entitlements, certificates and file lists work inside
the callback. Do not retain the borrowed report or its readers after returning.
An explicit `ReadBlob` requests an owned component allocation; streamed callers
should prefer `BlobReader`. The existing `Inspect`, `Verify`, byte APIs and JSON
CLI output continue to return/serialize complete owned component bytes.

[Native metadata evidence](../testdata/research/signature-metadata.json) covers
twelve dense files with CodeDirectory lengths immediately below, at and above
64 KiB, 16 MiB, 128 MiB and 1 GiB. Apple's CLI and an independently compiled
C/SDK probe accept every control. Both Clang targets compile the real SDK calls;
this records the public API contract, not the private framework implementation.
The capture retains compiler, SDK-header, oracle-binary, source and complete-file
hashes. The deterministic recipe extends a native ad-hoc directory with zeros,
adjusts its container lengths and retains its original page/special-slot bindings.

Every host reconstructs all twelve dense files and compares complete CLI output
with the capture. Library verification runs each at 64 KiB, 128 MiB and 256 MiB
working budgets, checks the SDK-observed CDHash, enforces an 8 MiB total Go
allocation regression bound, and requires scratch cleanup. The local 1 GiB
directory control used about 164 KiB of total Go allocations with the 64 KiB
budget. Each budget/case also runs in a fresh test process, recording total Go
allocations, a sampled heap peak, the OS-reported process peak, elapsed time and
storage reservations. Unix uses `getrusage`; Windows observes the Go worker's
`PeakWorkingSet64` through the test harness. The 1 ms heap sampler can miss short
peaks and is reported separately from the OS measurement. Local macOS process
peaks were approximately 15–16 MiB for the largest control. Cross-host results
must establish regression bounds before closure; these measurements cover one
metadata shape, not concurrent/nested workloads or a measured optimum for the
default budget. The wider Phase 02 scale matrix remains open.

```sh
go run scripts/probe-signature-metadata.go -check -out artifacts/signature-metadata.json
go test -count=1 -run '^TestSignatureMetadataBoundaries$' ./acceptance
```

Standalone `Inspect`/`InspectWithOptions` and `Verify`, including the CLI display
and verification operations, read supported Mach-O and UDIF representations through
held file descriptors. They no longer read the entire payload into a byte slice
or reject the file solely because it exceeds 1 GiB. [DMG signing](dmg-streaming.md),
[Mach-O mutation](macho-streaming.md) and [bundle payloads](bundle-streaming.md)
also use held ranges. Legacy byte APIs and individual metadata components retain
the limits documented below.

The range and byte paths share Mach-O/FAT parsing, UDIF structure validation,
report construction, certificate/requirement policy and strict-layout validation.
Range parsing reads headers, load commands, selected signature data and the UDIF
trailer. Verification hashes code ranges directly from the held source with
bounded reads. Universal padding is checked in chunks without a whole-file buffer.
The byte APIs retain their input ownership and existing representation behavior.

The descriptor remains open through sideband checks and verification. Short or
failing reads and cancellation return errors; close errors are retained. Size and
modification time are checked against the held object's initial stat before a
successful result is returned. These checks detect ordinary concurrent changes;
they do not provide a snapshot or protection against an actor restoring timestamps.
The existing source/path race obligations remain open.

## Native evidence

[Apple source evidence](../spec/apple-source-ranges.json) compiles complete
`DiskImageRep::readHeader`, `MachORep::signingData` and inline
`CodeDirectory::signingLimit` bodies for arm64 and x86_64. Surrounding declarations
are shims; they do not establish the UDIF layout or execute Apple's implementation.
The UDIF layout continues to come from the released APFS model.

The large-file capture exposed an existing CodeDirectory interpretation gap:
Apple selects a nonzero 64-bit limit in version 0x20300 or later even when the
32-bit field is nonzero. The native >4 GiB records contain `0xffffffff` in the
32-bit field and the true length in the 64-bit field. Parsing now follows that
precedence, with explicit fallback and contradictory-field unit cases.

The [native corpus](../testdata/research/large-source.json) covers payload lengths
one byte below, at and above 1 GiB, 2 GiB and 4 GiB. Each image contains a prefix
from the pinned native raw UDIF fixture, a real zero-filled sparse extent, and
Apple-produced signature/trailer bytes. Recipes retain source and native-binary
hashes, host profile and normalized display/verification output. Capture and
replay resolve the absolute operand path before replacing that exact
path with `<image>`, keeping macOS temporary-directory aliases out of portable
expectations. The harness rejects captures containing a residual host-path prefix.
The recipe measures content length; total signed file length also includes its signature
and 512-byte trailer. It is not a capture of a newly created multi-gigabyte
filesystem volume or a densely populated image.

Reproduce without a certificate, password or keychain:

```sh
python3 scripts/extract-source-ranges.py --check --output artifacts/apple-source-ranges.json
go run scripts/probe-large-source.go -check -out artifacts/large-source.json
go test -count=1 -run '^TestLargeSourceVerification$' ./acceptance
```

Every host reconstructs and verifies all nine real files using the committed
native signatures and compares CLI output with the capture. macOS additionally
verifies the reconstructed files with native codesign. Native-capture CI signs
and verifies the full corpus afresh and compares it with the recorded cases.
File creation/truncation failures fail the test rather than skip it. Existing
hdiutil, mounted-image, foreign-producer and signature-byte tests remain required.

Windows explicitly marks each new fixture sparse through the supported
`x/sys/windows` wrapper before truncation and checks the resulting attribute.
This follows [Windows sparse-file semantics](https://learn.microsoft.com/en-us/windows/win32/fileio/sparse-file-operations)
and reconstructs the same zero-extent recipe used by the native capture. The CLI
still reads and hashes every logical payload byte; it does not query or skip
sparse extents. All nine sizes, recorded signatures, exact diagnostics and the
30-second per-command deadline remain required. The transcript records fixture
setup, display and verification timings separately, including command details
and captured output on timeout. Dense/populated large-file qualification remains
an explicit Phase 02 obligation.

The unit tests also cover existing fixture parity, each held read failing or
being cancelled, descriptor cleanup, detectable source changes and FAT64 slice
offsets above 4 GiB. The existing inspection fuzzer now compares byte and range
inspection while retaining its previous checks and full CI duration.

A real 4 GiB + 1-byte payload verification allocated **76,536 bytes** in the local
Go API measurement. Its small-metadata regression control requires less than
8 MiB total Go allocations for that operation. This measurement is not RSS,
working set, a general peak-memory result or implementation of the planned shared
128 MiB budget. It excludes fixture setup and tests a single-page CodeDirectory.

## Size-limit audit and remaining integration

| Location | Current contract | Remaining Phase 02 work |
| --- | --- | --- |
| `source.go` / `source_report.go` | Scoped inspection and verification borrow signature ranges and spill their indexes; owned report/component reads retain the legacy 1 GiB allocation ceiling | Remaining materialized metadata/CMS limits, full accounting and ownership qualification |
| `sign.go` / `io.go` | Standalone Mach-O signing/removal use held-source plans and SDK replacement; byte APIs retain complete output buffers | Shared metadata budgets and remaining lifecycle policy |
| `macho.go` / `macho_commands.go` / `macho_source.go` | Fixed-size load-command summaries, source-range patches and streamed thin/FAT assembly; native 32-bit whole-file mutation limits are distinguished from byte API allocation limits | Large command-region native acceptance, input signature views and dense multi-gigabyte scaling |
| `dmg.go` / `dmg_source.go` | Path inspection, verification and signing use held ranges; signing writes only the new tail; byte APIs retain memory bounds | Shared metadata budget/spilling and larger page/metadata profiles |
| `bundle.go`, `bundle_tree.go`, `bundle_layout.go`, `bundle_versions.go` | Executable reads use held ranges; resources stream; plists/envelopes retain parser bounds | Shared metadata budgets and complete discovery/lifecycle qualification |
| `bundle_tree.go`, `bundle_nested.go` | Nested signatures use shared output plans without an aggregate payload ceiling | Shared budgets, metadata spilling and temporary storage accounting |
| `hashing.go` | Resource hashes stream to a known-size bound with identity/content checks | Shared managed-buffer accounting |

No new APFS API is needed for this standalone read-only step: Go's existing held
file descriptor provides data reads/stat, while APFS remains responsible for
filesystem metadata. Rooted bundle access already uses the shared SDK where its
containment/permissions contract applies. Replacement, metadata restoration,
resource forks and image codecs remain upstream responsibilities; audit released
APIs again before extending those operations.

Public `Report`/`Signature` objects retain owned component bytes. Signing
preflight now uses borrowed signature views instead: it scans every component
through bounded reads, keeps at most six directory summaries and stores slot and
overlap indexes in shared working sections that can spill. Duplicate-slot errors
remain immediate; overlap errors remain deferred until component parsing finishes.
Index growth follows entries actually read, not an untrusted declared count.

Load-command parsing keeps fixed-size summaries
and mutates source ranges through bounded patches, including removal relocation
and identifier hashing. Memory can still grow with signature metadata and
architecture count. The operation storage manager now shares a
128 MiB starting reservation pool for transfer buffers and generated
CodeDirectories. Sections that cannot fit spill into disjoint ranges of one
private temporary file, removed when the owning operation finishes. Generated
CMS binding hashes and SuperBlob output plans consume these ranges directly.
Nested operations reuse the same pool. `WithWorkingStorage` selects the budget,
temporary directory and final reservation observer for an API operation.

Page hashes use one reservation split between source reads and batched digest
writes. A spill receives up to 32 KiB of digests per write instead of one write
per page. Waiting for capacity is cancellable; tests exercise blocked waiters
through release, cancellation and closure.

Mach-O and DMG inspection read SuperBlob headers, index records and referenced
components separately, retaining owned bytes for public reports. Signing uses
the borrowed views for admission and replacement notices. Unused reserved
signature space is no longer materialized. Virtual 1/2/4 GiB boundary tests check
offset arithmetic and reads only; they do not establish native acceptance of a
gapped or oversized signature. Path verification, CLI display/extraction and
their parser objects still need the remaining metadata-budget work; returning
owned public reports remains a separate allocation contract.

This is not yet comprehensive memory enforcement. Input metadata, parser objects,
queued work and handle accounting remain to be integrated and measured. Caller
input and returned byte/report ownership remain unchanged; those allocations and
runtime overhead must be measured independently of managed reservations. The
phase still requires isolated heap/RSS/working-set and temporary-storage controls
across payload, nested and concurrent workloads before the default can be
described as qualified at scale. The dense signature-metadata controls now
collect isolated process measurements as described above.

Compressed-source replacement uses the merged result of
[APFS PR #198](https://github.com/deploymenttheory/go-apfs-v2/pull/198), pinned
to an exact `main` commit during Phase 02. The next upstream release is batched
under the [phase dependency policy](implementation_plan.md). The
research-only `scripts/probe-compressed-signing.go` records native standalone
and bundle sign/re-sign/dry-run/removal outcomes, with and without
`--preserve-afsc`, in versioned native captures. The macOS 27.0 build 26A428
profile is `testdata/research/compressed-signing.json`; the macOS 27.0.1 build
26A434 profile is `compressed-signing-26A434.json`. The former capture stores
these inputs inline, while the latter uses resource forks. This difference must
not be attributed to the OS build alone: the host framework checks the held
file's `fstatfs` flags and suppresses inline storage on `MNT_CPROTECT` volumes.
The local host volume has that flag; independently created test images can
permit inline storage on the same OS build. Extend the signing capture with
explicit volume-policy observations before selecting recompression behavior.
Each existing profile retains
its exact native storage bytes and provenance; the recapture selects the host
build explicitly and rejects an unqualified build. Its sixteen
cases have dependency/source provenance checked for both retained builds before
test shards run. When the dependency changes, each build needs a genuine fresh
capture; updating the local host's profile alone is insufficient. The 26A428
profile for APFS #209 was recovered from native-capture artifact `11467997498`
in codesign CI run `37587472210`: its driver/input/module hashes match the
checkout and all sixteen behavior records match the previous capture.
The sixteen
cases originally exposed the v0.17.2 staging rejection, retained in
`compressed-signing-v0.17.2.json`. CI now recaptures all sixteen outcomes and SDK
eligibility checks. `TestCompressedReplacementNative` also compares 24 live
zlib/LZVN/LZFSE standalone and bundle operations with Apple: complete logical
bytes, hidden compression header, resource fork, flags, identity changes and
bundle envelope. Apple strictly verifies the signed results. This qualifies
ordinary replacement and dry runs on those profiles; recompression, larger
fork-backed profiles and portable foreign-metadata integration remain separate
obligations.

Standalone [Mach-O mutation](macho-streaming.md) now reuses the released held-source
replacement API through metadata restore and a Windows-compatible close/rename handoff.
Its real-file corpus covers thin/universal inputs around 1/2/4 GiB, native allocation
rejections and an additional populated-region control.

The [Phase 02 plan](implementation_plan.md#phase-02) still requires populated
multi-gigabyte dense inputs, resource-budget/spill
failures, memory/storage scaling measurements on all hosts and complete operation
lifecycle qualification. This step does not finish Phase 02 or promote a whole
compatibility feature to verified.
