# Held-file inspection and verification

Standalone `Inspect`/`InspectWithOptions` and `Verify`, including the CLI display
and verification operations, read supported Mach-O and UDIF representations through
held file descriptors. They no longer read the entire payload into a byte slice
or reject the file solely because it exceeds 1 GiB. Bundle paths and signing/
removal output construction still use their existing bounded byte plans.

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
| `source.go` | Standalone read-only payloads use ranges; each materialized metadata read still has the legacy 1 GiB ceiling | Shared accounting, metadata spilling and aggregate/report ownership |
| `sign.go` / `io.go` | Signing and Mach-O removal read/construct full byte buffers with the legacy ceiling | Held-source mutation plans, streaming output, metadata/commit integration |
| `macho.go` | Byte output assembly remains bounded; range parsing supports FAT64 offsets | Stream architecture assembly, output growth and real large Mach-O qualification |
| `dmg.go` | Byte parsing/signing and generated output retain their memory bounds; range inspection bypasses the payload ceiling | Stream signing, safe in-place overlap handling and larger page/metadata profiles |
| `bundle.go`, `bundle_tree.go`, `bundle_layout.go`, `bundle_versions.go` | Executable/plist reads and aggregate scan budgets remain bounded | Integrate held sources and operation-wide budgets across discovery, verification and nested work |
| `bundle_tree.go`, `bundle_nested.go` | Staged signature output totals remain bounded | Shared write plans and temporary storage across children/siblings |
| `hashing.go` | Resource hashes stream, but callers still impose the legacy bundle budget | Separate memory consumption from bytes processed |

No new APFS API is needed for this standalone read-only step: Go's existing held
file descriptor provides data reads/stat, while APFS remains responsible for
filesystem metadata. Rooted bundle access already uses the shared SDK where its
containment/permissions contract applies. Replacement, metadata restoration,
resource forks and image codecs remain upstream responsibilities; audit released
APIs again before extending those operations.

Signature blobs and load-command metadata are still materialized, and public
`Report`/`Signature` objects retain byte fields. Memory can therefore grow with
metadata and architecture count. There is no aggregate 128 MiB enforcement or
spill store yet. The next integration must address that ownership explicitly,
retain byte API compatibility and measure total process memory separately.

The [Phase 02 plan](implementation_plan.md#phase-02) still requires populated
multi-gigabyte inputs, large Mach-O/bundle mutation paths, resource-budget/spill
failures, memory/storage scaling measurements on all hosts and complete operation
lifecycle qualification. This step does not finish Phase 02 or promote a whole
compatibility feature to verified.
