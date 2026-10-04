# Operation I/O and cancellation

Signing operations use a shared bounded transfer path for standalone Mach-O
replacements, rooted bundle executables, resource envelopes and in-place DMG
writes. The transport accepts a borrowed `io.ReaderAt`, a known length and a
source offset. It keeps offsets in `int64` and uses at most 64 KiB of transfer
buffer. Existing format builders supply byte readers through the same interface.

The lifecycle is transfer, truncate, representation-specific metadata, sync,
close and then the existing commit step. Cancellation is checked between transfer
calls and lifecycle steps. Short reads, short writes, invalid counts and failing
I/O stop the operation. When cancellation and a transfer I/O error occur together, callers
can inspect both with `errors.Is`. Cleanup still runs after failure or cancellation.

| Writer | Cancellation or failure before commit |
| --- | --- |
| Standalone Mach-O | Discard the private replacement; preserve the original name, bytes, inode and hard links |
| Rooted bundle executable | Discard the uncommitted replacement; retain previously committed independent work |
| Existing resource envelope | Preserve its inode; completed writes can remain visible through hard links |
| DMG | Preserve its inode; completed writes can remain visible through hard links, including during a native-compatible dry run |

In-place cancellation cannot undo a completed write. A blocking filesystem call
must return before cancellation can be observed. These are checkpoint guarantees,
not asynchronous interruption or whole-bundle rollback.

Standalone signing, removal, inspection and verification check their context
during bounded input reads. Input-size limits remain enforced even if the file
grows after its initial stat. Operation owners retain close failures alongside
the primary error. Explicitly closed standalone source handles are consumed once,
so deferred cleanup does not retry a failed close.

## Incremental hashes

Mach-O and DMG signing and verification check cancellation while hashing code
pages and special slots. Pages up to 64 KiB use the one-shot digest with checks
before and after it; larger inputs use a bounded incremental hash. The internal
known-length `ReaderAt` path supports SHA-1, SHA-256, truncated SHA-256 and SHA-384,
with checked 64-bit source ranges. A failed or cancelled read returns no digest.

Bundle resource scanning computes SHA-1 and SHA-256 in one cancellable pass. It
reads through EOF, including bytes added after the initial stat, enforcing the
remaining bundle budget with a one-byte overrun probe. It retains read errors and
resource-handle close errors. Cancellation does not publish a resource seal.

These are Go API cancellation guarantees. They do not imply an Apple CLI
cancellation option or interruption of a blocking OS call.

## Evidence and tests

The existing [Apple writer evidence](../spec/apple-writer.json) retains complete
allocation, commit, destructor, bundle-envelope and cleanup bodies. Re-extracting
both Clang targets from the pinned Apple sources produced identical evidence.
The Go context contract is tested directly; it is not presented as an Apple CLI
cancellation protocol.

[Portable transport tests](../pkg/codesign/transfer_test.go) cover chunk boundaries,
invalid/overflowing source ranges, zero length, short and failing I/O, simultaneous
errors, cancellation at every shared write checkpoint and close ownership. Virtual
source/sink tests exercise offsets around 4 GiB and transfer a logical 4 GiB + 17
bytes without allocating that payload. They are arithmetic/transport unit tests,
not a claim of native large-file acceptance.

[Filesystem cancellation tests](../pkg/codesign/transfer_filesystem_test.go)
cancel after observing the first completed chunk. All four writers must preserve
the expected inode and hard-link effects, and private stages must disappear.
Tests use deterministic checkpoints without sleeps or production-global hooks.
All 60 new outcomes are mandatory on Linux, macOS and Windows. The new transfer
implementation reached 100% statement coverage locally; CI still enforces more
than 95% for every production package on each OS independently.

Existing native tests retain their exact case membership and expectations for
mounted APFS/HFS+ writers, permissions, ACLs, hard links, timestamps, resource
envelopes, cleanup and DMG dry runs. Existing foreign-producer verification, race,
full-duration fuzz, pure-Go guards and GoReleaser builds remain mandatory.
The local native run passed 1,899 terminal outcomes in 16 existing groups with
their pinned outcome hashes unchanged. The new lifecycle cases also passed with
the race detector; all six GoReleaser targets built successfully.

The [hashing tests](../pkg/codesign/hashing_test.go) add 192 mandatory unit
outcomes per host. They replay 156 independently generated CommonCrypto digests
across four algorithms, thirteen lengths and three source offsets, including
offsets above 4 GiB. They check short/failing reads, cancellation, budget exhaustion,
and every context checkpoint reached by successful byte signing/verification and
bundle resource scans. The hashing helpers have 100% local statement coverage.

The [bundle boundary acceptance](../acceptance/hash_streams_test.go) adds thirteen
mandatory outcomes on each OS: twelve bundles covering three architectures and
resource lengths 65,535, 65,536, 65,537 and 131,089 bytes, plus the enclosing test.
Every host signs and verifies them. On macOS their complete executable and
CodeResources bytes must match native ad-hoc signing, and native strict verification
must accept the Go result. All twelve comparisons passed locally, alongside 226
unchanged existing byte/display/bundle-writer/DMG-dry-run outcomes.

[Apple hashing AST evidence](../spec/apple-hashing.json) contains four complete
verbatim methods from pinned Security source, compiled for both Clang targets.
Surrounding types and `hashFileData` are declarations, not a substitute runtime.
The [CommonCrypto capture](../testdata/research/hash-streams.json) independently
checks digest values using 4,093-byte chunks; it is not an implementation of
native signing. CI recompiles both the AST and oracle, compares their complete
facts/corpus and retains fresh provenance. Portable tests also reject stale
oracle source hashes and missing/duplicate cases.

Apple's file-hashing helper describes limit zero as EOF and permits short files.
Our internal range is an exact length: zero means empty and a short read fails.
These different internal contracts must not be confused when integrating future
streaming format readers. Neither the high-offset corpus nor the CommonCrypto
oracle establishes native large-file signing acceptance.

## Remaining Phase 02 work

Standalone inspection and verification now use [held-file range reads](source-range-io.md),
including real UDIF verification above 4 GiB. [DMG signing](dmg-streaming.md) now hashes those ranges and updates only the tail.
[Standalone Mach-O signing/removal](macho-streaming.md) now hashes and assembles
held ranges, then transfers into an SDK replacement. Bundle paths still materialize
whole byte slices and retain their 1 GiB limits. Operation-wide budgets remain
outstanding. Metadata/CodeDirectory materialization, CDHash calculation and other
metadata/CMS hashing still include one-shot paths. Bundle planning reads,
metadata/close checkpoints outside the shared transfer, source-content races,
compression policy, asynchronous sibling scheduling and full native failure
qualification remain in the [roadmap](implementation_plan.md#phase-02).

The agreed Phase 02 architecture replaces these whole-file path operations with
held-source range parsing, direct range hashing, streamed write plans and spill
storage. Its initial shared managed-buffer budget is 128 MiB across nested and
concurrent work. This is a proposed budget to benchmark, not implemented behavior
or a total-process memory cap. The intended result removes the arbitrary 1 GiB
file-size ceiling while preserving byte API contracts and native commit effects.
See the [implementation sequence](implementation_plan.md#pipeline-implementation-sequence)
for the prerequisite audit, real-file size boundaries, memory measurements and
mandatory three-OS qualification.
