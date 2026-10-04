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

## Remaining Phase 02 work

The Mach-O/DMG parsers and signature builders still materialize whole byte slices
and retain the 1 GiB path limit. This transfer layer does not complete large-file
signing, incremental hashing or operation-wide budgets. Bundle planning reads,
metadata/close checkpoints outside the shared transfer, source-content races,
compression policy, asynchronous sibling scheduling and full native failure
qualification remain in the [roadmap](implementation_plan.md#phase-02).
