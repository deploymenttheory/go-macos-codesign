# Compression preservation

`--preserve-afsc` requests recompression after signing replaces a compressed
executable or overwrites an existing compressed resource envelope. It preserves
the compression algorithm through the shared APFS codec and installation APIs.
Native queue admission occurs after replacement: admission failure can leave the
new signed inode in place. Later accepted compression failure does not necessarily
make Apple's signing operation fail. Cancellation and scratch-cleanup errors
remain observable through the Go API.

Recompression stages share the operation's configured temporary directory and
scratch-file accounting. `WorkingStorageStats` reports current and peak logical
temporary extents and file counts across signature spills and recompression.
Sparse holes count toward extents; these figures are not allocated disk blocks.
Partial writes count only the bytes actually written, and failed removal leaves
the retained file and extent visible in the final counters. Scope cleanup also
closes any stage that has not already been closed by its compression operation.
Replacement outputs, codec-internal allocations and general open descriptors
still need separate Phase 2 accounting.

The current implementation integrates native held-file observation, rooted
reopening and shared recompression for signing and re-signing. Resource envelopes
use a no-follow pathname metadata query before opening for writing: a read-only
open can be denied when Apple's query succeeds, while a write open can already
decompress the input. The query checks the previously observed file identity;
it does not make independent pathname operations a filesystem snapshot. Dry-run executable
replacement does not reach recompression. The CLI accepts the option during
removal, display and verification; these operations do not request recompression.
The native preservation matrix includes 24 zlib/LZVN/LZFSE standalone and bundle
comparisons. All 24 original replacement controls remain required. The comparison
checks complete logical bytes, compressed attribute and resource-fork bytes,
flags, inode replacement and resource envelopes; successful signed results are
also verified by Apple's tool.

The completion branch adds 30 envelope comparisons across zlib/LZVN/LZFSE,
ordinary access, denied data reads/writes and denied extended-attribute
reads/writes, with both re-sign and dry-run operations. It also runs the 24
executable preservation and 30 envelope comparisons on each of mounted APFS and
HFS+ volumes. These 138 additional leaf cases pass locally on macOS 27.0.1;
the exact test manifest requires all of them in Darwin CI. The pathname query
comes from merged [APFS #212](https://github.com/deploymenttheory/go-apfs-v2/pull/212),
included in the current APFS pin `18d01893f15709bd1eb37180989a1ebe5a53e62e`.
Both compression volume profiles have genuine dependency-sensitive recaptures;
all 32 retained observations are unchanged. Their independent C `fstatfs`
observations and two-target ASTs select the applicable mount policy before
comparison. Original build-specific captures remain immutable historical evidence.
Final consumer CI remains required before qualification.

This is an in-progress Phase 2 capability. Explicit foreign carrier publication
and source-context binding are not yet integrated. Linux and Windows require
that route to represent Darwin compression; their native flags cannot supply
Darwin state. Remaining qualification includes broader envelope and
observation/acquisition failures, post-rename failures, mount policies and macOS
15/26/27. The CLI flag's presence is not a claim of complete portable parity.

Replacement and archive preservation have different metadata contracts. Native
replacement enumerates an ordinary namespace that hides compression attributes
and resource forks while compression is active. This includes independent forks
on inline-compressed files. The shared borrowed-value policy is available from merged
[APFS #211](https://github.com/deploymenttheory/go-apfs-v2/pull/211), with mounted
native comparisons. Apple's
[XNU visibility predicates](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/decmpfs.c#L963)
explain the visibility boundary; they are not substitutes for runtime evidence.

Run the current native comparison with:

```sh
go test ./acceptance -run '^Test(CompressedReplacementNative|PreserveAFSCNative|PreserveAFSCEnvelopeNative|MountedCompressionPreservation)$' -count=1 -v
```

The ordinary admission/cancellation/cleanup policy and CLI applicability tests run
on every host. The native comparison requires a Darwin filesystem; portable
carrier acceptance and native readback remain additional required work, not
replacements for those controls.
