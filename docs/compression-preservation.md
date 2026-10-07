# Compression preservation

`--preserve-afsc` requests recompression after signing replaces a compressed
executable or overwrites an existing compressed resource envelope. It preserves
the compression algorithm through the shared APFS codec and installation APIs.
Native queue admission occurs after replacement: admission failure can leave the
new signed inode in place. Later accepted compression failure does not necessarily
make Apple's signing operation fail. Cancellation and scratch-cleanup errors
remain observable through the Go API.

The current implementation integrates native held-file observation, rooted
reopening and shared recompression for signing and re-signing. Dry-run executable
replacement does not reach recompression. The CLI accepts the option during
removal, display and verification; these operations do not request recompression.
The native preservation matrix includes 24 zlib/LZVN/LZFSE standalone and bundle
comparisons. All 24 original replacement controls remain required. The comparison
checks complete logical bytes, compressed attribute and resource-fork bytes,
flags, inode replacement and resource envelopes; successful signed results are
also verified by Apple's tool.

This is an in-progress Phase 2 capability. Explicit foreign carrier publication
and source-context binding are not yet integrated. Linux and Windows require
that route to represent Darwin compression; their native flags cannot supply
Darwin state. Remaining qualification includes compressed envelopes, denied
observation/acquisition, post-rename failures, actual mount policies and macOS
15/26/27. The CLI flag's presence is not a claim of complete portable parity.

Replacement and archive preservation have different metadata contracts. Native
replacement enumerates an ordinary namespace that hides compression attributes
and resource forks while compression is active. This includes independent forks
on inline-compressed files. The shared borrowed-value policy is being exposed in
[APFS #211](https://github.com/deploymenttheory/go-apfs-v2/pull/211), with mounted
native comparisons. Apple's
[XNU visibility predicates](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/decmpfs.c#L963)
explain the visibility boundary; they are not substitutes for runtime evidence.

Run the current native comparison with:

```sh
go test ./acceptance -run '^Test(CompressedReplacementNative|PreserveAFSCNative)$' -count=1 -v
```

The ordinary admission/cancellation/cleanup policy and CLI applicability tests run
on every host. The native comparison requires a Darwin filesystem; portable
carrier acceptance and native readback remain additional required work, not
replacements for those controls.
