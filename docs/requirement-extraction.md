# Requirement extraction

Display supports canonical requirement text for the existing bounded expression
language on Linux, macOS and Windows:

```sh
macoscodesign -d -r- Example.app
macoscodesign -d --requirements=requirements.txt Example.app
macoscodesign -d -a x86_64 -r- universal-tool
```

Both stdout and file destinations contain text. An explicit designated requirement
uses `designated => expression`; a synthesized one uses `# designated => expression`.
Binary sets retain their index order and host, guest, designated, library and plugin
labels. Type zero prints `invalid`; other unknown type numbers use Apple's comment
label. This does not add textual compilation of multi-requirement sets or new
expression predicates. The existing compiler and decoder are reused.

Canonical output preserves native boolean precedence, quoting, hex strings,
certificate positions and extension-existence comments. Literal whitespace is
preserved in quoted strings. The native simple alphanumeric-string formatter
truncates at 255 bytes; this profile reproduces that behavior. Such text is not
a lossless serialization of every compiled expression.

## Selection and integrity

`report.RequirementText(architecture)` returns owned text. The report must describe
a supported embedded signature. An empty selector prefers arm64, followed by the
first available architecture. With no explicit designated requirement, an ad-hoc
signature uses the selected architecture's CDHash followed by the other slices in
container order. An explicit architecture restricts synthesis to that slice.
Certificate synthesis reuses the existing CMS binding, linked-chain and default
requirement builders. It does not add trust anchors or a verification policy.

The primary CodeDirectory's nonzero requirements-slot hash must match the component.
A missing component with a nonzero hash fails; a component with an absent/zero hash
is ignored. An empty bound set also triggers default synthesis. Modified executable
pages do not prevent extraction. An explicit requirement can be extracted even
when CMS data is unreadable. `Report.Valid` remains unchanged.

Sets are limited to 1 MiB and 64 entries. The existing expression limits of 128
levels and 4,096 nodes remain. Overlapping child blobs are rejected by the shared
set validator before repeated decoding. Each selected/default-synthesis architecture
must have one CodeDirectory. Unknown expression opcodes and alternate directories
return `ErrUnsupported`; unlike native debug printing, they are not rendered as
successful partial expressions. Page integrity, trust and requirement satisfaction
remain separate verification operations.

## Output lifecycle

A file destination is created or truncated **before** fetching requirements.
Existing symlinks/hard links are followed, preserving the target inode and mode;
new files request mode 0666 subject to the host's creation mask. Each operand
truncates the same destination again, so the last successful operand wins. Stdout
concatenates results. The last repeated option supplies the destination.

An explicitly empty destination fails with the native empty-path diagnostic.
Open failures exit 1 immediately, including with `--continue`. Component failures
leave the destination truncated and use ordinary operand continuation rules.
Write/close failures are checked by Go; exhaustive native stdio failure equivalence
is not claimed. Colon and equals prefixes have no display-format meaning and are
literal filename characters; their filesystem availability differs across OSes.

In the tested combinations, normal metadata precedes extraction, certificates
precede requirements, requirements precede entitlements, signature-count lines
follow successful extraction, and file lists come last. Requirement extraction
suppresses the ordinary internal-requirement count/size line. Previous output
side effects remain after later failures. The portable `--json` option yields to
explicit requirement output. Verification ignores this option in the tested
profile. Removal with requirements is explicitly unsupported; native interprets
its argument as input in that mode, which remains a separate applicability task.

## Evidence and remaining work

[Acceptance tests](../acceptance/requirement_extraction_test.go) contain 87 cases:
54 representation/expression profiles, 21 lifecycle/interaction cases, six component
states and six architecture selections. Eighty-six compare raw native stdout,
stderr, status and output bytes/tree effects on macOS; one checks the portable
JSON interaction. They run on all three CI producers and record input preservation.
The six certificate-chain input archives contain nondeterministic signatures;
only their deterministic extracted text, not whole input hashes, is comparable
across producers. Absolute file-list stdout is compared locally with native output,
not as a portable path hash.

[The Clang driver](../scripts/extract-requirement-extraction.go) records six complete
pinned Apple function bodies on arm64 and x86_64 in the
[AST manifest](../spec/apple-requirement-extraction.json). It covers internal/default
selection, ad-hoc hash collection, set rendering and the printf buffer, with declared
private-type shims. Current private CLI call sites and the full dumper/interpreter
are not reconstructed by this AST. Their measured behavior comes from differential
tests. Production has no SDK, Clang, CGO or Apple runtime dependency.

Remaining work includes all other grammar/opcode families, requirement-set source
compilation, native debug output for unknown instructions, alternate/external slots,
Apple-proper and broader default certificate policy, malformed-CMS synthesis,
output aliases to inputs, special streams, permissions/ACLs, Unicode path
normalization, locales and exhaustive operation/diagnostic interactions. Verbose
certificate extraction can fail partway through native metadata display; that
checkpoint is not covered by this phase's nonverbose certificate-failure case.
The [implementation plan](implementation_plan.md#wp-09) retains these obligations;
`--requirements` remains partial.
