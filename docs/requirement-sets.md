# Requirement-set compilation

Signing accepts named requirement-set source through inline `-r`, a source file,
or a compiled binary set. All parsing, encoding and signing runs in pure Go on
Linux, macOS and Windows. Existing predicates are shared with the standalone
compiler and extraction decoder; this increment adds no new predicate families.

```sh
macoscodesign -s - -i org.example.tool \
  -r='host => never; designated => identifier "org.example.tool"' ./tool
macoscodesign -s - --requirements=requirements.txt ./tool
macoscodesign -s - --requirements=requirements.bin ./tool
macoscodesign -d -r- ./tool
```

For example, `requirements.txt` can contain:

```text
# Requirements may span lines; semicolons are optional.
host => never;
guest => never
designated => identifier "org.example.tool"
library => always
plugin => never
```

`codesign.CompileRequirements(source)` returns an owned requirements SuperBlob.
`codesign.RequirementsBytes(data)` accepts source or clones and validates a binary
set. `codesign.CompileRequirement(source)` continues to compile exactly one
standalone expression. A requirements set and a standalone requirement have
different magic values and are not interchangeable signing inputs.

## Measured grammar and encoding

| Source kind | Binary kind |
| --- | --- |
| `host` | 1 |
| `guest` | 2 |
| `designated` | 3 |
| `library` | 4 |
| `plugin` | 5 |
| Decimal number from 0 through 4294967295 | That unsigned value |

Leading decimal zeroes are accepted, including `08`. `invalid` is a display label,
not a source keyword; type zero is written `0 => expression`. Negative, hexadecimal,
Go-style radix and underscore-separated kinds are rejected. Source order does not
control encoding: entries and children are sorted by unsigned kind. Repeated kinds,
including numeric/named aliases, use the last expression. Earlier overwritten
expressions must still parse successfully.

Whitespace, C comments, C++ comments and shell comments may separate tokens.
Comments do not alter quoted strings. The `=>` arrow is one contiguous token;
spaces/comments cannot split it. Zero or more semicolons may follow each expression.
Leading semicolons and comma-separated sets are invalid. Implicit certificate
extension existence ends correctly before another kind or a semicolon.

Source is limited to 1 MiB, 64 assignments including duplicates, and the existing
128-level/4,096-operand budget per expression. Binary decoding retains its separate
node/depth limits; exceptionally long associative expressions can compile but exceed
the decoder's bounds. Numeric overflow is rejected instead of emulating Apple's
`atol`/32-bit conversion wraparound. These limits are explicit portable differences.

For compatibility with earlier versions, a bare expression becomes a designated
requirement. Apple `csreq` instead produces a standalone blob for it, and native
`codesign` rejects it as signing set source. The existing `not` spelling, Go string
escapes and hexadecimal identifier literals are also portable extensions; the
native compiler does not accept every expression emitted by its own text dumper.
Canonical extraction is consequently not a universal lossless source interchange.

## Signing, validation and remaining policy

The measured signing profile contains an explicit designated requirement. All five
named kinds are embedded without flattening the set. A false host, guest, library
or plugin requirement does not make ordinary static signature verification fail;
their contextual policies require separate work. On the recorded Mac baseline,
supplying a guest requirement does not automatically set the host CodeDirectory flag.

Apple merges representation defaults, explicit requirements and a synthesized
designated requirement when one is absent. The current certificate signer supplies
its default only when the caller supplies no requirements bytes. An explicit empty
or host-only certificate set therefore remains a known signing difference. The
next policy increment must cover empty/partial/full sets, default override ordering,
preservation, bundles, all supported identities and invalid designated requirements.
Ad-hoc extraction can already synthesize a commented CDHash designated requirement.

Unimplemented work also includes stdin/special streams, `$self.identifier`
substitution, all remaining predicate/operator families, Apple-proper defaults,
overflow emulation if desired, exact native syntax diagnostics and full operation
applicability. Rejected source preserves all signing operands in the tested
multi-operand `--continue` cases, but its diagnostic wording differs from Apple's
line/column parser messages. No inventory obligation becomes fully verified.

## Evidence

The [research driver](../scripts/extract-requirement-sets.go) records
[six complete Apple function bodies](../spec/apple-requirement-sets.json) through
Clang ASTs for arm64 and x86_64: generated set/type/element/integer parsing,
SuperBlob duplicate replacement, and internal default merging. SDK enum constants
and C++ library declarations are real; private/ANTLR interfaces are declaration-only
shims. The full lexer and expression parser are not reconstructed. Default merging
is documented research evidence, not a delivered signing change.

The same manifest contains 33 native `csreq` observations: 17 compiled byte fixtures
and 16 rejections. [Unit tests](../pkg/codesign/requirement_sets_test.go) check those
bytes, provenance, ownership, resource limits and malformed inputs on every OS.
[Acceptance tests](../acceptance/requirement_sets_test.go) rerun the native compiler
on Mac, compare 18 complete ad-hoc signed trees across six representations and three
input forms, and check 12 rejection/preservation cases. Twelve additional
[certificate cases](../acceptance/native_identity_test.go) compare native layout,
non-CMS components and matched-time complete RSA slices, with independent strict
verification. Source fuzzing now exercises set compilation as well as single
expressions; the existing binary-set target remains.

Three-OS producer evidence records deterministic compiled, input, signed-tree and
extracted-text hashes for comparison with the independently native-tested Mac.
Clang and Apple tools are development oracles only; production has no Apple runtime,
SDK, subprocess or CGO dependency. Release builds remain managed by GoReleaser.
