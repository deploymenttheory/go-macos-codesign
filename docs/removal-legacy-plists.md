# Declared legacy property-list encodings

Bundle removal must interpret Info.plist before choosing which file carries the
signature. A charset mismatch can select the raw plist instead of its executable,
or select an executable when native codesign would reject the metadata. The
portable parser therefore reproduces qualified CoreFoundation conversion rules
before codesign applies its existing selection and fallback policy.

## Implemented behavior

The [local plist package](../pkg/plist/README.md) implements 55 declared names
using 37 distinct single-byte mappings. Every byte was independently observed
through native `plutil`, including undefined bytes that make conversion fail.
ASCII aliases preserve high bytes as Latin-1, matching the native bulk decoder;
Windows and other legacy tables retain Apple's particular mappings and failures.
Production does not invoke a native converter or depend on the host's code page.

Selection happens before XML parsing:

- A recognized BOM or qualified unmarked-wide heuristic takes priority over the
  declaration. A UTF-8 BOM also overrides unknown, MacRoman and multibyte names.
- The byte stream must start exactly with `<?xml` for declaration selection.
  The scan recognizes exact `encoding=` and either quote character. Charset names
  use ASCII case-insensitive matching; unqualified non-ASCII names cannot enter
  a supported codec through Unicode folding. Spaces around `=`, an uppercase keyword or leading text
  whitespace do not select that charset. A substring such as `xencoding=` does.
  The first selected encoding wins when the attribute is repeated.
- Legacy conversion validates the entire input, including suffixes after a
  completed root. An undefined byte produces a native format failure and the
  existing raw-plist fallback. UTF-8 instead parses its first value directly;
  invalid bytes after that value can be ignored.
- The observed declaration names `macintosh`, `mac`, `macroman` and `x-mac-roman`
  fail in this property-list caller, even with ASCII contents. This does not
  claim that other CoreFoundation consumers cannot decode MacRoman.
- Unqualified names, including Shift_JIS and stateful encodings, remain explicit
  unsupported errors. They cannot silently authorize raw-plist fallback.

Input and expanded UTF-8 are each bounded at 8 MiB; the declaration still counts
toward conversion size. Depth and value budgets remain 32 and 100,000. Exhausting
a budget stops removal before mutation. These are documented implementation
limits, not claims about Apple's maximum sizes. Interpretation never rewrites the
original metadata, executable or filesystem URL.

`DecodeDictionary` and the compatibility `Unmarshal` retain their separate
validation contracts. This phase changes the native-profile `Decode` path used
for removal; it does not silently change signature serialization or add CLI modes.

## Evidence and required validation

| Evidence | Required checks |
| --- | --- |
| [Native byte corpus](../testdata/bundle-removal/plist-legacy-values.json) | 55 names × 256 bytes; every success/failure replayed through the public API; fresh macOS capture compares every scalar |
| [Native removal corpus](../testdata/bundle-removal/plist-legacy.json) | 126 inputs × three layouts × ordinary/platform metadata = 756 cases; targets, bytes, inode identity, control attributes and envelope effects |
| [Native complete values](../testdata/bundle-removal/plist-xml-values.json) | 126 new values plus all 106 earlier values; decoded strings and keys, including controls, are compared in full |
| [Generated tables](../pkg/plist/legacy_tables.go) | Deterministic Go generator checks retained driver/corpus provenance and generated source on all hosts |
| Linux/Windows exports | Each producer must supply all 756 results; the Mac import job compares 1,512 results against fresh native operations |
| Boundaries and failures | Exact expansion limit and overflow, unsupported-name errors, malformed declarations, unchanged input ownership and unchanged bundles after fatal errors |

The input corpus includes every defined byte of each charset, undefined bytes
inside and after XML, declaration syntax and case, BOM priority, native MacRoman
rejection, and UTF-8 failure/suffix controls. It is built from native observations,
not production lookup tables. All earlier operation and value corpora remain.
The shared capture driver was rerun for every earlier profile when extended.

[Clang evidence](../spec/apple-removal-discovery.json) retains 21 complete Apple
C bodies for arm64 and x86_64 Darwin. Three added built-in converters and the
verbatim Windows-1252 table expose mapping/failure branches. The pinned
[CFStringEncodings bulk decoder](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFStringEncodings.c)
is source-reviewed and hashed separately: its ASCII/Latin-1 fast path bypasses
the strict ASCII built-in. It is not counted as a compiled complete body.
Historical source explains the implementation; live observations establish the
current native profile.

Every production package must exceed 95% coverage on Linux, macOS and Windows.
All thirteen fuzz targets, race checks, pure-Go/provenance guards, golangci-lint,
the existing native harness and all six GoReleaser targets remain mandatory.
See [progress](progress.md) and the implementation PR for final CI results.

## Remaining work

- Qualify additional aliases and multibyte/stateful codecs with stream-level
  native evidence, invalid/truncated sequence behavior, output fidelity and
  mutation tests. Single-byte tables do not establish these contracts.
- Complete remaining XML declaration/markup/DTD/scalar and OpenStep NUL grammar,
  and broader binary object graph qualification.
- Continue metadata normalization, filesystem alias/discovery and the other
  codesign operations tracked in the [implementation plan](implementation_plan.md).

These gaps apply to the implementation on every host. This profile does not
claim complete CoreFoundation parsing or full native codesign parity.
