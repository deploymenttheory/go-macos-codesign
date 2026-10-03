# Shift-JIS property-list interpretation

Bundle removal reads Info.plist to select the file carrying a signature. Japanese
metadata must select the same file on Linux, macOS and Windows; interpreting the
wrong charset or silently replacing invalid bytes can change that selection.
The local `pkg/plist` decoder now implements eight native-qualified declarations
using two separate, generated Go mapping tables.

## Behavior

| Declaration (ASCII case-insensitive) | Native family |
| --- | --- |
| `shift_jis` | CoreFoundation Shift-JIS |
| `shift-jis`, `sjis`, `ms_kanji`, `csshiftjis`, `cp932`, `windows-31j`, `windows-932` | Windows Japanese |

These names are not interchangeable. In the underscore family, byte `5c` maps to
U+00A5 yen, `7e` to U+203E overline and pair `8160` to U+301C wave dash. The
Windows family instead produces backslash, tilde and U+FF5E fullwidth tilde.
Native mappings also accept some unexpected pairs: `817f` and `8180` both decode
to U+00F7 division sign. The implementation reproduces captured mappings rather
than applying a conventional trail-byte range check.

Conversion consumes the complete stream before XML interpretation, including
suffixes after a completed root. Undefined bytes/pairs and incomplete final
leads return `ErrFormat`; they never become replacement characters. Original
input bytes are unchanged. BOM selection, initial declaration scanning and XML
versus OpenStep dispatch retain the existing [encoding contract](removal-legacy-plists.md).
Input and converted UTF-8 each have an 8 MiB budget. Expansion failure is a fatal
`LimitError` before any signature or envelope mutation.

Removal can now discover an exact UTF-8 executable filename, including the
retained Japanese name `あ`. The change is confined to removal discovery;
signing/resource-seal path validation retains its current profile. Path traversal,
invalid UTF-8, separators, control characters, length limits, trailing dots/spaces
and Windows reserved names remain rejected. The Unicode device-name checks follow
[Microsoft's filename rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
This does not implement cross-spelling Unicode normalization or filesystem alias
matching; those remain discovery prerequisites below.

## Evidence and mandatory validation

- [`probe-plist-shift-jis.go`](../scripts/probe-plist-shift-jis.go) compiles a
  disposable C oracle with the host Clang and calls `CFPropertyListCreateWithData`.
  Every singleton and two-byte string is observed both inside CDATA and after a
  complete root for all eight names: **1,052,672 native observations**. The helper
  is test-only and never linked to the Go binary. A further **2,272 direct plutil
  comparisons** independently check all singletons and contrasting pair cases.
- The [retained stream corpus](../testdata/bundle-removal/plist-shift-jis-values.json)
  stores two deduplicated value tables, each name's complete observation digest,
  trailing-stream validity, host/SDK/compiler provenance and capture/oracle hashes.
  Unit tests replay every name, byte sequence and context through public `Decode`,
  checking full values, classified failures and immutable input. The macOS CI job
  repeats the native capture and fails on any mapping or validity drift.
- [`generate-plist-shift-jis.go`](../scripts/generate-plist-shift-jis.go) validates
  the complete corpus before generating [Go tables](../pkg/plist/shift_jis_tables.go).
  It checks stateless segmentation against every two-byte observation. Generated
  files are checked for exact reproducibility on all three hosts.
- The [operation corpus](../testdata/bundle-removal/plist-shift-jis.json) contains
  **912 cases**: 19 stream/name states × eight names × three layouts × ordinary
  and platform metadata. Every defined mapping is included in long streams;
  invalid bytes/pairs, incomplete leads, accepted DEL trails, halfwidth sequences,
  BOM precedence, declaration case and XML dispatch are covered separately.
  All 48 Unicode executable cases stay in the ordinary passing matrix.
- API and CLI tests retain selected-file bytes, inode identity, signature and
  control attributes, and envelope effects. Linux and Windows must each export
  all 912 results; the Mac import job compares **1,824 foreign results** against
  fresh native codesign operations. Eight plist profiles now require **5,832**
  foreign results in total.
- The [complete native value corpus](../testdata/bundle-removal/plist-xml-values.json)
  adds 152 values for **390 total**, including the full long mapping strings.
  All seven earlier operation profiles were recaptured after extending the
  shared driver, and their complete case arrays remain unchanged.
- Exact expansion limits, overflow after a completed root, byte-pair boundaries,
  unsupported remaining codecs and unchanged bundles after fatal errors have
  explicit tests. All thirteen fuzz targets, race tests, strict coverage above
  95% for each production package on each host, guards, golangci-lint, native
  acceptance and six GoReleaser targets remain mandatory.

The [Clang evidence](../spec/apple-removal-discovery.json) now contains 23 complete
Apple bodies on arm64 and x86_64 Darwin. The added
[`__CFStringEncodingGetICUName` and `__CFStringEncodingICUToUnicode` bodies](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFICUConverters.c)
retain codepage preference, canonical-name fallback, end-of-stream flushing,
buffer iteration and invalid-input handling. ICU types and helper interfaces are
declarations; converter-creation callback policy is source-reviewed, not counted
as a compiled body. Historical source explains control flow; live observations
establish current mappings. No ICU, native bindings, new Go dependency or runtime
subprocess is introduced into production.

EUC-JP is now qualified separately in the [EUC-JP profile](removal-euc-jp-plists.md).

## Remaining work

1. Qualify other multibyte and stateful encodings, including ISO-2022-JP
   and GB18030, along with further declaration aliases. They remain explicit
   unsupported errors before mutation on every host.
2. Complete Unicode normalization, filesystem aliases and wider executable-key
   discovery, including differing metadata and on-disk spellings. Exact-name
   discovery is not a claim of complete filesystem equivalence.
3. Complete the remaining OpenStep, XML and binary grammar/types and all broader
   obligations in the [implementation plan](implementation_plan.md).

This increment does not declare complete plist or native codesign parity. Final
validation results belong in its draft PR; the user controls merging.
