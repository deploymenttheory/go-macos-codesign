# plist

`plist` is the pure-Go property-list parser used by this project's codesign
implementation. It runs on Linux, macOS and Windows without Apple frameworks,
native bindings, subprocesses or filesystem access.

Apple property lists can contain XML, binary object graphs or OpenStep text.
Codesign needs to interpret these bytes to find bundle executables, validate
resource metadata and read entitlement and CMS data. General-purpose decoders do
not reproduce every observed CoreFoundation parsing rule: duplicate keys, text
encoding detection, character conversion and malformed-input behavior can change
which file a removal operation selects.

This package owns parsing and bounded text conversion. `pkg/codesign` owns
bundle discovery, raw-file fallback, executable selection, signature schemas,
byte-exact signature serialization and mutation. Original input bytes remain the
caller's property and are never rewritten. APFS continues to own filesystem and
host-metadata operations.

## API

| Function | Use | Contract |
| --- | --- | --- |
| `Decode` | Interpret metadata using the native profiles qualified by this repository | XML, binary and OpenStep values; scalar and container roots; classified errors |
| `DecodeDictionary` | Validate the existing codesign dictionary profile | XML/binary dictionaries, duplicate-key rejection and an XML `plist` wrapper |
| `Unmarshal` | Preserve existing typed CMS/entitlement decoding | Adapter to the existing `howett.net/plist` contract, including its format result; callers supply their own size and schema checks |

The two bounded entry points serve existing caller contracts. They are not CLI
modes or a new choice between preserving data and imitating macOS. In particular,
`Decode` never selects a file or authorizes removal after an error; codesign makes
those decisions.

```go
value, err := plist.Decode(data)
if err != nil {
    return err
}
metadata, ok := value.(map[string]any)
if !ok {
    return fmt.Errorf("expected a metadata dictionary")
}
executable, _ := metadata["CFBundleExecutable"].(string)
```

`Decode` distinguishes `ErrFormat` from `ErrUnsupported`. `LimitError`, inspected
with `errors.As`, identifies exhausted native-interpretation budgets and also
matches `ErrFormat`. Unsupported representations and budget exhaustion must not
be mistaken for native evidence that metadata is empty or malformed.
`DecodeDictionary` retains the existing strict validation errors, including
`ErrFormat` for its XML size/structure limits. `Unmarshal` returns dependency
errors directly and does **not** apply the bounded native profile.

The bounded profiles cap input at 8 MiB, nesting at 32 and values at 100,000.
Native decoding additionally bounds converted text and expanded binary graphs;
shared references cannot bypass expansion budgets. These are explicit safety
limits, not claims that Apple's parser uses identical limits. Return values use
Go maps, slices, strings, booleans, numbers, byte data and dates. The currently
qualified binary UID profile returns its bytes; this is not an unrestricted
NSKeyedArchiver object model.

## Declared single-byte encodings

`Decode` supports 55 native-qualified charset names: ASCII aliases, ISO-8859-1
aliases and ISO-8859-2/3/4/5/6/7/8/9/10/11/13/14/15/16, Windows-874 and 1250–1258
with their `cp` aliases, IBM437/850/852/855/860/862/863/865/866, KOI8-R, KOI8-U
and x-mac-cyrillic. These are Apple's observed mappings, including its permissive
ASCII interpretation and undefined-byte failures, rather than generic charset tables.

BOM selection precedes the initial declaration scan. Legacy input is converted
in full, including trailing bytes, before XML interpretation; an undefined byte
produces `ErrFormat`. UTF-8 parsing can ignore bytes after a completed root.
The native-rejected MacRoman declaration names are format failures for this
property-list caller. Other unqualified names remain `ErrUnsupported`.
Conversion is capped at 8 MiB before declaration neutralization and parsing. XML dispatch is retained even
when a declaration is followed by OpenStep text. No API
rewrites the source. See the [qualified behavior and evidence](../../docs/removal-legacy-plists.md).

## Declared Shift-JIS encodings

`Decode` also supports eight qualified Japanese charset names. `shift_jis` selects
Apple's Shift-JIS family; `shift-jis`, `sjis`, `ms_kanji`, `csshiftjis`, `cp932`,
`windows-31j` and `windows-932` select its Windows Japanese family. Their mappings
are distinct. Entire-stream validation rejects undefined pairs and incomplete
leads, including ignored suffixes, before interpretation. The same 8 MiB decoded
budget and original-byte ownership apply.

Generated Go tables retain native observations, including mappings that differ
from conventional Shift-JIS decoders. Every one- and two-byte input is replayed
in body and EOF contexts for every name: 1,052,672 observations. Native CI
recaptures them with a test-only C property-list oracle plus 2,272 direct plutil
comparisons. See [Shift-JIS behavior and evidence](../../docs/removal-shift-jis-plists.md).

## Declared EUC-JP encodings

`Decode` supports `euc-jp`, `euc_jp`, `eucjp`, `cseucpkdfmtjapanese`,
`extended_unix_code_packed_format_for_japanese`, `x-euc-jp`, `cp51932` and
`windows-51932`. They share a native-qualified table with unusual trail and
extension mappings. Every captured `8f`-prefixed triple fails, matching Apple.
Complete-stream validation, conversion budgets and immutable input apply.
The 2,101,248 native observations are replayed on every host and recaptured on
macOS, with 2,464 independent plutil checks. See
[EUC-JP behavior and evidence](../../docs/removal-euc-jp-plists.md).

XML string/key assembly removes exactly one leading U+FEFF after joining raw
text, CDATA and entities; interior and repeated characters are preserved. This
native string rule applies independently of the declared input encoding.

## Declared ISO-2022-JP encodings

`Decode` supports `iso-2022-jp`, `iso_2022_jp`, `iso2022jp`, `csiso2022jp`,
`cp50221` and `windows-50221`. Five mapping states and ten state prefixes follow
native escape, pair, EOF and conversion-buffer behavior. All 23,623,680 retained
body/EOF observations and 3,240 conversion-boundary cases replay on every OS;
macOS recaptures them, with 17,580 direct plutil cross-checks. Input immutability,
whole-stream validation and both conversion budgets remain required. See
[ISO-2022-JP behavior and evidence](../../docs/removal-iso2022-jp-plists.md).

## Declared ISO-2022 extensions

`Decode` supports JP-1 (`iso-2022-jp-1`, `iso_2022_jp_1`, `iso2022jp1`) and JP-2
(`iso-2022-jp-2`, `iso_2022_jp_2`, `iso2022jp2`, `csiso2022jp2`). These families
use strict seven-bit streams, distinct pair tables and newline state resets.
JP-2 additionally supports Chinese, Korean and Latin/Greek G2 single shifts.
Their full-buffer trailing escapes fail without the base family's reset exception.
All 15,651,328 captured byte observations and 13,650 complete stream cases replay
on each host. See [behavior and evidence](../../docs/removal-iso2022-extensions.md).


## Evidence and tests

The package is tested directly against 1,294 retained complete native values and
through all existing codesign unit, CLI and mutation comparisons. Corpus and
capture-driver hashes link the tests to native evidence. CI recaptures the native
values on macOS and compares Linux/Windows operation exports with native codesign.
The thirty-one complete Apple C bodies and Clang evidence remain in
[`spec/apple-removal-discovery.json`](../../spec/apple-removal-discovery.json).

All 14,080 native byte observations are replayed through `Decode`. The
[single-byte tables](legacy_tables.go) are generated deterministically by
[`generate-plist-legacy.go`](../../scripts/generate-plist-legacy.go); CI checks
reproducibility on every host and recaptures native mappings on macOS.

Every production package must exceed 95% coverage on each host. All twelve
existing fuzz targets remain; `FuzzDecode` additionally exercises both bounded
public entry points and checks that inputs remain unchanged. Race checks, pure-Go
dependency guards and six GoReleaser targets remain mandatory.

## Outstanding work

- **Other encodings and aliases:** remaining multibyte/stateful codecs need their own native
  stream contracts; single-byte observations cannot establish their behavior.
- **Remaining grammar:** additional OpenStep NUL contexts, XML/binary types,
  malformed graphs and wider parser behavior remain explicitly unqualified.
- **Broader codesign parity:** discovery, normalization and security-policy gaps
  remain tracked in the [implementation plan](../../docs/implementation_plan.md).

A separate repository is unnecessary until another consumer demonstrates that
it needs this qualified parser contract. This package does not claim complete
CoreFoundation, plist or codesign equivalence.
