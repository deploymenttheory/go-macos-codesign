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

## Evidence and tests

The package is tested directly against 106 retained complete native values and
through all existing codesign unit, CLI and mutation comparisons. Corpus and
capture-driver hashes link the tests to native evidence. CI recaptures the native
values on macOS and compares Linux/Windows operation exports with native codesign.
The existing eighteen complete Apple C bodies and Clang evidence remain in
[`spec/apple-removal-discovery.json`](../../spec/apple-removal-discovery.json).

Every production package must exceed 95% coverage on each host. All twelve
existing fuzz targets remain; `FuzzDecode` additionally exercises both bounded
public entry points and checks that inputs remain unchanged. Race checks, pure-Go
dependency guards and six GoReleaser targets remain mandatory.

## Outstanding work

- **Declared legacy encodings:** the next functional increment. Retained research
  covers every byte for 55 ASCII-compatible charset names (14,080 observations),
  independently captured by native `plutil`. CI checks fresh native observations.
  These tables are research evidence; the converter does not yet implement them.
  Qualification must also cover declaration selection, whole-stream conversion,
  invalid bytes, resource expansion and actual removal targets on all three hosts.
- **Other encodings and aliases:** multibyte/stateful codecs need their own native
  stream contracts; single-byte observations cannot establish their behavior.
- **Remaining grammar:** additional OpenStep NUL contexts, XML/binary types,
  malformed graphs and wider parser behavior remain explicitly unqualified.
- **Broader codesign parity:** discovery, normalization and security-policy gaps
  remain tracked in the [implementation plan](../../docs/implementation_plan.md).

A separate repository is unnecessary until another consumer demonstrates that
it needs this qualified parser contract. This package does not claim complete
CoreFoundation, plist or codesign equivalence.
