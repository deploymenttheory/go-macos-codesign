# XML strings during signature removal

Removal reads XML plist strings and keys using the character behavior of macOS
CoreFoundation on Linux, macOS and Windows. This matters because rejecting a
valid `Info.plist` can change the target from its executable to the raw metadata
file. Original plist bytes, inode identity and the selected metadata URL remain
unchanged. Signing, display and verification retain their strict parser.

## Supported behavior

| Input inside a string or key | Interpretation |
| --- | --- |
| Literal NUL, controls, U+FFFE/U+FFFF | Preserve the exact character |
| Literal CR, LF or CRLF | Preserve the original line endings |
| CDATA | Append its literal bytes, including controls and markup characters |
| `lt`, `gt`, `amp`, `apos`, `quot` entities | Decode once |
| Decimal and lowercase-`x` hexadecimal numeric references | Decode Unicode scalars, including supplementary values |
| Empty numeric references `&#;` and `&#x;` | Decode U+0000, as observed on the native host |
| Surrogate, out-of-range or overflowing numeric references | Native syntax failure: no executable dictionary |
| Unknown entities, malformed CDATA, comments/PIs/child elements inside strings | Native syntax failure: no executable dictionary |
| Equivalent literal/escaped duplicate keys | Keep the last value |
| NUL/control-bearing keys | Preserve the entire key; do not truncate or confuse it with an executable key |

The [removal-only parser](../pkg/codesign/bundle_removal_xml.go) uses Go's XML
markup tokenizer with its own bounded matching stack. It reads string/key
content directly, following native CDATA/entity composition, without placeholder
substitution or changing source bytes. Other scalar values retain the existing
plist codec. A first pass checks the complete first value's structural budget
before dictionary grammar interpretation or graph allocation. This preserves the
existing rule that malformed dictionaries cannot conceal a later resource limit.

The input and decoded-text limits remain 8 MiB, with 32 levels and 100,000 values.
Limits and unsupported representations fail before mutation. The native policy
of ignoring text after the first XML value remains unchanged. Ordinary syntax
failures retain the acquired raw plist URL under the existing layout rules.

## Native evidence and required tests

The [capture driver](../scripts/probe-removal-plist-interpretation.go) adds
`-profile xml-characters`: **192 native operations**, covering 32 inputs in
ordinary/platform metadata across Contents apps, flat frameworks and versioned
frameworks. This includes UTF-8 and both BOM-marked UTF-16 byte orders. The
previous **36 UTF-32 character cases** now run as successful parity tests rather
than requiring unsupported errors. Both corpora replay through the public API
and CLI on every host. macOS also compares fresh native attributes, explicit
AppleDouble carriers and Apple `codesign` operations. Captures assert selected
signature removal, unchanged file bytes/inodes/control attributes and envelope
removal.

The foreign-import job requires **456 additional results**: Linux and Windows
must each supply all 228 cases. The preceding 180 interpretation, 120 UTF-16 and
276 UTF-32 cases remain mandatory. No OS feature or test gate is skipped.

A separate [value probe](../scripts/probe-removal-xml-values.go) invokes native
`plutil` and retains **38 complete value observations** in
[the value corpus](../testdata/bundle-removal/plist-xml-values.json). These prove
character/key fidelity, not only executable selection. Portable tests compare
the full decoded maps and arrays, validate input/driver/corpus hashes and preserve
the original input buffer. macOS CI recaptures both operation and value evidence.
This native tooling is used only for research and acceptance, never production.

[Apple's pinned C source](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFPropertyList.c)
supplies complete `parseStringTag`, `parseCDSect_pl` and
`parseEntityReference_pl` bodies to the [Clang extraction](../scripts/extract-removal-discovery.go).
There are now **15 complete bodies on both Darwin targets**. Parser state,
string-interning/error interfaces and the `NO` Boolean definition are compile
shims; function bodies remain verbatim. The historical entity implementation
uses a 16-bit accumulator. Current macOS instead preserves supplementary scalar
references and rejects invalid scalars; retained live observations establish that
contract. Historical source alone is not used to assert current entity behavior.

Strict-parser regressions, unsupported-context and limit no-mutation tests,
malformed strings, scalar boundaries and parser fuzz seeds accompany the native
replays. Per-package coverage above 95%, race checks, all twelve fuzz targets,
provenance, lint and six-target GoReleaser checks remain required.

## Remaining work

- Unmarked UTF-16/32 and declared legacy codecs still need qualified conversion.
- NUL in OpenStep and XML control characters outside strings/keys remain explicit
  unsupported errors where the existing parser cannot establish native behavior.
- Wider XML markup/DTD/scalar behavior, binary representations, metadata key
  normalization and plist aliases remain separate qualification work.
- The other signing, verification and display operations remain in the
  [full implementation plan](implementation_plan.md); this phase is not full
  `codesign` parity. See [progress](progress.md) for validation status.
