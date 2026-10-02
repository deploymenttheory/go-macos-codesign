# Encoded property lists during removal

Signature removal interprets UTF-16LE/BE and UTF-32LE/BE property lists carrying a
byte-order mark on Linux, macOS and Windows. This applies to ordinary and
platform metadata in supported apps and frameworks. Decoding supplies discovery
keys; it never rewrites the acquired plist, changes its inode or switches its raw
URL to another metadata file. Signing, display and verification keep their
existing strict parser.

## Qualified behavior

| Input | Removal interpretation |
| --- | --- |
| UTF-16LE/BE with BOM, XML or OpenStep | Decode before executable selection |
| UTF-32LE/BE with BOM, XML or OpenStep | Decode before executable selection |
| BMP and supplementary Unicode characters | Preserve decoded characters |
| BOM with a conflicting XML encoding declaration | BOM controls conversion |
| Incomplete final code unit | Ignore the final byte in UTF-16 or final one to three bytes in UTF-32 |
| UTF-16 unmatched surrogate | Interpret the prefix before that surrogate |
| UTF-32 surrogate or value above U+10FFFF | Reject the entire decoded dictionary, even when the invalid value follows a complete XML document |
| Invalid/truncated dictionary or BOM alone | Retain the raw plist target under the existing layout rules |
| Decoded text exceeding 8 MiB | Fail before mutation |

The UTF-16 prefix rule can preserve a complete XML dictionary followed by an invalid
surrogate, while an invalid surrogate inside a dictionary leaves an incomplete
document. The latter supplies no executable keys. UTF-32 instead validates every
complete scalar: an invalid value anywhere supplies no executable keys. The
selected raw plist remains the fallback target under the existing layout rules.
Structural bounds still apply
after conversion: 32 levels and 100,000 values. Original encoded input also
retains its 8 MiB bound. These operational limits remain fatal rather than
authorizing fallback to a different removal target.

The [pure-Go converter](../pkg/codesign/bundle_removal_encoding.go) runs before
the existing bounded interpreter. It has no host-dependent path or native
binding. The [XML character interpreter](removal-xml-characters.md) now handles
NUL, controls and noncharacters in strings/keys. Unmarked UTF-16/32, legacy
codecs and unqualified character contexts remain explicit errors. The platform loader's unsupported-input
cleanup test uses a declared legacy encoding; UTF-16/32 success and malformed
interpretation have their own native replay tests. UTF-32 never expands beyond
its encoded input size, but retains the same input and structural limits.

## Evidence and test contract

[Apple's pinned parser source](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFPropertyList.c)
detects a BOM before a declaration and converts non-UTF-8 input before parsing.
Its `encodingForXMLData` body is retained through the
[Clang extraction](../scripts/extract-removal-discovery.go), bringing the evidence
to fifteen complete bodies on both Darwin targets, including the subsequent
string, CDATA and entity extraction. Error-construction and existing
private interfaces use declarations; the complete encoding decision body is
compiled against the host SDK. Current native results, rather than historical
source alone, establish the supported behavior.

The extraction also retains the complete `CFUniCharFromUTF32` function and its
two surrogate predicates from
[Apple's Unicode header](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFUniChar.h).
Both strict and lossy branches remain in the AST. Apple's
[string decoder](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFStringEncodings.c)
uses strict conversion for UTF-32, with complete-unit truncation before conversion;
the new native matrix independently qualifies those results.

The existing [capture driver](../scripts/probe-removal-plist-interpretation.go)
accepts `-profile encodings` for UTF-16. Its [120-case corpus](../testdata/bundle-removal/plist-encodings.json)
contains 20 inputs across two metadata locations and three layouts. Capture
asserts selected-file effects, unchanged bytes/inodes/control attributes and
envelope removal. All 180 earlier interpretation cases remain mandatory and
were recaptured after the shared driver changed. `-profile utf32` records
[276 further cases](../testdata/bundle-removal/plist-utf32.json): 46 inputs across
the same locations/layouts, including both byte orders, XML/OpenStep, declarations,
scalar boundaries, invalid values inside/after a dictionary, incomplete code units,
empty BOMs, truncated dictionaries, OpenStep controls and ignored trailing XML
controls. A separate [36-case character corpus](../testdata/bundle-removal/plist-utf32-grammar.json)
retains native acceptance of controls, noncharacters and NUL inside XML strings.
`-profile utf32-grammar` recaptures it in macOS CI. These cases now have matching API/CLI
replay on all hosts and 72 mandatory foreign results; the subsequent
[XML character phase](removal-xml-characters.md) also adds 192 cases and 384
foreign results.

API and CLI replay run on every OS. macOS compares Go with fresh native
operations; the foreign-import job requires **240 additional records**, one
Linux and one Windows result per UTF-16 case. UTF-32 adds **552 mandatory records**;
each of its 276 cases must have both producers. Native CI recaptures both corpora.
UTF-16/32 seeds extend the existing parser fuzz target. Expansion/complexity limits,
surrogate boundaries, unchanged input buffers and strict-parser isolation have
focused unit tests. All existing coverage, race, twelve fuzz targets, provenance,
lint and six GoReleaser build gates remain unchanged.

## Outstanding work

- Unmarked UTF-16 needs separate XML/OpenStep qualification. Exploratory native
  probes accepted little-endian OpenStep but did not select executable keys for
  the equivalent XML or big-endian OpenStep. Those observations are not an
  implemented portable contract and must not be generalized into BOM detection.
- Unmarked UTF-32 and declared legacy encodings need native corpora and bounded codecs.
- XML string/key controls, U+FFFE/U+FFFF and NUL are implemented in the
  [character phase](removal-xml-characters.md). Unqualified contexts outside
  strings/keys and OpenStep NUL still require native evidence and implementation.
- Wider XML grammar, binary representations, key normalization, plist aliases
  and the other CLI operations remain in the [implementation plan](implementation_plan.md).

This completes the BOM-marked UTF-16/32 removal profiles, not all property-list
encoding support or full native `codesign` parity. See [progress](progress.md)
for the current validation status.
