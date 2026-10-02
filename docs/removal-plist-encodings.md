# Encoded property lists during removal

Signature removal interprets UTF-16LE and UTF-16BE property lists carrying a
byte-order mark on Linux, macOS and Windows. This applies to ordinary and
platform metadata in supported apps and frameworks. Decoding supplies discovery
keys; it never rewrites the acquired plist, changes its inode or switches its raw
URL to another metadata file. Signing, display and verification keep their
existing strict parser.

## Qualified behavior

| Input | Removal interpretation |
| --- | --- |
| UTF-16LE/BE with BOM, XML or OpenStep | Decode before executable selection |
| BMP and supplementary Unicode characters | Preserve decoded characters |
| BOM with a conflicting XML encoding declaration | BOM controls conversion |
| Odd final byte | Interpret the complete code-unit prefix |
| Unmatched surrogate | Interpret the prefix before that surrogate |
| Invalid/truncated dictionary or BOM alone | Retain the raw plist target under the existing layout rules |
| Decoded text exceeding 8 MiB | Fail before mutation |

The prefix rule can preserve a complete XML dictionary followed by an invalid
surrogate, while an invalid surrogate inside a dictionary leaves an incomplete
document. The latter supplies no executable keys. Structural bounds still apply
after conversion: 32 levels and 100,000 values. Original encoded input also
retains its 8 MiB bound. These operational limits remain fatal rather than
authorizing fallback to a different removal target.

The [pure-Go converter](../pkg/codesign/bundle_removal_encoding.go) runs before
the existing bounded interpreter. It has no host-dependent path or native
binding. UTF-32, unmarked UTF-16, decoded NUL characters and other unqualified
encoding forms remain explicit errors. The platform loader's unsupported-input
cleanup test now uses UTF-32; UTF-16 success and malformed-prefix behavior have
their own native replay tests.

## Evidence and test contract

[Apple's pinned parser source](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFPropertyList.c)
detects a BOM before a declaration and converts non-UTF-8 input before parsing.
Its `encodingForXMLData` body is retained through the
[Clang extraction](../scripts/extract-removal-discovery.go), bringing the evidence
to nine complete bodies on both Darwin targets. Error-construction and existing
private interfaces use declarations; the complete encoding decision body is
compiled against the host SDK. Current native results, rather than historical
source alone, establish the supported behavior.

The existing [capture driver](../scripts/probe-removal-plist-interpretation.go)
accepts `-profile encodings`. Its [120-case corpus](../testdata/bundle-removal/plist-encodings.json)
contains 20 inputs across two metadata locations and three layouts. Capture
asserts selected-file effects, unchanged bytes/inodes/control attributes and
envelope removal. All 180 earlier interpretation cases remain mandatory and
were recaptured after the shared driver changed.

API and CLI replay run on every OS. macOS compares Go with fresh native
operations; the foreign-import job requires **240 additional records**, one
Linux and one Windows result per case. Native CI also recaptures the corpus.
UTF-16 seeds extend the existing parser fuzz target. Expansion/complexity limits,
surrogate boundaries, unchanged input buffers and strict-parser isolation have
focused unit tests. All existing coverage, race, twelve fuzz targets, provenance,
lint and six GoReleaser build gates remain unchanged.

## Outstanding work

- Unmarked UTF-16 needs separate XML/OpenStep qualification. Exploratory native
  probes accepted little-endian OpenStep but did not select executable keys for
  the equivalent XML or big-endian OpenStep. Those observations are not an
  implemented portable contract and must not be generalized into BOM detection.
- UTF-32 and declared legacy encodings need native corpora and bounded codecs.
- Native accepted a decoded NUL in unrelated XML string metadata during research;
  Go's XML parser rejects that grammar. It remains an explicit unsupported case,
  requiring grammar work rather than silently discarding the executable key.
- Wider XML grammar, binary representations, key normalization, plist aliases
  and the other CLI operations remain in the [implementation plan](implementation_plan.md).

This completes the BOM-marked UTF-16 removal profile, not all property-list
encoding support or full native `codesign` parity. See [progress](progress.md)
for the current validation status.
