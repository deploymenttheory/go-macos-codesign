# Unmarked property lists during removal

Signature removal now interprets unmarked wide-character metadata using the
macOS detection rule on Linux, macOS and Windows. Correct detection matters:
changing the dictionary's executable keys can change which file loses its
signature. Conversion is for interpretation only; original metadata bytes,
inodes and the acquired raw plist URL remain intact.

## Native detection and selection

An explicit UTF-8/16/32 byte-order mark takes precedence. Otherwise, when an
input has more than two bytes and either of its first two bytes is zero,
CoreFoundation skips those first two bytes and interprets the remainder as
native UTF-16. The qualified Mac architectures are little-endian. The Go
implementation fixes that byte order to match macOS on every producer host;
it does not infer big-endian text from which leading byte is zero.

| Captured input | Native-compatible result |
| --- | --- |
| Unmarked UTF-16LE XML beginning with `<` | The opening character is dropped; no executable dictionary |
| Unmarked UTF-16LE with a disposable leading unit before XML | That unit is dropped; the XML dictionary supplies executable keys |
| Unmarked UTF-16LE OpenStep dictionary | The opening brace is dropped; the remaining strings-file form retains its keys |
| Either leading byte zero, followed by little-endian XML | Skip both prefix bytes and interpret that XML |
| Standard unmarked UTF-16BE examples | No byte swap; captured dictionaries fail interpretation |
| Standard unmarked UTF-32LE/BE examples | Enter the UTF-16 heuristic, not a UTF-32 detector; captured inputs supply no executable dictionary |
| A second BOM after the discarded unit | It is not another encoding selection; captured inputs supply no dictionary |
| Conflicting XML encoding declaration after detection | The detected wide-character codec controls conversion |
| Incomplete final UTF-16 unit | Ignore the incomplete byte |
| Unmatched UTF-16 surrogate after complete XML | Retain the convertible prefix |

A missing dictionary preserves native raw-plist fallback under the supported
layout rules. It does not authorize selecting a different metadata file.
These results describe the captured forms; they do not introduce a general
big-endian or unmarked UTF-32 codec guess.

## Parser selection and bounds

The [converter](../pkg/plist/encoding.go) retains the existing
UTF-16 prefix and size rules. The [removal interpreter](../pkg/codesign/bundle_removal_plist.go)
checks the first native object character after resource preflight, so invalid
converted prefixes cannot be reinterpreted by the dependency as another codec
or have a second BOM stripped. Malformed prefixes cannot conceal later nesting
or value-count limits.

The plist dependency has no API to select its OpenStep parser. For text already
classified as OpenStep, the adapter prepends the fixed, neutral comment `/*<*/`
to its interpretation copy. The comment is invalid XML before any user tag and
valid OpenStep whitespace. This forces text parsing and prevents a second text
encoding guess. It never changes a source file, an extracted string or a key.
The copy adds five bounded bytes after the original input has passed preflight.
Native regression cases prove that XML inside a quoted OpenStep string remains
string content rather than becoming a different dictionary.

Input and decoded text remain limited to 8 MiB, with 32 levels and 100,000
values. Both acquisition and interpretation failures remain fatal before
mutation; tests assert their respective error categories and unchanged bundle
contents. Signing, display and verification retain their strict parser.

## Evidence and required acceptance

The [capture driver](../scripts/probe-removal-plist-interpretation.go) adds
`-profile unmarked`, recording [408 operations](../testdata/bundle-removal/plist-unmarked.json):
68 byte sequences in ordinary/platform metadata across Contents apps, flat
frameworks and versioned frameworks. Inputs cover both byte orders at both
widths, prefix removal, zero-byte position, short data, declarations, secondary
BOMs, partial tails, surrogates and quoted XML. The prior profiles remain intact
and were recaptured with the shared driver's updated source hash.

Every case replays through the public API and CLI on all three OSes. macOS
compares fresh native attributes, explicit AppleDouble carriers and Apple
`codesign`; the foreign-import job requires **816 additional results**, with
both Linux and Windows represented for every case. Captures assert selected
signature removal, original file bytes/inodes/control attributes and envelope
removal.

The [native value probe](../scripts/probe-removal-xml-values.go) now records
**106 observations**: all 38 earlier character observations plus the 68 new
inputs. Portable tests compare complete values and provenance. Its mandatory
macOS `-check` compares fresh contents and statuses with the retained observations
and cannot overwrite its reference.

[Apple's pinned property-list source](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFPropertyList.c)
provides the complete conversion caller and UTF-8 conversion helper;
[the old-style parser](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFOldStylePList.c)
provides complete initial-object dispatch and its verbatim unquoted-character
predicate. [Clang evidence](../spec/apple-removal-discovery.json) now contains
**18 complete bodies on both Darwin targets**. Parser state and helper interfaces
are compile shims. Current byte order, declaration precedence and parser outcomes
are established by live native observations, not historical source alone.

Unit tests cover original-buffer preservation, strict-parser isolation, invalid
prefixes, short inputs, acquisition/decoded-size bounds and complexity failures
without mutation. Unmarked seeds extend the existing parser fuzz target. The
strict per-package coverage threshold, race, all twelve fuzz targets, native
captures, foreign imports, lint and six-target GoReleaser gates are unchanged.

The full local harness also exposed an existing nondeterministic native nested
permission result. The [permission acceptance](signing-permissions.md) now checks
that specific grandchild worker against a successful native control and rejects
partial writes or ancestor changes. The portable signer's exact preservation
requirement remains unchanged.

## Remaining work

- The [declared legacy profile](removal-legacy-plists.md) implements 55 single-byte
  charset names. Additional aliases and multibyte/stateful stream behavior still
  need native corpora and bounded conversion.
- Other OpenStep NUL contexts remain explicit unsupported errors, including NUL
  inside quoted strings. This phase qualifies invalid initial objects and tiny
  inputs without treating all embedded NUL as a native syntax failure.
- Wider XML/OpenStep grammar, scalar/binary representations, metadata key and
  path normalization, plist aliases and other operations remain in the
  [implementation plan](implementation_plan.md).

See [progress](progress.md) for validation status. This closes the captured
unmarked detection phase, not complete property-list or native codesign parity.
