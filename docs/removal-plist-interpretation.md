# Property-list interpretation during signature removal

Removal needs an executable name or a raw plist target; it does not need enough
metadata to build or validate a signature. `--remove-signature` now interprets
bounded UTF-8 XML, OpenStep and supported binary metadata under that distinction
on Linux, macOS and Windows. Signing, display and verification retain their
strict dictionary parser.

The acquired ordinary or platform plist remains selected when decoding fails or
the root is not a dictionary. Existing bundle-stem lookup still runs where the
layout permits it; otherwise removal operates on that raw plist and then purges
the selected signature envelope. A malformed platform plist does not trigger an
ordinary-plist retry. Selected executable read/format failures remain fatal.

## Supported interpretation

| Metadata | Discovery behavior |
| --- | --- |
| XML dictionary, with or without the plist wrapper | Use its executable key |
| UTF-8 BOM | Interpret the following UTF-8 document |
| XML duplicate keys | Last value wins |
| Complete XML value followed by trailing text or another root | Use the first value |
| OpenStep dictionary or strings-file syntax | Use its executable key |
| OpenStep comments, quoted strings, octal/Unicode escapes, arrays and data | Decode before applying executable-name policy |
| OpenStep duplicate keys | Last value wins |
| Binary dictionary duplicate keys | First value wins |
| Binary UID in unrelated metadata | Retain its non-string character; it is not an executable name |
| Binary UID beyond the native 32-bit range | Invalid dictionary; retain the raw plist URL |
| Captured syntax errors, truncated/cyclic binary input or non-dictionary roots | Supply no executable keys and retain the raw plist URL |
| Byte, nesting, object-count or expanded-graph limits exceeded | Fail before mutation; never reinterpret an operational limit as an empty dictionary |

The existing 8 MiB, 32-level and 100,000-value bounds remain. XML preflight bounds
its first interpreted value before generic decoding; OpenStep preflight counts
containers and scalar/key tokens while treating comments, quoted strings and
hex data as opaque. Binary parsing retains cycle detection and expanded-value/
byte accounting. It continues to reject unsupported object types. Unknown text
encodings are explicit errors, not evidence that native metadata is empty.

The pure-Go `howett.net/plist` dependency supplies XML/OpenStep interpretation
after bounded preflight. The existing binary object-graph reader is shared;
removal has explicit duplicate/root/UID policy. This introduces no native runtime
binding, subprocess or new SDK primitive.

## Evidence and required tests

The [Go capture script](../scripts/probe-removal-plist-interpretation.go) records
[180 native cases](../testdata/bundle-removal/plist-interpretation.json): 30 inputs,
ordinary/platform locations and Contents app, flat-framework and versioned-
framework layouts. Expected selection is asserted independently against native
`codesign`. Each record retains input bytes, links, status/output, selected file,
content hashes, inode identity and signature/envelope effects, together with the
host and native binary/capture-source hashes. Fixtures use disposable generic
signature attributes and never access a personal signing identity or keychain.

Every case replays through the Go API and production CLI on all three hosts.
Mac acceptance also compares native attributes and explicit AppleDouble carriers
with fresh Apple operations. The unchanged import job requires **360 new foreign
records**, two producers per native case, in addition to every previous import.
Resource-limit, unsupported-encoding and strict-parser tests remain mandatory.
Tests that previously required removal to reject invalid metadata now assert the
measured raw-plist selection and unchanged executable/data, while retaining the
original signing/verification rejection and preservation assertions.

The [Clang extraction](../scripts/extract-removal-discovery.go) now records eight
complete Apple function bodies for both Mac architectures. The bundle loader
shows invalid/non-dictionary empty synthesis and raw-URL retention. Complete
`CFDictionaryAddValue` and `CFDictionarySetValue` bodies retain distinct hash
insertion/replacement calls; Objective-C dispatch/KVO/type-validation interfaces
are declared shims. Pinned binary parsing calls `CFDictionaryAddValue` for mutable
dictionaries; the current native corpus independently proves first-duplicate
selection. Historical code is not treated as proof of all current parser behavior.
Sources: [Apple bundle plist loading](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBundle_InfoPlist.c),
[Apple binary plist parsing](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBinaryPList.c),
[Apple dictionary operations](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFDictionary.c).

The new `FuzzRemovalPlist` target joins all eleven existing fuzz targets. Strict
coverage above 95% per production package, actual Windows/macOS/Linux execution,
native capture/import, race, provenance, lint and six GoReleaser builds remain
required. See [progress](progress.md) for the implementation PR and validation.

## Remaining differences

- UTF-16 and other text encodings, wider XML grammar/scalar/DTD/entity behavior,
  legacy text corner cases and unsupported binary object types/large integers
  still require native qualification and implementation. This is a captured
  interpretation profile, not a complete CoreFoundation parser replacement.
- Binary address/length widths beyond eight bytes, unused header references,
  non-string dictionary keys, unpaired UTF-16 and out-of-range dates remain
  explicit representation errors. These strict-reader restrictions are not
  treated as evidence that the native dictionary is empty.
- Product/platform key normalization beyond the qualified executable override,
  plist aliases, case/Unicode discovery, other layouts and concurrent mutation
  retain their roadmap obligations.
- Signing/display/verification parser policy needs independent qualification;
  removal's permissive interpretation must not weaken signature validation.
- Native has different resource ceilings. The documented bounded limits remain
  explicit compatibility constraints and must not silently change the target of
  a mutating operation.
