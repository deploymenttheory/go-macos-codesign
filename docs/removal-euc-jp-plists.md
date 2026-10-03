# EUC-JP property-list interpretation

Bundle removal uses Info.plist to select the file carrying a signature. EUC-JP
metadata must select the same file on Linux, macOS and Windows, including when
Apple accepts an unusual byte sequence or rejects a nominally valid extension.
The pure-Go `pkg/plist` decoder implements eight native-qualified declarations.

## Supported behavior

These ASCII case-insensitive names share one captured mapping family:
`euc-jp`, `euc_jp`, `eucjp`, `cseucpkdfmtjapanese`,
`extended_unix_code_packed_format_for_japanese`, `x-euc-jp`, `cp51932` and
`windows-51932`. Further aliases require their own qualification.

The host's mappings differ from conventional EUC-JP:

- `a422` and `a4a2` both produce `あ`; low-byte trails are not uniformly invalid.
- `a000` and `a0ff` both produce U+00A9. Other extension rows have their own
  captured mappings rather than generic Windows/JIS substitutions.
- `8e00` produces U+FEC0, `8e3f` produces U+FEFF, and `8ee0` produces U+FFA0.
- Every captured `8f`-prefixed three-byte sequence is rejected. Accepting a
  generic JIS X 0212 mapping here would differ from the native property-list caller.

All 128 ASCII singletons are identity mappings. There are 14,786 accepted
non-ASCII lead/trail pairs. Conversion processes the complete input before XML
interpretation, including bytes after a completed root. Invalid or incomplete
sequences return `ErrFormat`, without replacement characters. The input and its
converted UTF-8 representation each retain the existing 8 MiB budget. A
`LimitError` remains fatal before removal can mutate a bundle.

XML string construction has a separate rule: Apple removes one leading U+FEFF
from the final assembled string or key. CDATA, entities and raw text participate
in that assembly. Interior U+FEFF and a second leading U+FEFF remain present.
The decoder now applies this rule after assembly, rather than deleting the
character during EUC-JP conversion. Native executable/key selection and complete
value captures cover these distinctions. Original plist bytes remain unchanged.

BOM precedence, declaration scanning and XML/OpenStep dispatch retain the existing
[encoding contract](removal-legacy-plists.md). Exact UTF-8 executable discovery
uses the existing removal path checks; normalization and filesystem aliases
remain separate prerequisites.

## Evidence and validation

The [capture script](../scripts/probe-plist-euc-jp.go) builds a temporary C oracle
with host Clang and calls `CFPropertyListCreateWithData`. For each name it observes
all 256 singletons, 65,536 pairs and 65,536 `8f`-prefixed triples, in body and EOF
contexts: **2,101,248 observations**. An additional **2,464 direct plutil checks**
independently compare every singleton and 52 contrasting pairs/triples per name.

Body values use ASCII framing around the assembled string so leading-BOM string
construction cannot be mistaken for an empty byte mapping. The closing CDATA
boundary precedes the final frame character, preserving incomplete-sequence
failures. EOF observations independently establish whole-stream validity.
The [retained corpus](../testdata/bundle-removal/plist-euc-jp-values.json) records
all values, failures, per-name digests, source/oracle hashes and host provenance.

The [generator](../scripts/generate-plist-euc-jp.go) verifies the entire inventory,
ASCII segmentation, scalar mappings, triple rejection, body/EOF validity and raw
observation digests before producing [Go tables](../pkg/plist/euc_jp_tables.go).
Every OS checks deterministic generation and replays every observation through
public `Decode`. macOS CI repeats the native capture and fails on drift.

The [operation corpus](../testdata/bundle-removal/plist-euc-jp.json) contains
**1,488 cases**: 31 states × eight names × three layouts × two metadata locations.
It covers all accepted mappings in long streams, native extension/trail rules,
invalid bytes and triples, incomplete suffixes, halfwidth sequences, Unicode
executables, leading-BOM values/keys, declaration case and BOM precedence.
API and CLI tests compare selected-file bytes, inode identity, signature/control
attributes and envelope effects. Linux and Windows each export every case;
macOS independently checks **2,976 new foreign results**, bringing the nine plist
profiles to **8,808 required foreign results**.

Full native value captures add 248 observations for **638 total**. All eight
previous operation profiles are recaptured when the shared driver changes, with
their complete case arrays required to remain unchanged. Exact expansion limits,
ignored-tail overflow and no-mutation errors retain dedicated tests. Every
production package must exceed 95% coverage on every host. All thirteen fuzz
targets, race checks, guards, lint and six GoReleaser binaries remain mandatory.

The [Clang evidence](../spec/apple-removal-discovery.json) retains **25 complete
Apple function bodies** for arm64 and x86_64 Darwin. This increment adds the
[pinned charset alias resolver](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFICUConverters.c)
and [unique UTF-8 string constructor](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFPropertyList.c).
SDK headers and declared helper interfaces support syntax/AST extraction;
historical source explains the caller contracts but does not establish which
converter implementation the current host selects. Live observations establish
current mappings and errors. No native bindings, runtime subprocess or new Go
dependency is introduced into production.

## Remaining work

ISO-2022-JP, GB18030 and additional codecs/aliases still need independent stream
qualification. Unicode normalization and filesystem aliases, remaining OpenStep
NUL contexts, wider XML/binary grammar and metadata normalization remain tracked
in the [implementation plan](implementation_plan.md). This increment does not
claim complete plist or codesign parity. Final validation is reported in its
draft PR; the user controls merging.
