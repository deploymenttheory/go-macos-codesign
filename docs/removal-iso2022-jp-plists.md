# ISO-2022-JP property-list interpretation

Info.plist selects which file loses its signature during bundle removal. The
pure-Go decoder now interprets six native-qualified ISO-2022-JP declarations
identically on Linux, macOS and Windows. It preserves the original metadata and
the existing removal, fallback and resource-limit contracts.

## Supported behavior

The ASCII case-insensitive names `iso-2022-jp`, `iso_2022_jp`, `iso2022jp`,
`csiso2022jp`, `cp50221` and `windows-50221` share one captured mapping family.
ISO-2022-JP-1 and ISO-2022-JP-2 are different native families and remain
unqualified. A generic standards converter cannot substitute for these captures.

The decoder starts in ASCII state. Recognized escapes change state at character
boundaries:

| State | Escape bytes | Native mapping |
| --- | --- | --- |
| ASCII | `ESC ( B`, `ESC ( H` | All 256 bytes map to their Latin-1 scalar |
| Roman | `ESC ( J` | ASCII mapping with yen and overline substitutions |
| Kana | `ESC ( I`, `ESC ) I` | Bytes `21`–`5f` map to halfwidth characters |
| JIS X 0208 | `ESC $ @`, `ESC $ B`, `ESC $ D` | 7,137 pairs in `21`–`7e` |
| JIS X 0212 | `ESC $ ( D` | 6,064 pairs in **`a1`–`fe`** |

In particular, native `ESC $ D` selects the 0208 table, and the 0212 state
requires high-bit pairs. Unknown or incomplete escapes remain data in the
current state. SI/SO do not introduce shifts. An escape after a pending pair
lead is pair data, not a new state. Invalid, undefined and incomplete pairs
fail without replacement characters. EOF does not itself require an ASCII reset.

Conversion covers the whole input, including bytes after the XML root. The
native caller has a minimum 504 UTF-16-unit output buffer. At 504 or more decoded
units, trailing recognized escapes fail because the full-buffer conversion loop
cannot consume them. A single `ESC ( B` following the final non-ASCII-state
character is consumed with that character and succeeds. Redundant ASCII resets,
`ESC ( H` and multiple trailing escapes do not receive that exception. Counts
include declaration and XML syntax before declaration neutralization.

These native conversion failures return `ErrFormat`, allowing the existing
qualified raw-plist removal fallback. Input and converted UTF-8 sizes retain
their separate 8 MiB budgets; a `LimitError` is fatal before mutation. Exact
Unicode executable discovery uses the existing path checks. Wider normalization
and filesystem alias behavior remain separate work.

## Evidence and testing

The [state capture](../scripts/probe-plist-iso2022-jp.go) compiles a temporary C
oracle with host Clang and calls `CFPropertyListCreateWithData`. For each of six
names and ten state prefixes, it captures 256 singletons, 65,536 pairs, 65,536
escape vectors and 65,536 extended-escape vectors, in string-body and EOF
contexts: **23,623,680 observations**. It cross-checks **17,580** inputs directly
with `plutil`. Both contexts are retained independently, with exact values,
failures, per-name digests and source/oracle/host provenance in the
[corpus](../testdata/bundle-removal/plist-iso2022-jp-values.json).

The [generator](../scripts/generate-plist-iso2022-jp.go) verifies all inventories,
digests, mappings and BMP scalar assumptions before emitting Go tables. Every
OS checks deterministic generation and replays every observation through public
`Decode`. The separate [boundary probe](../scripts/probe-plist-iso2022-jp-boundaries.go)
retains **3,240 actual plutil cases** at 503, 504 and 505 units, including repeated
escapes and incomplete suffixes. CI repeats both captures and rejects drift.

The [operation corpus](../testdata/bundle-removal/plist-iso2022-jp.json) retains
**1,836 cases**: 51 states × six names × three layouts × two metadata locations.
It includes every defined mapping, state transitions, malformed sequences,
terminal states, buffer boundaries, Unicode executables, BOM precedence and
declaration dispatch. API and CLI tests compare bytes, identities, signature
attributes, control attributes and envelope effects. Linux and Windows each
export every case for fresh native comparison: **3,672 additional results**,
bringing ten plist profiles to **12,480 required foreign results**.

Full native values total **944**, adding 306 while preserving all 638 previous
observations. Every earlier operation profile is recaptured after shared-driver
changes and its complete case array must remain unchanged. Dedicated tests
preserve exact expansion bounds, input immutability and no-mutation failures.

The [Clang evidence](../spec/apple-removal-discovery.json) retains **27 complete
Apple function bodies** for arm64 and x86_64 Darwin. This phase adds the complete
byte-to-Unicode conversion dispatcher and decoded-length dispatcher from the
[pinned Apple source](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFStringEncodingConverter.c).
The buffer structure is retained verbatim; the bulk caller's minimum-capacity
rule is separately source-reviewed in
[CFStringEncodings.c](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFStringEncodings.c).
That entire caller is not claimed as compiled evidence. Historical source
explains contracts; current native captures establish mapping and terminal-reset
behavior, including the exception above.

The required macOS native-capture job runs alongside the full three-OS test
matrix. Foreign verification depends on both. All existing capture commands,
100-framework stress controls, thirteen fuzz targets, race checks, guards, lint,
strict coverage above 95% for every production package/OS and six GoReleaser
targets remain mandatory. Production adds no native binding or dependency.

Race and all thirteen one-minute fuzz runs execute in separate required jobs;
the combined `race-and-fuzz` gate fails if either fails or is cancelled. Each
worker retains a 20-minute job limit. The exhaustive race suite has an explicit
18-minute test deadline inside that bound; the former implicit ten-minute Go
deadline cannot accommodate the larger instrumented native replay. No cases,
race instrumentation, assertions or fuzz durations are removed.

## Remaining work

ISO-2022-JP-1, ISO-2022-JP-2, GB18030 and further aliases require independent
qualification. Unicode normalization and filesystem aliases, remaining OpenStep
NUL contexts, wider XML/binary grammar and metadata normalization remain in the
[implementation plan](implementation_plan.md). This phase does not establish
complete plist or codesign parity. Final validation belongs to the draft PR;
the user controls merging.
