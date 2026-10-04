# ISO-2022-JP-1 and ISO-2022-JP-2 property lists

These encodings can appear in the XML declaration of bundle metadata. Decoding
that metadata determines which executable loses its signature during removal.
The pure-Go plist parser implements the qualified native behavior on Linux,
macOS and Windows; production does not load Apple frameworks or run converters.

## Supported behavior

| Family | Case-insensitive declaration names | Character states |
| --- | --- | --- |
| JP-1 | `iso-2022-jp-1`, `iso_2022_jp_1`, `iso2022jp1` | ASCII, Roman, Kana, JIS X 0208 and JIS X 0212 |
| JP-2 | `iso-2022-jp-2`, `iso_2022_jp_2`, `iso2022jp2`, `csiso2022jp2` | JP-1 states plus GB2312, KSC5601 and Latin/Greek G2 single shifts |

These families differ from the separately qualified
[base ISO-2022-JP family](removal-iso2022-jp-plists.md). Both require seven-bit
streams, reject unknown or incomplete escapes and SI/SO, and interpret
`ESC ( H` as Roman. JIS X 0212 uses seven-bit pairs. `ESC & @` selects JIS X 0208;
`ESC $ D`, `ESC $ ( B` and `ESC ) I` are invalid. Generated tables retain 7,336
JIS X 0208, 6,067 JIS X 0212, 7,445 GB2312 and 8,414 KSC5601 pair mappings.

JP-2 uses `ESC . A` and `ESC . F` to designate Latin and Greek G2. `ESC N`
selects that designation for one character. Designation survives G0 state
changes; repeated single shifts and redesignation before the shifted character
follow the native observations. A single shift without a designation fails.

CR/LF at a character boundary clear G2 and pending single shift. They reset
non-Roman character states to ASCII; Roman remains Roman. A newline inside a
pair is invalid. Incomplete and undefined pairs fail without replacement text.
EOF can retain a character state or a designated pending single shift.

Whole-input conversion includes bytes after the XML root. At 504 or more decoded
UTF-16 units, trailing recognized escapes fail. The base-family terminal-reset
exception does not apply. Declaration and XML syntax contribute to this count.
Conversion failures return `ErrFormat`, permitting the existing qualified
raw-plist fallback. Input and expanded UTF-8 each retain their 8 MiB bound;
`LimitError` prevents mutation. Original input and file bytes remain unchanged.

## Evidence and reproducibility

The [native byte probe](../scripts/probe-plist-iso2022-extensions.go) compiles a
temporary C oracle with host Clang and calls `CFPropertyListCreateWithData`.
For each of seven names and fifteen prefixes it captures every singleton and
pair, in string-body and EOF contexts. The initial ASCII state also captures
all two-byte escape suffixes and all two-byte extended-escape suffixes with a
mapping discriminator. This produces **15,651,328 observations** and **28,511**
independent plutil comparisons. Exact values, failures, digests and provenance
are retained in the [byte corpus](../testdata/bundle-removal/plist-iso2022-extensions-values.json).
The [generator](../scripts/generate-plist-iso2022-extensions.go) verifies the
complete inventory, alias digests and BMP mapping assumptions before emitting Go.

A separate [stream probe](../scripts/probe-plist-iso2022-extension-streams.go)
retains **13,650 complete plutil observations**: transitions, controls, G2 state,
and 503/504/505-unit boundaries. Every OS replays both corpora through public
`Decode`, comparing complete values and failure classes while checking input
ownership. Native CI independently recaptures and compares every record.

The [operation corpus](../testdata/bundle-removal/plist-iso2022-extensions.json)
contains **2,100 native codesign cases**: fifty inputs per name, three layouts
and two metadata locations. It covers all defined mapping streams, terminal
states, controls, boundaries, exact Unicode executables, BOM priority and
declaration dispatch. API and CLI replay checks selected files, original bytes,
identities, signature/control attributes and resource-envelope effects.
Linux and Windows each export every case for native verification: **4,200 new
foreign results**, bringing eleven plist profiles to **16,680 required results**.
Full native values total **1,294**. Every previous case remains.

The [Clang evidence](../spec/apple-removal-discovery.json) contains **31 complete
Apple C bodies** for arm64 and x86_64 Darwin. New bodies cover encoding-index,
Windows-codepage and canonical-name lookup, and ICU decoded-length delegation.
All three encoding database tables are retained verbatim from the
[pinned Apple source](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFStringEncodingDatabase.c).
The sizing wrapper comes from
[CFICUConverters.c](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFICUConverters.c).
Historical source explains the interfaces; live captures qualify current
behavior. ICU's [ISO-2022 converter](https://github.com/unicode-org/icu/blob/main/icu4c/source/common/ucnv2022.cpp)
was also reviewed for state-machine context; it is not substituted for native
observations or included as production code.

All existing captures, native controls, thirteen 60-second fuzz targets, full
race suite, strict coverage above 95% for each production package on each OS,
guards, lint and six GoReleaser targets remain required. The native-capture job
runs alongside the three-OS matrix; foreign verification requires both.

## Remaining work

GB18030, other stateful codecs and aliases, Unicode normalization and filesystem
alias matching, remaining OpenStep NUL contexts, wider XML/binary grammar and
metadata normalization remain in the [implementation plan](implementation_plan.md).
This increment does not establish complete plist or codesign parity. Final CI
evidence belongs to the draft PR; the user controls merging.
