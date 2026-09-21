# Research and provenance

## Clang AST extraction

`scripts/extract-sdk.py` invokes Clang against the SDK's `kern/cs_blobs.h` using
both `arm64-apple-macos27` and `x86_64-apple-macos27` targets. It records:

- Explicit enum values from `-Xclang -ast-dump=json`.
- `CS_` macros from `-E -dM`.
- Field declarations and `-Xclang -fdump-record-layouts-complete` output.
- Compiler version, SDK name, source-header SHA-256, and target triples.

Run `make research` on a development Mac, or pass an SDK explicitly:

```sh
python3 scripts/extract-sdk.py --sdk /path/to/MacOSX.sdk --output artifacts/apple-sdk.json
```

The committed result is `spec/apple-sdk.json`. It is factual research input;
production Go builds do not run Clang or open an SDK. Serialized formats use
explicit byte offsets and big-endian encoding. C alignment is not a wire format:
the modern CodeDirectory fields end at byte 108 while the C structure has size
112. The writer selects the actual version-specific header length.

This extractor analyzes SDK declarations. It does **not** decompile the installed
`/usr/bin/codesign`, and the full Apple C++ implementation has not yet been
translated through an AST pipeline. Public source analysis and differential
testing supply the behavioral evidence for the implemented subset.

[Clang's AST documentation](https://clang.llvm.org/docs/IntroductionToTheClangAST.html)
describes the source-level representation used for extraction.

### Certificate-phase extraction

`scripts/extract-cms.py` adds `spec/apple-cms.json`: Clang AST declarations from
the SDK's CMSEncoder/CMSDecoder headers, plus the verbatim `ExprOp` and
`MatchOperation` enum excerpts from the pinned Apple `requirement.h`. It records
both targets, function types, enum values, source/header hashes, and the compiler.
The C++ excerpts compile independently; this is not a claim that Apple's full
private implementation or control flow has been compiled or translated.

To reproduce after downloading the pinned source:

```sh
mkdir -p .research/apple
gh api 'repos/apple-oss-distributions/Security/contents/OSX/libsecurity_codesigning/lib/requirement.h?ref=db15acbe6a7f257a859ad9a3bb86097bfe0679d9' \
  -H 'Accept: application/vnd.github.raw+json' > .research/apple/requirement.h
make research-cms
```

The CMS implementation uses the detached content and signed-attribute rules in
[RFC 5652](https://www.rfc-editor.org/rfc/rfc5652), alongside the pinned Relic,
ipsw, signapple, and zsign-rs references. The SEC1 key parser follows
[RFC 5915](https://www.rfc-editor.org/rfc/rfc5915). Native verification and an
independent OpenSSL CMS verifier check the resulting encodings in acceptance.

### Signature layout and CMS encoding

`scripts/extract-signature.py` compiles the pinned `CodeSigner.cpp` default-budget
assignment and the complete `SuperBlobCore::Maker::size` method body through Clang
for both target architectures. Surrounding type declarations are explicit shims;
the method body and assignment are verbatim. `spec/apple-signature.json` records
the extracted 18,000-byte CMS budget, method type, AST node counts/operators, and
source/excerpt/translation-unit hashes. This is source-level AST research, not a
claim to have compiled the full private Apple implementation or inferred wire
layout from the shim types.

Download `CodeSigner.cpp`, `superblob.h`, and `cmsasn1.c` from the pinned URLs in
that record into `.research/apple`, then run `make research-signature`.
The CMS template source declares streamable outer containers while its signer
records remain definite-length. Native outputs establish the observed BER form,
SHA-256 parameters, and CoreFoundation hash-agility XML formatting. Those bytes
are checked by RSA comparisons at identical signing times and by authenticated
metadata comparisons for ECDSA. Native fixtures and the 64-case host matrix cover
allocation alignment; the AST method itself is not an executed native oracle.

## Primary implementation references

### Mach-O deallocation

`make research-removal` runs the Go driver `scripts/extract-removal.go`. It parses
the complete verbatim `get32`, `get64`, `remove_signature_space` and
`code_sign_deallocate` bodies from pinned Apple Security
[codesign_alloc.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/codesign_alloc.cpp).
Download that file to `.research/apple/codesign_alloc.cpp` before reproduction.
The [AST record](../spec/apple-removal.json) pins both targets, source/excerpt/SDK
header hashes and the translation unit. SDK Mach-O, endian and overflow declarations
are real; logging, file I/O and VM wrapper interfaces are declaration-only shims.
The full source requires a private `os/cleanup.h`; the driver does not claim a
complete Security build or execute Apple code.

Independent native probes confirm the 12-byte symbol-table padding bound,
7-byte trailing allowance, unchanged LINKEDIT virtual size and 16 KiB universal
alignment. The [native corpus and acceptance](removal.md) establish exact bytes
for the tested profile. Observed malformed-table and reordered-command native
corruption is not reproduced by the portable implementation.

### Certificate chains, Team IDs and PKCS#12

`make research-certificates` analyzes the complete verbatim macOS Team ID method
from `CodeSigner.cpp`, the organization anchor method from `drmaker.cpp`, and
developer requirement constants from `StaticCode.cpp`. Two-target Clang AST
counts, extracted constants and source/excerpt hashes are in
`spec/apple-certificates.json`. Type shims support parsing; they do not execute
Apple trust services or establish private-framework behavior.

Portable chain constraints follow the implemented subset of
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280). PKCS#12 follows
[RFC 7292](https://www.rfc-editor.org/rfc/rfc7292) and was compared with
[SSLMate/go-pkcs12](https://github.com/SSLMate/go-pkcs12). That package was not
added as a dependency because it imports `crypto/x509`; the parser here always
requires authenticated PFX contents. Only the unmodified Go `x/crypto` RC2
primitive is retained as an attributed dependency for legacy imports.
[Apple's published roots](https://www.apple.com/certificateauthority/) pin
developer recognition independently of caller trust. See fixture manifests for
public certificate, OpenSSL version and password provenance.

| Source | Use in this project |
| --- | --- |
| [Apple Security, pinned revision](https://github.com/apple-oss-distributions/Security/tree/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib) | CodeDirectory versions, allocation, requirement opcodes, entitlement flags, disk representations, and identification of native-service dependencies |
| [Rust apple-codesign](https://github.com/indygreg/apple-platform-rs/tree/0ebbd2ef3b96d5adccc30b1cad4deea38cd735c4/apple-codesign) | Portable signing architecture, CMS/requirements/resource-envelope research, and documented compatibility limits |
| [C++ zsign](https://github.com/zhlynn/zsign) | Cross-platform Mach-O and entitlement encoding approaches |
| [C++ ldid](https://github.com/ProcursusTeam/ldid) | Behavioral comparison and feature discovery; no implementation code copied |
| [.NET MachObjectFile](https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/MachO/MachObjectFile.cs) | Independent ad-hoc Mach-O allocation/signing implementation |

These sources are research references, not runtime dependencies. Public Apple
source may lag the installed macOS version. Host observations therefore take
precedence when a versioned discrepancy is found. No claim is made that an older
source revision describes every macOS 27 feature.

## Timestamp research

Timestamp research uses [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) and
[RFC 5816](https://www.rfc-editor.org/rfc/rfc5816), alongside Apple's pinned
`tsaTemplates.h` and `tsaSupport.c`. `make research-timestamps` runs a Go research
driver that invokes Clang for arm64 and x86_64 and records enum values, carrier
fields and `verifyTSTInfo` AST node kinds in `spec/apple-timestamps.json`.
The declarations and full function body are verbatim excerpts; supporting
types, function declarations and control-flow macros are explicit shims.
This does not compile Apple's full Security library or execute its policy.

The same Go research target extracts Objective-C AST facts for the complete
`initWithURLString:` and `post:` methods in pinned `timestampclient.m` and reads
the corresponding `OSX/lib/TimeStampingPrefs.plist`. The two-target result in
`spec/apple-timestamp-http.json` records the 15-second timeout, POST method,
request content type and default Apple endpoint. HTTP framing follows a bounded
profile of [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html). Live acceptance
uses the production Go CLI and native `codesign --verify --strict`; it is opt-in.

The pinned [Relic timestamper](https://github.com/sassoftware/relic/blob/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/internal/signinit/timestamper.go)
supplied a transport-interface comparison, while
[ipsw AddTimestamps](https://github.com/blacktop/ipsw/blob/6c4348e321e74d70162d6ff139cb2c76ad2ba2ba/internal/codesign/cms/cms.go)
provided an unsigned-attribute attachment comparison. Neither is a dependency
or a substitute for native acceptance. The recorded Apple TSA response uses
SHA-1 CMS; that compatibility path is verified while new requests use SHA-256
imprints. See [timestamp evidence and limits](timestamps.md).

The [additional GitHub implementation review](reference-implementations.md)
records pinned Go, Rust, Python, and C++ sources for CMS, bundles, DMGs, and
further Clang AST research, including their known compatibility limits.

## Bundle research

`make research-bundles` runs `scripts/extract-bundles.go`, which parses the full
verbatim `BundleDiskRep::defaultResourceRules` and `ResourceBuilder::hashName`
methods and the resource-flag enum from pinned Apple Security sources through
Clang on both target architectures. [spec/apple-bundles.json](../spec/apple-bundles.json)
records source/excerpt/translation-unit hashes, string literals, enum values and
AST node kinds. Interface/type/signing-flag shims are explicit; this is not a
compilation or execution of Apple's full bundle loader.

To reproduce, download `bundlediskrep.cpp`, `resources.cpp` and `resources.h`
from the pinned URLs in that record into `.research/apple`, then run
`make research-bundles`. The source records the rule weights and localization
exceptions. Native comparisons independently establish exact XML formatting,
Info.plist/resource binding, display counts, and addition/removal/tamper behavior
for the [supported app profile](bundles.md). Go code never invokes Clang or
CoreFoundation to load or seal a bundle.

The target also runs `scripts/extract-bundle-plists.go`, using pinned
[CoreFoundation binary-plist source](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBinaryPList.c).
It extracts the complete trailer/marker declarations, `_getSizedInt`,
`__CFBinaryPlistGetTopLevelInfo`, `_readInt`, and Security's `component` and
`getDictionary` methods. [spec/apple-bundle-plists.json](../spec/apple-bundle-plists.json)
records both targets, trailer size/offsets, marker values, method ASTs and hashes.
Explicit interface/endian/arithmetic shims support parsing; the driver does not
execute CoreFoundation or derive its full parsing policy. Download CFBinaryPList.c,
ForFoundationOnly.h, bundlediskrep.cpp and StaticCode.cpp from the recorded URLs
into `.research/apple` before running it.

The existing [howett.net/plist decoder](https://github.com/DHowett/go-plist/blob/v1.0.1/bplist_parser.go)
was reviewed for binary object and integer semantics. Production retains it for
XML; binary bundle metadata uses a bounded reader because generic graph expansion
has no depth/value/byte budget. Native `plutil` fixtures and independent Go-encoded
inputs establish the implemented subset. Source research and these comparisons
do not establish malformed-input acceptance parity outside the documented bounds.

## Nested-code research

The bundle target also runs `scripts/extract-nested.go`. The resulting
[nested AST record](../spec/apple-nested.json) parses five complete verbatim
methods: `signNested`, `SecCodeSigner::sign`, `validateNestedCode`,
`identificationFor` and `uniqueName`. These establish source control flow for
child signing, preserve/linker-signature behavior, requirement sealing, shallow
versus deep validation, and UUID/hash identifier suffixes. Interface, flag,
error and logging shims are explicit; their placeholder constants are not
extracted native values. Download signer.cpp, CodeSigner.cpp, StaticCode.cpp
and machorep.cpp from the recorded pinned Security URLs before reproducing it.

The native requirement text follows pinned
[reqdumper.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/reqdumper.cpp)
and RequirementKeywords.h. Independent Apple dumper comparisons check the
implemented subset. The pinned
[sigtool resource builder](https://github.com/nix-community/sigtool/blob/25e0b75326d13708e9b744be3ecb984001905dfe/resources.cpp)
provides a second reference for excluding nested code from legacy hashes and
emitting CDHash/requirement seals; its ad-hoc logic does not replace Apple's
certificate designated requirements or native architecture-selection evidence.
Neither source becomes a production dependency.

The same target runs `scripts/extract-nested-apps.go`, recording complete native
`ResourceBuilder::scan(Scanner, Scanner)`, `findStringEndingNoCase` and
`SecStaticCode::validateNonResourceComponents` bodies on both architectures in
[spec/apple-nested-apps.json](../spec/apple-nested-apps.json). The scanner stops
ordinary resource traversal at nested directory boundaries; shallow verification
loads and checks signed non-resource metadata, including Info.plist. SDK FTS
declarations support parsing; interface/error/slot/logging shims remain explicit.
Download resources.cpp, resources.h and StaticCode.cpp from the pinned record
before reproducing it. Native probes and acceptance independently establish
recursive ordering, preservation, mixed metadata and mutation behavior. This
phase narrowed directory discovery to Contents-based APPL `.app` children under
the supported code roots; it does not claim every native bundle representation.

The layout phase adds `scripts/extract-bundle-layouts.go` and
[spec/apple-bundle-layouts.json](../spec/apple-bundle-layouts.json). It parses complete
verbatim `DiskRep::bestGuess(const char*, const Context*)`, `BundleDiskRep::setup`,
`BundleDiskRep::checkMoved`, `BundleDiskRep::validateFrameworkRoot`,
`SecStaticCode::validateOtherVersions`,
`SecStaticCode::validateSymlinkResource`, `BundleDiskRep::Writer::remove()` and
`BundleDiskRep::Writer::purgeMetaDirectory` bodies for arm64 and x86_64, including
the framework validator's C++ block. SDK filesystem declarations are real;
CoreFoundation/disk-representation/validation/writer interfaces and error/flag/slot constants are explicit shims.
The record pins sources, excerpts, compiler and translation unit. Download
bundlediskrep.cpp, StaticCode.cpp and diskrep.cpp from its pinned URLs before reproducing it.

Apple's [framework anatomy](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFrameworks/Concepts/FrameworkAnatomy.html)
and [bundle placement guidance](https://developer.apple.com/documentation/bundleresources/placing-content-in-a-bundle)
explain the version and alias structure. The pinned sigtool resource builder is
an independent reference for paths, nested binaries and symlink text seals.
Native probes settle the actual Info.plist location, duplicated framework metadata
sealing, display paths and relative-link behavior. Eighteen native tar fixtures
and standalone/mixed-tree acceptance independently check the Go implementation.
The version extension parses the complete setup and alternate-version methods.
Setup selects `Context.version` or Current; Contents layouts take precedence.
Alternate validation enumerates physical directories, skips the selected canonical
path, and applies the same parent requirement to each remaining version. The
previous nested-code AST records its strict-flag call site. Host CLI probes show
that default parent verification also reaches this check on macOS 27; shallow
checks omit alternate pages/resources, while deep checks include them. Standalone
framework validation visits only the selected version. Three additional native
archives, selected-version byte/display/removal comparisons and mutations prove
these distinctions independently of the shimmed AST. Absolute/outer-scope
resource links remain outside the bounded profile.

The direct-directory extension adds the complete `DiskRep::bestGuess` body.
Its directory branch constructs a BundleDiskRep at that directory; setup only
arbitrates versions beneath its own bundle root. Host tests independently show
that a direct `Versions/A` remains valid despite malformed outer aliases or
sibling metadata, and rejects an additional bundle-version selector. A direct
Current directory input resolves to its physical target for display. Eighteen
signing/removal comparisons, ninety display cases and 64 failed-selector checks
exercise that behavior. The AST also exposes native executable-path promotion.
Its CoreFoundation call is expanded by `scripts/extract-bundle-discovery.go` and
[the discovery AST record](../spec/apple-bundle-discovery.json): five complete
functions from Apple's pinned CF revision
`dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3`, parsed with actual SDK CoreFoundation
declarations on both targets. Download `CFBundle.c` from the recorded URL into
`.research/apple/CFBundle.c` before running `make research-bundles`.

The functions derive a bundle URL, compare the executable path exactly and require
metadata for flat candidates. Private helpers, executable lookup, effective
layout version and buffer bounds remain explicit shims. This does not execute
CoreFoundation or claim complete CFBundle discovery. Host probes and acceptance
separately establish supported Contents/framework behavior, physical file-alias
resolution, helper boundaries and option interactions. Hard links do not select
a bundle merely by sharing its main executable's inode. Independent
[writer research and native tests](file-writes.md) establish standalone hard-link
replacement separately from these discovery tests.

## Writer and native-option research

`make research-writer` now extracts nine complete methods on both targets: the
MachOEditor commit/destructor and BundleDiskRep metadata-path, directory-creation,
component-write, remove overloads, flush and stale-file purge methods. The
[record](../spec/apple-writer.json) pins verbatim excerpts and SDK headers. Real
SDK open/copyfile constants establish in-place envelope writes and metadata copy;
private interface/slot/error shims do not establish wire values. Native tests
independently establish bundle executable replacement, envelope inode retention
and unlink-on-removal. Regular stale-file cleanup is delivered in PR #30.

The directory-stat follow-up also parses the complete `copyfile_stat` function
and its internal flag enum from copyfile revision
`9f91eb6ced021952278816cdc76ad68da8631ccb`. The private header supplies omit/preserve
masks; SDK declarations supply the actual BSD, mode and copyfile flag values.
The private state carrier and two helper interfaces are declaration-only shims.
The native directory matrix confirms physical framework-version selection and
records the remaining explicit-source-ACL difference. APFS tests independently
execute `copyfile(COPYFILE_STAT)` as a test-only metadata oracle.

To refresh the additional research inputs before `make research-writer`:

```sh
curl -fsSL https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c -o .research/apple/copyfile.c
curl -fsSL https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile_private.h -o .research/apple/copyfile_private.h
```

`make research-inventory` records the installed binary/manual identity and probes
79 recognized switches, including 32 absent from the manual. It also retains ten
rejected binary-string candidates. Each option has seven operation cells with
raw command/status/output and before/after hashes or an explicit unavailable
context. The pinned open-source revision does not supply the current parser;
[the inventory guide](native-inventory.md) explains provenance and why recognition
does not establish feature semantics or full equivalence.

## DMG research and direct library reuse

`make research-dmg` runs `scripts/extract-dmg.go` against pinned Apple
`diskimagerep.cpp` and `diskrep.cpp`. It extracts complete trailer-reading/setup,
signing-limit, signature-writing and canonical-identifier methods through Clang
for both targets. [spec/apple-dmg.json](../spec/apple-dmg.json) records method
ASTs, source/excerpt hashes and explicit header/interface shims. Those shims do
not establish UDIF wire offsets; production uses go-apfs-v2's `disk.DMGFooter`.
Download the two sources from the URLs in that record into `.research/apple`
before reproducing the extraction.

Native comparisons establish canonical trailer hashing with a blinded signature
length, unpaged hashing, exact signature framing and unsupported image removal.
Relic's pinned [DMG signer](https://github.com/sassoftware/relic/blob/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/lib/fruit/dmg/sign.go)
is an independent signature-adapter reference. It is not a dependency or the
source of another UDIF representation here. [DMG support](dmg-integration.md)
records the APFS dependency and an isolated unsigned LZMA encoder observation.

## Local reference repositories

The initial review covered `deploymenttheory/go-macos-pkg-1` and `sdk/go-apfs-v2`.
Their useful patterns included separation of CLI and SDK code, subprocess-based
acceptance tests, fixture manifests, and explicit unsupported behavior. The package
project's identity/CMS/timestamp components and the APFS project's UDIF signature
offset/length fields informed the implemented certificate/timestamp work and
remain useful for the disk-image phase. `go-apfs-v2` is now the direct DMG
dependency. Its `pkg/disk` exposes
`DMGFooter` with code-signature fields, `EncodeUDIF` and streaming raw-image
wrapping. The reviewed local revision and dependency audit are recorded in the
[DMG support guide](dmg-integration.md). Production imports the format model;
acceptance also uses its encoder and existing native APFS/HFS+ fixtures.

## Observations encoded in tests

### Standalone path resolution

`make research-paths` extracts five complete functions into
[spec/apple-paths.json](../spec/apple-paths.json). Apple's CLI
[`cleanPath` and `staticCodePath`](https://github.com/apple-oss-distributions/security_systemkeychain/blob/2b4c65b1074521e9c1dd2c8dc7fbf45dd775ec70/src/cs_utils.cpp)
call `realpath` before creating the static code object. Three
[`SingleDiskRep` methods](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/singlediskrep.cpp)
use its stored path for canonical/executable paths and the recommended identifier.
Download the pinned `cs_utils.cpp` and `singlediskrep.cpp` to `.research/apple`
before reproduction. The driver uses real SDK CoreFoundation/Security and libc
declarations, with explicit private interface shims. It records complete excerpt
and source hashes and both target ASTs; it does not execute Apple source.

Independent host tests establish physical-path selection, default identifiers,
unchanged aliases, `link/..` behavior and exact display output. They also exposed
retained old signature bytes after a shorter replacement SuperBlob. The pinned
[`codesign_alloc.cpp`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/codesign_alloc.cpp)
copies input slices before resizing, and `MachOEditor::write` writes only the new
blob. This allocation observation is source inspection plus nine native byte
comparisons; the path AST record does not claim to analyze the allocator.

### Signature encoding

Native signing reserves space based on a longer current CodeDirectory header
even when it emits a shorter version. That reserved space changes the Mach-O load
commands and therefore the page hashes. Universal slice alignment also changes
during native signing. The implementation reproduces these details for the
recorded fixtures rather than comparing only extracted hashes.

Original XML entitlement bytes are preserved on the observed native path. Binary
plist entitlement input is rejected by the CLI; binary bundle metadata is supported.
Boolean entitlements can change executable flags;
truth-like strings and integers are not equivalent to boolean true.

Further research must pin source revisions, extract C++ declarations/control
flow where available, record unavailable private dependencies, and add independent
host cases before extending the compatibility claims.
