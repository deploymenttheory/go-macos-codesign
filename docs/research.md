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
