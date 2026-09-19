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

## Local reference repositories

The [additional GitHub implementation review](reference-implementations.md)
records pinned Go, Rust, Python, and C++ sources for CMS, bundles, DMGs, and
further Clang AST research, including their known compatibility limits.

The initial review covered `deploymenttheory/go-macos-pkg-1` and `sdk/go-apfs-v2`.
Their useful patterns included separation of CLI and SDK code, subprocess-based
acceptance tests, fixture manifests, and explicit unsupported behavior. The package
project's identity/CMS/timestamp components and the APFS project's UDIF signature
offset/length fields remain references for unfinished certificate and disk-image
work. They have not been introduced as production dependencies.

## Observations encoded in tests

Native signing reserves space based on a longer current CodeDirectory header
even when it emits a shorter version. That reserved space changes the Mach-O load
commands and therefore the page hashes. Universal slice alignment also changes
during native signing. The implementation reproduces these details for the
recorded fixtures rather than comparing only extracted hashes.

Original XML entitlement bytes are preserved on the observed native path. Binary
plist CLI input is rejected. Boolean entitlements can change executable flags;
truth-like strings and integers are not equivalent to boolean true.

Further research must pin source revisions, extract C++ declarations/control
flow where available, record unavailable private dependencies, and add independent
host cases before extending the compatibility claims.
