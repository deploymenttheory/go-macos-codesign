# Additional GitHub implementation references

Reviewed on 2026-09-19. These supplement the Apple Security, apple-platform-rs,
zsign, ldid, and .NET references in [research.md](research.md).

This is a source and documentation review. The projects below were not built or
run as part of this review. Their interoperability scripts are evidence of test
design, not independently reproduced results. No reviewed project establishes
complete feature or byte-for-byte parity with the installed Apple `codesign`.

## Most useful for certificate signing

### SAS Relic — Go

[Relic](https://github.com/sassoftware/relic/tree/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c)
has separate Mach-O, DMG, signature-blob, PKCS#7, and timestamp components.
Its [signature builder](https://github.com/sassoftware/relic/blob/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/lib/fruit/csblob/sign.go)
and [Apple hash attributes](https://github.com/sassoftware/relic/blob/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/lib/fruit/csblob/attrs.go)
are particularly relevant to detached CMS over CodeDirectories.
The [DMG signer](https://github.com/sassoftware/relic/blob/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/lib/fruit/dmg/sign.go)
also covers UDIF signature placement and trailer updates.

Its [macOS documentation](https://github.com/sassoftware/relic/blob/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/doc/macos.md)
calls support preliminary: fat binaries can be verified but must be signed as
separate thin binaries, and notarization does not include ticket stapling.
This is the strongest additional Go reference for our CMS and later DMG work.

### blacktop/go-macho and blacktop/ipsw — Go

The [go-macho codesign package](https://github.com/blacktop/go-macho/blob/0b3c4a4cb4548a0d1284c1b5fc0de6f4422c0246/pkg/codesign/codesign.go)
parses signature components and assembles signatures, delegating certificate
signing through a `SignerFunction` callback. It is not a complete `codesign` CLI.
The companion [ipsw CMS implementation](https://github.com/blacktop/ipsw/blob/6c4348e321e74d70162d6ff139cb2c76ad2ba2ba/internal/codesign/cms/cms.go)
provides the missing certificate-signing layer, including signed attributes and
Apple hash-agility attributes. Its
[wrapper](https://github.com/blacktop/ipsw/blob/6c4348e321e74d70162d6ff139cb2c76ad2ba2ba/internal/codesign/codesign.go)
includes PKCS#12 loading and optional RFC 3161 timestamps.

These provide useful examples of separating Mach-O layout from cryptographic
signing. They are research inputs rather than proposed wholesale dependencies;
their Go certificate and networking dependencies would need checking against our
requirement to avoid Apple security frameworks.

### jveko/zsign-rs — Rust

[zsign-rs](https://github.com/jveko/zsign-rs/tree/bf2e779108dbb22b7d15b20165aa3e7092269228)
describes itself as a learning port of zsign. Its core uses RustCrypto for
CMS/X.509/PKCS#12 and is designed for WebAssembly. The
[CMS implementation](https://github.com/jveko/zsign-rs/blob/bf2e779108dbb22b7d15b20165aa3e7092269228/crates/zsign-core/src/crypto/cms.rs)
contains RSA and P-256 ECDSA signing, Apple hash-agility attributes, and tests.

Its [Apple interoperability script](https://github.com/jveko/zsign-rs/blob/bf2e779108dbb22b7d15b20165aa3e7092269228/scripts/verify-apple-interop.sh)
is a useful acceptance-test reference: generate a certificate and nested bundle,
sign it, verify with Apple `codesign`, independently verify CMS with OpenSSL,
and check rejection after tampering. Those tools belong to its test harness;
they are not requirements of the portable signing core. We have not executed
this script or independently checked the project's portability claims.

### achow101/signapple — Python

[signapple](https://github.com/achow101/signapple/tree/3fab3bb57f227f0dd31007b417683035f5204838)
is a readable independent implementation of certificate signing, verification,
bundle resources, and notarization. Its
[signing code](https://github.com/achow101/signapple/blob/3fab3bb57f227f0dd31007b417683035f5204838/signapple/sign.py)
is useful for checking CMS attribute encoding against the Go and Rust examples.

Its README explicitly describes a detached-signature format different from
Apple's; source comments also describe differences in generated designated
requirements. Linux operation uses OpenSSL/LibreSSL through its dependencies.
It is a format and behavior reference, not a build or runtime dependency for us.

## Additional C++ and ad-hoc references

| Reference | Useful evidence | Scope and limitations |
| --- | --- | --- |
| [nix-community/sigtool](https://github.com/nix-community/sigtool/tree/25e0b75326d13708e9b744be3ecb984001905dfe) — C++ | Bundle resource sealing, nested-code handling, framework layouts, and entitlement encoding. A useful additional Clang AST input. | Ad-hoc signing only; invokes external `codesign_allocate` and depends on OpenSSL/libplist. It can run outside macOS, but does not meet a pure-Go runtime requirement. |
| [Go linker codesign](https://github.com/golang/go/blob/46f508b3aa365918ac78a63340ce2343306835af/src/cmd/internal/codesign/codesign.go) — Go | Small independent implementation of CodeDirectory serialization, sizing, and page hashing. | Intentionally implements the Go linker's basic ad-hoc use case; no certificate CMS or general CLI parity. |
| [LLVM LLD Mach-O signing](https://github.com/llvm/llvm-project/blob/8fef76f77072537ea9d124df3d95a90671a2c02d/lld/MachO/SyntheticSections.cpp) — C++ | `CodeSignatureSection` shows signature allocation, alignment, CodeDirectory construction, and page hashing. Another useful Clang AST input. | Linker-generated ad-hoc signatures. Apple-specific hashing/cache handling is separate from the portable format logic. |

## Lower-priority findings

[AzozzALFiras/GoSigner](https://github.com/AzozzALFiras/GoSigner/tree/e41d1beccf96a53f7f9cb42590e9ecdcb1101447)
is another Go implementation focused on IPA/iOS signing. Its
[CMS code](https://github.com/AzozzALFiras/GoSigner/blob/e41d1beccf96a53f7f9cb42590e9ecdcb1101447/codesign/cms/signature.go)
and README describe omitting Apple hash-agility attributes for its iOS target,
unlike several references above. That target-specific choice needs independent
macOS testing before it could inform our implementation. Its license file also
adds conditions after an MIT text, so it should not be treated as an ordinary
MIT source for copying.

[Bearer/gon](https://github.com/Bearer/gon) was excluded as an implementation
reference because it orchestrates Apple's signing tools on macOS. Wrappers do
not solve the requirement for a portable signing implementation.

## Application to this project

Relic and ipsw informed the CMS structure and hash-agility comparisons, with
signapple and zsign-rs as independent encoding references. Certificate signing
for thin and universal binaries, native allocation, chain/Team ID policy,
PKCS#12 and RFC 3161 support are now implemented. Relic's transport interface and
ipsw's unsigned-attribute handling also informed the timestamp phase. Evidence
and remaining limits are in [certificates](certificates.md),
[timestamps](timestamps.md) and the [progress report](progress.md).

The first bundle phase now follows Apple's pinned resource rules and compares
native executable/envelope bytes and mutation behavior. The Rust resource-envelope
and C++ sigtool references remain useful for the next nested-code/framework
phase. Binary bundle metadata now adds pinned CoreFoundation AST research and
comparisons with the existing howett.net/plist dependency; a bounded reader
enforces graph-expansion limits before constructing Go values. DMG support now
directly uses go-apfs-v2's format model, with Apple and
Relic informing the signature adapter. Compare native verification and signature
structure; acceptance alone does not prove byte equality or complete CLI parity.

Use sigtool and LLVM as additional C++ inputs for Clang AST research. Keep Apple
Security as the primary behavioral source and record disagreements with the
host version. None of these additional AST analyses has been run yet.

Production remains pure Go. Clang, Apple `codesign`, and other reference tools
are research/acceptance tools only. Build and release packaging remains with
GoReleaser. The initial reference review introduced no production dependencies;
subsequent implementation phases are tracked in the project roadmap.
