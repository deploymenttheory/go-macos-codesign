# Changelog

## Unreleased

- Support multiple physical framework versions and `--bundle-version` selection
  for signing, inspection, verification and removal, with matching path APIs.
- Validate every nested framework version against the parent's requirement,
  including code pages, resources and descendants during deep verification.
- Preserve unselected versions, reject cross-version hard-linked write targets,
  and share traversal budgets across physical versions.
- Add native byte/display/removal comparisons, alternate-version mutations,
  three native fixtures, two complete Apple methods in the Clang AST record,
  and eighteen additional Linux/Windows trees for native CI verification.

## 0.1.0 (2026-09-20)


### Features

* add native CMS parity, certificate policy and PKCS12 identities ([d095e99](https://github.com/deploymenttheory/go-macos-codesign/commit/d095e994fdc8a9474cfec76ddf8ac91a2a1453fd))
* add portable app bundle resource sealing ([b6f05a7](https://github.com/deploymenttheory/go-macos-codesign/commit/b6f05a7f0024ba12e9486c6693418af5d4c662a0))
* add portable app bundle resource sealing ([1657c88](https://github.com/deploymenttheory/go-macos-codesign/commit/1657c88a8299b81d64e59789a4fffb4af1f50ba1))
* add portable Mach-O signing and certificate CMS ([7ef598a](https://github.com/deploymenttheory/go-macos-codesign/commit/7ef598a072fdcc49b7d5617d8c1b6a2aca1fd6ae))
* add portable RFC 3161 timestamp verification and signing callbacks ([3eaae1c](https://github.com/deploymenttheory/go-macos-codesign/commit/3eaae1c195151e1e7b35693ddfe0d1ab0267f2fc))
* add pure Go online timestamp acquisition ([666ea7e](https://github.com/deploymenttheory/go-macos-codesign/commit/666ea7ef88c9341667d5d26892dbd03710fce3f2))
* add pure Go online timestamp acquisition ([eb5cc31](https://github.com/deploymenttheory/go-macos-codesign/commit/eb5cc318def53a750a0736d42546b3751bec6266))
* add RFC 3161 timestamp verification and signing callbacks ([368c19a](https://github.com/deploymenttheory/go-macos-codesign/commit/368c19a11ee9969a6f8a7ffc3e219d063730427c))
* implement portable Mach-O code signing ([5058e89](https://github.com/deploymenttheory/go-macos-codesign/commit/5058e89e8b902fd3c782bfd7e8d4e21ea70ef7de))
* match native certificate signature allocation and CMS encoding ([933c944](https://github.com/deploymenttheory/go-macos-codesign/commit/933c944924bc741faf1b614e615169822ad198a7))
* recursively sign and verify nested APPL bundles ([cdd63de](https://github.com/deploymenttheory/go-macos-codesign/commit/cdd63defd65dc022cff206101476934b9536af1d))
* recursively sign and verify nested APPL bundles ([603922b](https://github.com/deploymenttheory/go-macos-codesign/commit/603922b77ea11fe0637b4e99c68eb260c7c9ea26))
* seal and deeply verify nested Mach-O code ([cb98a38](https://github.com/deploymenttheory/go-macos-codesign/commit/cb98a387ba1d1631bae103cc92dd267e98c2f795))
* seal and deeply verify nested Mach-O helpers and dylibs ([3318948](https://github.com/deploymenttheory/go-macos-codesign/commit/33189485d0b563a017f53a39b21b83f4ec07de93))
* sign UDIF disk images using go-apfs-v2 ([0768132](https://github.com/deploymenttheory/go-macos-codesign/commit/07681324f5f91c64fff776fb5edb5557070805f9))
* sign UDIF disk images using go-apfs-v2 ([4d8a96f](https://github.com/deploymenttheory/go-macos-codesign/commit/4d8a96f02cf865dbb9df3f2ff5eb49c7a3debe29))
* support bounded binary bundle plists ([8bed5a0](https://github.com/deploymenttheory/go-macos-codesign/commit/8bed5a097efedea624ee943f4cffd39b06edc7ba))
* support bounded binary bundle plists ([5e737ac](https://github.com/deploymenttheory/go-macos-codesign/commit/5e737acee2fa35c4d86b7f8c82f88e734b1f03b7))
* support plug-ins, XPC and framework bundle layouts ([63fd691](https://github.com/deploymenttheory/go-macos-codesign/commit/63fd691f22d65d92a8aae8825b10677224d40c1d))
* support plug-ins, XPC and framework bundle layouts ([116e41d](https://github.com/deploymenttheory/go-macos-codesign/commit/116e41de55c8c2f5b12dc8dffd68109f18981b65))


### Bug Fixes

* match native removal and repair release automation ([0e2f03b](https://github.com/deploymenttheory/go-macos-codesign/commit/0e2f03b8c7b5b4fad95e085ae55fe51dde43fbc0))
* match native removal and repair release automation ([0acb051](https://github.com/deploymenttheory/go-macos-codesign/commit/0acb051e08dbd340dfd73fe214e3780bb0fe7d95))
* preserve entitlement fixture bytes on Windows ([4fd6abe](https://github.com/deploymenttheory/go-macos-codesign/commit/4fd6abe8eed380c9554133ec74774a9f03e5190a))
* preserve native format detection precedence ([d51f6a8](https://github.com/deploymenttheory/go-macos-codesign/commit/d51f6a863c0c0d385094e94675d258cf4bfe2bdd))

## Changelog

## Development record through 0.1.0

The implementation is under development. Full-parity claims remain blocked by
the [compatibility inventory](spec/compatibility.json); versioned releases describe
the supported subset. The entries below describe the development milestones
included in 0.1.0. See
[project progress](docs/progress.md) for milestones and measured validation.

### Added

- Pure-Go Mach-O library and Cobra/Viper CLI for signing, inspecting, verifying
  and removing embedded signatures on Linux, macOS and Windows.
- Ad-hoc signing for arm64, x86_64 and universal files; XML/DER entitlements,
  selected CodeDirectory options and a requirements compiler/evaluator subset.
- RSA and ECDSA P-256/P-384/P-521 CMS signing, Apple hash-agility attributes,
  native allocation/BER compatibility and unencrypted PEM identities.
- Bounded certificate-chain policy, explicit leaf pins/CA roots, recognized
  Apple Team IDs, authority/signing metadata and authenticated PKCS#12 import.
- RFC 3161 token verification, separate TSA trust, historical certificate
  validation, library signing callbacks and nonce-bound SHA-256 exchanges.
- Online CLI timestamps through Apple's HTTP TSA or a custom HTTP endpoint,
  bundled public Apple roots, request deadlines and cancellation.
- Contents-based APPL bundle signing, inspection, verification and removal;
  deterministic CodeResources, Info.plist binding, localization rules and
  resource tamper detection, with explicit layout/path/size limits.
- Binary Info.plist support with original-byte preservation, bounded object
  graphs, duplicate/cycle rejection, native fixtures and two-encoder acceptance;
  verification of binary CodeResources under the existing resource rules.
- Nested Mach-O helper/dylib requirement seals, `--deep` signing/verification,
  native preserve/force/dry-run behavior, explicit child trust and staged writes.
  Includes real native dylib fixtures, five-method Clang AST research and exact
  ad-hoc executable/envelope comparisons on all supported architectures.
- Recursive Contents-based APPL .app children with mixed XML/binary metadata,
  staged descendant-first signing, shared traversal/output budgets, cross-bundle
  hard-link checks and native shallow/deep verification semantics.
- Contents-based BNDL plug-ins and XPC! services/extensions, unversioned and
  single-version FMWK frameworks, canonical framework aliases and bounded relative
  resource symlink sealing. Includes real MH_BUNDLE fixtures, eighteen native
  archives, five-method Clang AST research and mixed-layout acceptance.
- UDIF DMG signing, inspection and verification through a direct go-apfs-v2
  dependency, with native trailer binding, identifiers, CMS/timestamps and display.
  Native-unsupported DMG removal preserves the input and returns an error.
- Clang AST research with pinned source hashes, native macOS differential
  acceptance, OpenSSL checks and a greater-than-95% coverage gate per package.
- Linux/macOS/Windows CI, race checks, nine fuzz targets, and required native
  verification of 300 Linux/Windows-produced files, bundles and DMGs,
  including strict deep verification of eighteen apps with plain Mach-O children
  and 36 recursive app trees, plus 126 archives preserving bundle-layout symlinks.
- GoReleaser builds and snapshot packages for six OS/architecture pairs.
- Forty-four native removal fixtures, two-target deallocator Clang AST evidence,
  complete bundle-removal byte comparisons and 88 foreign-output CI comparisons.
- SPDX SBOMs per archive and keyless Cosign signatures over release checksums.

### Changed

- Use golangci-lint as the sole code-linting workflow; remove SuperLinter.
- Follow the go-macos-pkg release pattern: Release Please uses the organization
  App with explicit PAT fallback and owns tags/changelog/releases; GoReleaser
  appends artifacts. Keep the full-parity audit separate from publishing the
  documented subset, and exercise snapshot SBOMs in CI.
- Keep production dependency graphs free of Apple trust bridges, including
  indirect `crypto/x509`, TLS and HTTP imports. Retain attributed, pinned Afero
  and RC2 subsets for portable configuration and legacy PKCS#12 decoding.

### Fixed

- Match native symbol-table padding removal, preserve LINKEDIT virtual sizes,
  normalize universal alignment and accept up to seven post-signature bytes.
  Reject malformed table ranges without mutation. Bundle removal preserves empty
  signature directories and now matches complete native bytes in the tested corpus.
- Shallow nested verification now checks Info.plist and signed non-resource
  metadata, including requirement and entitlement hashes, matching native policy.
- Match native canonical Mach-O default identifiers, including ad-hoc UUID and
  UUID-less load-command hash suffixes, against the arm64 baseline.
- Preserve LF/binary fixture bytes across Windows checkouts and retain detailed
  failure transcripts, byte-difference diagnostics and source provenance in CI.
- Match tested native timestamp option exit codes and ad-hoc behavior; preserve
  the input when timestamp acquisition fails, including on a later fat slice.
