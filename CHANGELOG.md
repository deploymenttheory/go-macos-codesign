# Changelog

## Unreleased

The implementation is under development. Full-parity releases remain blocked by
the [compatibility inventory](spec/compatibility.json). The entries below describe
implemented development work, not published versioned releases. See
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
- UDIF DMG signing, inspection and verification through a direct go-apfs-v2
  dependency, with native trailer binding, identifiers, CMS/timestamps and display.
  Native-unsupported DMG removal preserves the input and returns an error.
- Clang AST research with pinned source hashes, native macOS differential
  acceptance, OpenSSL checks and a greater-than-95% coverage gate per package.
- Linux/macOS/Windows CI, race checks, nine fuzz targets, and required native
  verification of 174 Linux/Windows-produced files, app bundles and DMGs,
  including strict deep verification of eighteen apps with plain Mach-O children
  and 36 recursive app trees.
- GoReleaser builds and snapshot packages for six OS/architecture pairs.

### Changed

- Use golangci-lint as the sole code-linting workflow; remove SuperLinter.
- Keep production dependency graphs free of Apple trust bridges, including
  indirect `crypto/x509`, TLS and HTTP imports. Retain attributed, pinned Afero
  and RC2 subsets for portable configuration and legacy PKCS#12 decoding.

### Fixed

- Shallow nested verification now checks Info.plist and signed non-resource
  metadata, including requirement and entitlement hashes, matching native policy.
- Match native canonical Mach-O default identifiers, including ad-hoc UUID and
  UUID-less load-command hash suffixes, against the arm64 baseline.
- Preserve LF/binary fixture bytes across Windows checkouts and retain detailed
  failure transcripts, byte-difference diagnostics and source provenance in CI.
- Match tested native timestamp option exit codes and ad-hoc behavior; preserve
  the input when timestamp acquisition fails, including on a later fat slice.
