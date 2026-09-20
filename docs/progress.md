# Project progress

Updated 2026-09-19. This page describes the implementation in this branch and
links its validation evidence. It does not declare a release or full `codesign`
parity. The [compatibility inventory](../spec/compatibility.json) remains the
release gate; the [roadmap](implementation.md) lists the remaining work.

## Delivered milestones

| Milestone | Result | Change |
| --- | --- | --- |
| Mach-O and ad-hoc foundation | Thin/universal parsing, signing, inspection, verification and removal; XML/DER entitlements and a requirements subset | Native fixtures and host comparisons in [testing](testing.md) |
| Certificate signing and policy | RSA/ECDSA CMS, native signature allocation, PEM and authenticated PKCS#12, bounded certificate chains, Team IDs and display metadata | [PR #8, merged](https://github.com/deploymenttheory/go-macos-codesign/pull/8) |
| RFC 3161 core | Token verification, explicit TSA trust, historical certificate validation, signing callbacks and nonce-bound request/response processing | [PR #9, merged](https://github.com/deploymenttheory/go-macos-codesign/pull/9) |
| Online timestamps | Pure-Go HTTP transport, Apple/custom TSA CLI options, pinned Apple roots, deadlines, cancellation and failure preservation | [PR #10, merged](https://github.com/deploymenttheory/go-macos-codesign/pull/10) |
| Basic app bundles | Contents-based APPL signing/removal, XML Info.plist binding, deterministic resource envelopes, metadata display and tamper checks | [Supported profile and native evidence](bundles.md) |
| UDIF disk images | Direct go-apfs-v2 dependency; payload-preserving signatures, canonical trailer binding, native identifiers/display and timestamps | [DMG support and native evidence](dmg-integration.md) |

The third-party repositories are research references. Production does not call
Apple tools, import Apple frameworks, use CGO, or require an SDK/Clang. Certificate
and timestamp handling avoid `crypto/x509`, `crypto/tls` and `net/http`; dependency
guards inspect the full graph for Linux, Darwin and Windows.

## Recorded validation

The DMG phase passes local `make verify` on macOS 27 build 26A428 with 3,093/3,216
library statements (96.18%), 418/420 CLI statements (99.52%) and 1/1 entry-point
statement covered. Forty native byte comparisons, 200 display comparisons,
fifteen signature/image-checksum cases, five committed native fixtures, local TSA
tests, lint and a 30-second DMG fuzz run pass. A live Apple timestamp on the APFS
fixture also passes native strict verification. These are local results; remote
CI must establish the expanded 96-artifact matrix for this implementation.

### App-bundle phase CI

[PR #12 is merged](https://github.com/deploymenttheory/go-macos-codesign/pull/12).
Its [completed workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35469486771)
tested commit `8410d21faf443c3471634fd3525c8153cae31223`. Downloaded artifacts report:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 2,926/3,041 — 96.22% | 406/413 — 98.31% | 1/1 — 100% |
| Windows 2025 | 2,923/3,041 — 96.12% | 406/413 — 98.31% | 1/1 — 100% |
| macOS 27 | 2,926/3,041 — 96.22% | 411/413 — 99.52% | 1/1 — 100% |

All three OS jobs, native strict verification of all **66** foreign artifacts,
six-target GoReleaser packaging, the race detector and all seven fuzz targets
passed. [golangci-lint also passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35469486829).
Native bundle bytes, fifteen display cases and eleven mutation cases matched.

### Online-timestamp phase CI

The [implementation workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35466827806)
ran commit `eb5cc318def53a750a0736d42546b3751bec6266` on real Linux, Windows 2025
and macOS 27 jobs. Its downloaded coverage artifacts report:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 2,533/2,617 — 96.79% | 401/405 — 99.01% | 1/1 — 100% |
| Windows 2025 | 2,533/2,617 — 96.79% | 401/405 — 99.01% | 1/1 — 100% |
| macOS 27 | 2,534/2,617 — 96.83% | 403/405 — 99.51% | 1/1 — 100% |

These are statement-coverage measurements for that commit, not feature-completion
percentages. Every production package must remain above 95%. Future changes need
their own passing run; these measurements are not a claim about an untested commit.

- All three OS jobs passed their unit, CLI acceptance, provenance and dependency checks.
- Native Apple strict verification passed for all **54** files produced by Linux
  and Windows: 27 per OS, including a replayed Apple timestamp.
- The independent local TSA tests ran on each OS and covered all three Mach-O
  forms, authenticated responses, timeout/failure preservation and dry runs.
- GoReleaser built and packaged all six OS/architecture targets with CGO disabled.
- [golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35466827777).
  The Go race detector and all six parser-fuzz targets also passed; the
  implementation workflow completed successfully.

An opt-in local run on macOS 27 also used the compiled production CLI to obtain
fresh Apple timestamps on 2026-09-19 at 20:13:45–20:13:46 UTC. Native
`codesign --verify --strict` accepted the arm64, x86_64 and universal outputs.
This was a live local check, separate from deterministic CI. The command and
attestation output format are documented in [timestamps](timestamps.md).

## What is still incomplete

The initial Contents-based app/resource profile is implemented. Binary bundle
plists, nested code, framework/plugin layouts and symlink/xattr policy are the
next format work. UDIF signing is now implemented for a bounded profile;
large-image streaming, encrypted/segmented images, generic-file and detached
signatures remain open. Further work includes
requirement predicates, CodeDirectory variants, metadata preservation, certificate
and timestamp policy, revocation, and exact CLI diagnostics/localization.

Developer ID recognition is tested with a real public certificate chain; no
Developer ID private key is present, so there is no end-to-end Developer ID signing
or notarized-distribution claim. Live process state, native keychain databases and
non-exportable keys remain portability blockers. See the [full capability matrix](compatibility.md).

## Keeping this page current

For each implementation phase, update the capability documentation, roadmap,
[unreleased changelog](../CHANGELOG.md) and machine-readable compatibility inventory.
Record the tested commit, actual workflow URL, per-package coverage and native
acceptance result after the checks finish. Preserve known gaps instead of marking
an entire native option verified from one passing example.
