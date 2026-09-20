# Project progress

Updated 2026-09-20. This page describes the implementation in this branch and
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
| Binary bundle plists | Bounded metadata graphs, original-byte binding, XML/binary envelope verification and native byte/display comparisons for two encoders | [Bundle profile and evidence](bundles.md) |
| Nested Mach-O code | Helper/dylib requirement seals, staged deep signing, shallow/deep verification and explicit child trust | [Nested profile and native evidence](bundles.md#nested-mach-o-code-and-apps) |
| Recursive APPL apps | Nested .app discovery, mixed XML/binary metadata, descendant-first signing, shared budgets and cross-bundle hard-link checks | [Recursive profile and native evidence](bundles.md) |

The third-party repositories are research references. Production does not call
Apple tools, import Apple frameworks, use CGO, or require an SDK/Clang. Certificate
and timestamp handling avoid `crypto/x509`, `crypto/tls` and `net/http`; dependency
guards inspect the full graph for Linux, Darwin and Windows.

## Recorded validation

The recursive-app phase passes local native comparisons on macOS 27 build 26A428:
24 complete tree byte comparisons, 90 display cases, eighteen ad-hoc/RSA/P-256
trees accepted with strict deep verification, and 26 mutation/depth outcomes.
Three native fixtures each contain three apps and six Mach-O files. Native
lifecycle and shallow metadata-tampering checks also pass. Shared bounds,
cross-bundle hard links, root closure and late construction failures are tested.
An independent local TSA covers all twelve signatures in a universal tree,
child TSA trust and preservation after a later child's timestamp request fails.
Local verification measures 3,553/3,684 library statements (96.44%), 420/422 CLI
statements (99.53%) and 1/1 entry-point statement (100%); golangci-lint passes.
Remote CI must establish this phase's expanded 174-artifact matrix.

### Nested Mach-O phase CI

[PR #15 is merged](https://github.com/deploymenttheory/go-macos-codesign/pull/15).
Its [completed workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35498792947)
tested commit `cb98a387ba1d1631bae103cc92dd267e98c2f795`. Downloaded artifacts report:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,466/3,604 — 96.17% | 414/422 — 98.10% | 1/1 — 100% |
| Windows 2025 | 3,463/3,604 — 96.09% | 414/422 — 98.10% | 1/1 — 100% |
| macOS 27 | 3,472/3,604 — 96.34% | 420/422 — 99.53% | 1/1 — 100% |

All three OS jobs, six-target GoReleaser packaging, race detection and nine fuzz
targets passed. Apple verified all **138** Linux/Windows artifacts, including
**18 nested-Mach-O apps** with strict deep verification and **24 binary-plist
apps**; all **30 DMGs** also passed `hdiutil verify`.
[golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35498792940).
The hosted Mac used build 26A5406e; its exact native byte/display comparisons also
passed despite differing from the local 26A428 baseline.

### Binary-plist phase CI

[PR #14 is merged](https://github.com/deploymenttheory/go-macos-codesign/pull/14).
Its [completed workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35491318218)
tested commit `5e737acee2fa35c4d86b7f8c82f88e734b1f03b7`. Downloaded artifacts report:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,237/3,369 — 96.08% | 412/420 — 98.10% | 1/1 — 100% |
| Windows 2025 | 3,234/3,369 — 95.99% | 412/420 — 98.10% | 1/1 — 100% |
| macOS 27 | 3,246/3,369 — 96.35% | 418/420 — 99.52% | 1/1 — 100% |

All three OS jobs, six-target GoReleaser packaging, race detection and eight fuzz
targets passed. Apple verified all **120** Linux/Windows artifacts, including
**24 binary-plist apps**; all **30 DMGs** also passed `hdiutil verify`.
[golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35491318128).
Six exact binary signatures/envelopes, thirty display cases, twelve native strict
checks, four metadata mutations, three native fixtures and a binary-envelope case
passed. The binary reader had 100% unit statement coverage.

### DMG phase CI

[PR #13 is merged](https://github.com/deploymenttheory/go-macos-codesign/pull/13).
Its [completed workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35471292982)
tested commit `d51f6a863c0c0d385094e94675d258cf4bfe2bdd`. Downloaded artifacts report:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,084/3,216 — 95.90% | 412/420 — 98.10% | 1/1 — 100% |
| Windows 2025 | 3,081/3,216 — 95.80% | 412/420 — 98.10% | 1/1 — 100% |
| macOS 27 | 3,093/3,216 — 96.18% | 418/420 — 99.52% | 1/1 — 100% |

All three OS jobs, six-target GoReleaser packaging, race detection and all eight
fuzz targets passed. Native strict verification accepted all **96** artifacts;
all **30 DMGs** also passed `hdiutil verify`.
[golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35471292983).
Forty native byte comparisons, 200 display comparisons, fifteen signature/image
checks, five committed fixtures and local TSA tests passed. A separate live Apple
timestamp on the APFS fixture passed native strict verification at 2026-09-19
21:31:11 UTC.

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

The Contents-based app/resource profile includes XML and bounded binary bundle
plists, plain nested Mach-O helpers/dylibs and recursive Contents-based APPL apps.
Framework/plugin/XPC bundle layouts and symlink/xattr policy are the next format
work. UDIF signing is implemented for a bounded profile;
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
