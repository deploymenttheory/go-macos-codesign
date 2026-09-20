# Project progress

Updated 2026-09-20. This page describes the implementation in this branch and
links its validation evidence. It does not declare a release or full `codesign`
parity. The [compatibility inventory](../spec/compatibility.json) remains the
full-equivalence audit; the [roadmap](implementation.md) lists the remaining work.
Versioned releases of the supported subset use [Release Please and GoReleaser](releases.md).

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
| Plug-ins, XPC and frameworks | BNDL/XPC! Contents layouts, unversioned/single-version FMWK layouts, validated framework aliases and relative symlink seals | [Layout profiles and evidence](bundles.md#frameworks) |
| Multiple framework versions | Explicit version selection, isolated writes/removal, alternate-version requirement checks, shared limits and native fixtures | [Framework version behavior and limits](bundles.md#frameworks) |
| Native removal bytes | Symbol-table padding, virtual-size preservation and universal alignment; safe malformed-input rejection | [Removal evidence and remaining limits](removal.md) |
| Release automation | App-token/PAT Release Please flow and GoReleaser append releases, SPDX SBOMs and signed checksums | [Workflow and configuration](releases.md) |

The third-party repositories are research references. Production does not call
Apple tools, import Apple frameworks, use CGO, or require an SDK/Clang. Certificate
and timestamp handling avoid `crypto/x509`, `crypto/tls` and `net/http`; dependency
guards inspect the full graph for Linux, Darwin and Windows.

## Recorded validation

The removal phase passes local native comparisons on macOS 27 build 26A428:
44 standalone cases, eighteen complete bundle layouts, three mixed trees and
nine re-signing comparisons with strict native verification. The earlier
eight-byte executable padding exception is removed. Four complete deallocator
functions have two-target Clang AST records. Unit tests bound malformed symbol
ranges and check endian/32-bit layouts, command relocation and failure preservation.
The [completed PR #18 workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35511644634)
tested commit `0acb051e08dbd340dfd73fe214e3780bb0fe7d95`. Its Linux, Windows and
macOS library coverage was 3,713/3,857 (96.27%), 3,710/3,857 (96.19%) and
3,719/3,857 (96.42%) respectively. CLI coverage exceeded 98% and entry-point
coverage was 100% on every OS. All 300 signed imports and 88 removal comparisons
passed, together with packaging, race detection and nine fuzz targets.
[golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35511644632).
All 543 source/fixture hashes per OS were audited against that checkout; only
seventeen expected Windows text line-ending conversions differed.

Release workflows now follow the go-macos-pkg reference. `actionlint` and
`goreleaser check` pass; an actual local GoReleaser snapshot produced six archives,
six SPDX SBOMs and twelve validated checksums. Snapshot signing is explicitly
skipped. The repository inherits `RP_APP_ID` and `RP_APP_PRIVATE_KEY` from the
organization. Release Please subsequently created the 0.1.0 release, and the
[successful tagged workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35513404237)
on `39b705e1660b3e7458f3baedcb7b2ae31b5c8b86` published six archives, six SPDX
SBOMs, checksums and a Sigstore signature bundle in
[v0.1.0](https://github.com/deploymenttheory/go-macos-codesign/releases/tag/v0.1.0).
That release contains the supported subset through PR #18.

### Framework-version phase

The new phase adds twelve selected-signing tree comparisons, ninety exact display
comparisons, six selected-removal comparisons and six dry-run preservation cases.
Twenty-one parent cases agree with Apple in shallow/deep modes, including unsigned
alternates, incompatible CDHashes/requirements and page/resource/metadata changes.
Nine identity/architecture combinations pass native strict deep verification.
Three native app archives preserve both framework versions and are reproduced by
the Go CLI. The two-target Clang layout record now includes complete selection and
alternate-version validation methods, bringing it to seven methods.
Local full-suite coverage is 3,803/3,949 library statements (96.30%), 423/425 CLI
statements (99.53%) and 1/1 entry-point statement (100%). Lint, dependency and
fixture guards, and six-target GoReleaser builds pass.

CI now requires 318 signed imports, including eighteen additional Linux/Windows
framework-version trees, plus the existing 88 removal comparisons. The current
branch still needs its own completed CI run; prior merged evidence is not a claim
about this implementation.

### Bundle-layout phase CI

[PR #17 is merged](https://github.com/deploymenttheory/go-macos-codesign/pull/17).
Its [completed workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35504676803)
tested commit `116e41de55c8c2f5b12dc8dffd68109f18981b65`. Downloaded artifacts report:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,682/3,827 — 96.21% | 414/422 — 98.10% | 1/1 — 100% |
| Windows 2025 | 3,679/3,827 — 96.13% | 414/422 — 98.10% | 1/1 — 100% |
| macOS 27 | 3,688/3,827 — 96.37% | 420/422 — 99.53% | 1/1 — 100% |

All three OS jobs, six-target GoReleaser packaging, race detection and nine fuzz
targets passed. Apple verified all **300** Linux/Windows artifacts, including
**126 layout archives**, **36 recursive app trees**, **18 plain-nested-code apps**,
**24 binary-plist apps** and **30 DMGs**; every DMG passed `hdiutil verify`.
[golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35504676779).
All 492 recorded source/fixture hashes per OS were audited against that checkout;
only seventeen expected Windows text line-ending conversions differed.

The phase recorded 36 complete standalone signing byte comparisons, 180 display
cases, twelve mixed-tree byte comparisons and 63 native strict deep checks.
Thirty-nine mutations were checked in both modes. Eighteen native archives
preserve signed bytes and symlink targets; five complete validation/removal
methods have Clang records. The padding gap recorded in that phase is fixed by
the current removal work rather than retroactively claimed as a PR #17 success.

### Recursive-app phase CI

[PR #16 is merged](https://github.com/deploymenttheory/go-macos-codesign/pull/16).
Its [completed workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35501058762)
tested commit `603922b77ea11fe0637b4e99c68eb260c7c9ea26`. Downloaded artifacts report:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,547/3,684 — 96.28% | 414/422 — 98.10% | 1/1 — 100% |
| Windows 2025 | 3,544/3,684 — 96.20% | 414/422 — 98.10% | 1/1 — 100% |
| macOS 27 | 3,553/3,684 — 96.44% | 420/422 — 99.53% | 1/1 — 100% |

All three OS jobs, six-target GoReleaser packaging, race detection and nine fuzz
targets passed. Apple verified all **174** Linux/Windows artifacts, including
**36 recursive app trees** and **18 plain-nested-code apps** with strict deep
verification, plus **24 binary-plist apps** and **30 DMGs**; every DMG also passed
`hdiutil verify`. [golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35501058628).
All 463 recorded source/fixture hashes per OS were audited against that checkout;
only expected Windows Git text line-ending conversions differed. Hosted macOS
build 26A5406e also passed the exact native byte and display comparisons.

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

The bundle profile includes XML/binary metadata, nested Mach-O files, recursive
APPL/BNDL/XPC! Contents layouts, unversioned/multiple-version FMWK frameworks,
explicit selection and bounded relative symlink seals. Direct physical-version
path discovery and broader symlink/xattr policy are the next format work.
UDIF signing is implemented for a bounded profile;
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
