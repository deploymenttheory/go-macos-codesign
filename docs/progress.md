# Project progress

Updated 2026-09-24. This page describes the implementation in this branch and
links its validation evidence. It does not declare a release or full `codesign`
parity. The [compatibility inventory](../spec/compatibility.json) remains the
full-equivalence audit; the [roadmap](implementation.md) lists the remaining work.
Versioned releases of the supported subset use [Release Please and GoReleaser](releases.md).

## Current certificate-extraction slice

Display accepts `--extract-certificates[=PREFIX]` and writes supported CMS chains
as leaf-first DER files, including an embedded root. It reuses owned certificate
metadata without adding a trust decision or a platform dependency. Default/empty
prefixes, in-place overwrite, preserved stale files, partial failures, multiple
targets and architecture selection have independent native comparisons. The new
matrix has 115 portable cases and two Mac-specific cases; the latter retain the
existing bundle-parent alias display difference explicitly. Eight complete Apple
path/notice/CMS-accessor functions have two-target Clang records.

[Certificate extraction](certificates.md#certificate-extraction) documents the
write contract and remaining chain, signature-slot, entitlement-display and
filesystem limits. Only this inventory entry advances to partial: 26 partial,
54 not implemented, eight blocked and zero fully verified. Final per-commit CI
and artifact validation belong to the implementation PR.

## Merged signing-notice slice

Forced signing now emits the native replacement notice once per top-level operand,
including dry runs and later failures. The optional `SignOptions.OnReplace`
callback keeps presentation in the CLI and byte APIs silent. Invalid page sizes
are rejected before notices. The new matrix adds 92 portable cases and eight Mac
failure/continuation cases; all 70 retained DMG dry-run cases now require exact
diagnostics. Six complete Apple path/notice functions have two-target Clang records.
[Signing diagnostics](signing-diagnostics.md) separates these results from remaining
verbosity, malformed-signature and OS-error differences.

[PR #50](https://github.com/deploymenttheory/go-macos-codesign/pull/50) passed all
three OS jobs, lint, six-target packaging, race/fuzz and native imports. Library
coverage is 95.30% on Linux, 95.21% on Windows and 95.39% on Mac; CLI coverage
exceeds 98% and the entry point is 100%. The audit checked 604 source hashes per
OS, all 80 lifecycle output hashes per foreign producer against native-compared
Mac records, packaged binaries and twelve checksums. The actual merge shares the
audited tree; [the plan](implementation_plan.md#merged-pr50) records exact commits
and the local native chain-setup failure that did not recur in hosted CI.

## Merged ad-hoc DMG dry-run slice

Ad-hoc DMG path dry runs now write native requirements/CMS components and optional
entitlements without a CodeDirectory. This changes bytes and modification time in
place and leaves the image unsigned, including after forced replacement of a
valid signature. Repeated dry runs and subsequent signing work without force.
`SignBytes` remains construction-only and returns a complete signature.

A 70-case lifecycle matrix covers five image formats, signed/unsigned inputs and
seven option profiles. All 80 existing DMG access/metadata cases now require byte
equality; four additional cases cover write permissions. Expanded Clang evidence
extracts the complete native architecture-agnostic signer on both targets. CI adds
140 unsigned Linux/Windows output comparisons, separate from valid signed imports.
Final per-commit validation is recorded in
[merged PR #49](https://github.com/deploymenttheory/go-macos-codesign/pull/49).

PR #49 passed all three OS jobs, lint, six-target packaging, race/fuzz and native
imports. Library coverage is 95.29% on Linux, 95.20% on Windows and 95.38% on Mac;
CLI coverage exceeds 98% and the entry point is 100% on each. All 601 source hashes
per OS and packaged binary/checksum evidence were audited. The actual merge shares
the tested tree; [the plan](implementation_plan.md#merged-pr49) records exact commits.

The native certificate dry-run probe terminates by signal before writing. Four
public RSA/P-256 observations are pinned; Go returns unsupported before writing
or calling a TSA. PR #50 closes the measured replacement-notice omission
for supported inputs; full CLI diagnostic parity remains open.

Merged [PR #48](https://github.com/deploymenttheory/go-macos-codesign/pull/48)
delivers unsigned-child dry-run allocation, 72 native cases and twelve portable
failure/cancellation controls. All 54 failure-boundary cases require matching
source/replacement access. Its [required CI](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35686294132)
passed; [the plan](implementation_plan.md#merged-pr48) identifies the tested and
merged commits without claiming a new artifact audit of that historical run.

Merged [PR #47](https://github.com/deploymenttheory/go-macos-codesign/pull/47)
defers source access until execution reaches each executable and pins released
APFS v0.9.0. Its actual merge shares the audited tree; three-OS CI, six packages,
race/fuzz, 606 signed imports and 88 removals pass. The
[implementation plan](implementation_plan.md#merged-pr47) records exact evidence.

Inaccessible directories, broader planning and asynchronous sibling failures,
ACL inheritance/copying remain open. The merged bundle dry-run corpus covers a
single descendant chain; sibling scheduling is not claimed equivalent.
[File writes](file-writes.md) records the limits. All 88 inventory statuses and
D04/WP-02 remain partial or outstanding.

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
| Direct framework directories | Physical-version and Current inputs, independent resource boundaries, native display paths and selector rejection | [Direct directory behavior](bundles.md#direct-version-directory-paths) |
| Main-executable inputs | Contents/framework main paths and file aliases select the bundle; helpers and hard-link aliases remain standalone; native lifecycle and resource-tamper comparisons | [Executable discovery and limits](bundles.md#main-executable-paths) |
| Standalone hard-link writes | Staged Mach-O replacement delegates metadata to go-apfs-v2; neighbours remain unchanged; DMGs retain in-place behavior | [Shared API, native comparisons and limits](file-writes.md) |
| Standalone file aliases | Physical target selection for identifiers, display and writes; preserved aliases and lexical neighbours; native trailing-allocation bytes on re-signing | [Alias behavior and evidence](file-writes.md) |
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

### Bundle executable writer and native inventory

This branch implements the first D04 slice. Bundle main/nested Mach-O writes
stage replacements under their existing `os.Root`; external hard-link neighbours
retain their original bytes and inode. CodeResources retains its in-place update
and unlink-on-removal behavior. All executables stage before any bundle commit;
late commit failures can leave earlier writes in place. Native ACL inheritance,
creation-time behavior, new signature-directory security and stale-file cleanup
remain explicit gaps in [file writes](file-writes.md).

The APFS prerequisite shipped in [PR #102](https://github.com/deploymenttheory/go-apfs-v2/pull/102)
and [v0.5.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.5.0).
This module pins that release; it needs no development workspace or APFS replace.
Local native acceptance passes 126 complete tree/inode comparisons. Fifteen metadata profiles
also record the remaining native differences. Local full verification
passes with 3,979/4,161 library statements (95.63%), 423/425 CLI statements (99.53%)
and 1/1 entry-point statement. golangci-lint and all six GoReleaser builds pass.
APFS [three-OS tests and six builds](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/35531568090)
passed at `5ffe196cad831ba35916cec46f30f1d0ce419591`.

[PR #27](https://github.com/deploymenttheory/go-macos-codesign/pull/27) records the
[implementation workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35532377695)
for `a9248cd5c091c9cbb9a6cc8d195243a4dcca6af1`. Its three producer jobs,
six-target packaging, native imports and
[golangci-lint](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35532377717)
pass. Downloaded artifacts report:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,972/4,161 — 95.46% | 417/425 — 98.12% | 1/1 — 100% |
| Windows 2025 | 3,969/4,161 — 95.39% | 417/425 — 98.12% | 1/1 — 100% |
| macOS 27 | 3,979/4,161 — 95.63% | 423/425 — 99.53% | 1/1 — 100% |

All 573 source/fixture hashes per OS match the tested source, with only seventeen
expected Windows text conversions. Each foreign producer's 126 writer-tree
hashes and 184 standalone/alias/allocation hashes match the hosted Apple-compared
outputs. Apple accepts all 522 imported signed artifacts, including 168 writer
archives; all 88 removal outputs match native bytes. Twelve archive/SBOM checksums
pass, and all six binaries embed APFS v0.5.0 with CGO disabled. The CI merge commit
has the same tree as the tested head. Final PR checks and subsequent documentation
commits remain identified separately in the pull request.

D01 expands the checklist from 55 to 88 entries without upgrading statuses:
25 partial, 55 not implemented, eight blocked, zero fully verified. The
[native inventory](native-inventory.md) has 79 parser-recognized switches with
seven operation cells each, raw transcripts and explicit unavailable contexts.
D02 writer research expands from two to nine complete methods on both targets.

### Standalone file alias phase

Standalone Mach-O/UDIF aliases resolve before reads, default identifiers, display
and writes. Relative, absolute and chained links retain their entries; `link/..`
uses the physical parent. Mach-O replacement continues to use APFS v0.4.0 and
preserves hard-link neighbours, while DMGs retain in-place writes. Re-signing
also preserves existing trailing allocation bytes, matching native shorter-ID
behavior found by the new comparisons.

Local native acceptance passes 150 Mach-O alias cases, ten DMG alias cases,
350 complete display comparisons and nine allocation-padding comparisons.
Broken/looping aliases fail eight CLI operations without writes. Five complete
Apple path functions have two-target Clang AST records. The full local suite
passes with 3,930/4,098 library statements (95.90%), 423/425 CLI statements
(99.53%) and 1/1 entry-point statement. golangci-lint and six GoReleaser builds
pass. Each producer emits 169 output hashes for comparison with the independently
native-checked macOS outputs. Final per-commit CI results and downloaded artifact
audits are recorded in the phase's pull request; local checks do not establish
Windows or Linux execution. [Writer limits](file-writes.md) remain explicit.

### Standalone writer and shared metadata phase

The writer delegates filesystem metadata to the exported go-apfs-v2 API delivered
in [merged APFS PR #100](https://github.com/deploymenttheory/go-apfs-v2/pull/100)
and released in [v0.4.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.4.0).
The dependency now pins that release.
Codesign contains no platform metadata copier. The Darwin replacement path uses
supported libSystem wrappers; the dependency's separate legacy compression
reader is unchanged. [Writer limits](file-writes.md) document clone support,
unsupported compression/protection, and remaining platform metadata gaps.

Local acceptance passes fifteen complete native Mach-O byte/inode comparisons
and one in-place DMG comparison, including dry runs and unsigned removal.
Cancellation after staging preserves both names and removes temporary files.
Two complete Apple writer methods and real SDK metadata constants have two-target
Clang AST evidence. The complete local suite passes with 3,919/4,087 library
statements (95.89%), 423/425 CLI statements (99.53%) and 1/1 entry-point statement.
The [final PR #24 workflow for `ce8f6b992e67313772a9fabb29fd867a3f696bde`](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35524062102)
passed all three platforms, native imports, six-target packaging, race detection
and nine fuzz targets. [golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35524062104).
Downloaded evidence reports:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,912/4,087 — 95.72% | 417/425 — 98.12% | 1/1 — 100% |
| Windows 2025 | 3,909/4,087 — 95.64% | 417/425 — 98.12% | 1/1 — 100% |
| macOS 27 | 3,919/4,087 — 95.89% | 423/425 — 99.53% | 1/1 — 100% |

All 563 source/fixture hashes per OS matched that tested commit, allowing only seventeen
expected Windows text line-ending conversions. Six archives and six SPDX SBOMs
pass all twelve checksum checks. Build metadata in every binary confirms
APFS v0.4.0, no local APFS replacement and `CGO_ENABLED=0`. All 354 signed imports
and 88 removal comparisons passed. Fifteen Linux and fifteen Windows hard-link
output hashes matched the independently native-compared macOS outputs.
The phase is merged in [PR #24](https://github.com/deploymenttheory/go-macos-codesign/pull/24).
The [APFS dependency workflow](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/35522969833)
passes its three OS test/acceptance jobs and six build targets.

### Executable-path discovery phase

The phase adds supported main-executable discovery with exact filename matching,
physical alias resolution and the existing bundle resource boundary. It preserves
helper-file classification and rejects external special-slot overrides once a
bundle is selected. Five complete CoreFoundation functions are extracted with
Clang for arm64 and x86_64 using real SDK declarations and explicit private shims.

Focused host acceptance passes 54 complete signing/removal comparisons, 270 display
comparisons, 54 dry runs, four helper/alias resource-tamper cases, read-only
hard-link display, a physical-parent regression and 32 selector-operation outcomes.
Nine identity/architecture trees sign all six child layouts and the parent via
executable inputs. Eighteen child archives reproduce existing native fixtures.
CI requires eighteen additional Linux/Windows trees, taking the signed import
total to 354 while retaining 88 removal comparisons. The complete local suite
passes with 3,891/4,044 library statements (96.22%), 423/425 CLI statements
(99.53%) and 1/1 entry-point statement (100%). Lint, dependency/fixture guards
and all six GoReleaser build targets pass. Per-commit workflow and artifact
results are recorded in [merged PR #23](https://github.com/deploymenttheory/go-macos-codesign/pull/23).
Its [completed workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35520425295)
tested code commit `62f2b0478cc5992568331071604599b622265a90`; the final documentation
commit is `d9875722d1c9fe65dd19ed958dcc560b4a1be326`.

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,884/4,044 — 96.04% | 417/425 — 98.12% | 1/1 — 100% |
| Windows 2025 | 3,881/4,044 — 95.97% | 417/425 — 98.12% | 1/1 — 100% |
| macOS 27 | 3,891/4,044 — 96.22% | 423/425 — 99.53% | 1/1 — 100% |

All 354 signed imports and 88 removal comparisons passed, as did packaging,
race detection and nine fuzz targets.
[Lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35520425262).
All 559 source/fixture hashes per OS were audited against the final checkout;
only seventeen expected Windows text line-ending conversions differed. The six
archives and six SPDX SBOMs passed all twelve checksum comparisons.
Malformed/oversized/symlinked metadata retains the stricter rejection profile.

### Direct framework-directory phase CI

Direct physical and Current version-directory inputs now pass eighteen complete
native signing/removal comparisons, ninety exact display comparisons, eighteen
dry runs, four boundary cases and 64 failed-selector preservation checks.
Nine identity/architecture trees are produced through direct paths; the three
ad-hoc trees reproduce the committed native archives. Clang records eight complete
methods, including native directory/file representation discovery.
Six additional trees prove native deep-signing byte equality with a Mach-O helper.
Two parent-link cases match Apple's `link/..` resolution, preserve the lexical
sibling and work when that sibling is absent.

[PR #22 is merged](https://github.com/deploymenttheory/go-macos-codesign/pull/22).
Its [completed workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35518761734)
tested `9902744e1eec3132f0738bc7defabe913d7d2dba`. Downloaded evidence reports:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,847/4,000 — 96.175% | 417/425 — 98.12% | 1/1 — 100% |
| Windows 2025 | 3,844/4,000 — 96.10% | 417/425 — 98.12% | 1/1 — 100% |
| macOS 27 | 3,854/4,000 — 96.35% | 423/425 — 99.53% | 1/1 — 100% |

All OS jobs, native verification, six-target packaging, race detection and nine
fuzz targets passed; [golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35518761729).
Apple accepted all **336** signed imports and matched all **88** removals byte for
byte. All **554** source/fixture hashes per OS match the tested checkout, allowing
seventeen expected Windows CRLF conversions. Six archives and six SPDX 2.3 SBOMs
passed all twelve SHA-256 checksums. Windows passed both parent-link regressions;
macOS also confirmed native byte equality and all six nested-helper cases.

### Framework-version phase CI

The phase added twelve selected-signing tree comparisons, ninety exact display
comparisons, six selected-removal comparisons and six dry-run preservation cases.
Twenty-one parent cases agree with Apple in shallow/deep modes, including unsigned
alternates, incompatible CDHashes/requirements and page/resource/metadata changes.
Nine identity/architecture combinations pass native strict deep verification.
Three native app archives preserve both framework versions and are reproduced by
the Go CLI. That phase expanded the two-target Clang layout record to seven
methods by adding complete selection and alternate-version validation bodies.
Local full-suite coverage is 3,803/3,949 library statements (96.30%), 423/425 CLI
statements (99.53%) and 1/1 entry-point statement (100%). Lint, dependency and
fixture guards, and six-target GoReleaser builds pass.

[PR #20 is merged](https://github.com/deploymenttheory/go-macos-codesign/pull/20).
Its [completed workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35516832486)
tested `d0af1256eaacc322bbd0ac540d4803f1b5ebb2af`. Downloaded evidence reports:

| Runner | Library | CLI | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,796/3,949 — 96.13% | 417/425 — 98.12% | 1/1 — 100% |
| Windows 2025 | 3,793/3,949 — 96.05% | 417/425 — 98.12% | 1/1 — 100% |
| macOS 27 | 3,803/3,949 — 96.30% | 423/425 — 99.53% | 1/1 — 100% |

All OS jobs, packaging, race detection and nine fuzz targets passed;
[golangci-lint passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35516832475).
Apple accepted all **318** signed imports, including eighteen multi-version
framework trees, and matched all **88** removal outputs byte for byte. All 551
recorded source/fixture hashes per OS were audited against that checkout; only
seventeen expected Windows text line-ending conversions differed. The six archives
and six SPDX SBOMs passed all twelve checksum checks. Prior merged evidence does
not establish validation of a later implementation.

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
explicit selection, direct version directories, main-executable discovery and
bounded relative symlink seals. Wider discovery and broader symlink/xattr policy are the next
format work.
UDIF signing is implemented for a bounded profile;
large-image streaming, encrypted/segmented images, generic-file and detached
signatures remain open. Further work includes
requirement predicates, CodeDirectory variants, wider file replacement and
metadata preservation, certificate
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
