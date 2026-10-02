# Project progress

Updated 2026-10-02. This page describes the implementation in this branch and
links its validation evidence. It does not declare a release or full `codesign`
parity. The [compatibility inventory](../spec/compatibility.json) remains the
full-equivalence audit; the [roadmap](implementation.md) lists the remaining work.
Versioned releases of the supported subset use [Release Please and GoReleaser](releases.md).

## Current removal phase

PR83 is merged at `e5aaee2c3dfb8530ba08c7fd129735e83ee216a5` after
[all required gates passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/37037417359).
Audited codesign coverage was 95.08% Linux, 95.50% macOS and 95.02% Windows;
all 66 platform-selection foreign records matched Apple. The next branch,
`feat/removal-plist-interpretation`, starts from that main and retains APFS v0.17.0.

The [plist interpretation phase](removal-plist-interpretation.md) adds bounded
XML/OpenStep/binary removal semantics, including raw-plist fallback after parse
failure and format-specific duplicate-key order. It retains 174 native cases,
adds 348 mandatory foreign records, extends Clang evidence to eight complete
bodies and adds a twelfth fuzz target. Resource limits remain fatal and the
strict signing/verification parser remains unchanged. This increment requires
its own complete CI; broader encodings and grammar remain explicit gaps.

### Merged platform-plist profile

PR81 is merged at `0701a24555d1e7cae7536260b25ae48a090c9657` after its
[full compatibility run passed](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/37013658411).
The merged `feat/platform-plist-selection` branch includes roadmap PR82
and pins published APFS v0.17.0.
Resource reads now use the SDK content reader, and replacement staging uses its
metadata reader; the duplicated native resource openers are removed. Fourteen
retained platform-plist research cases run on macOS, with provenance checks on
all hosts. Platform-plist selection is now implemented for the bounded removal
profile on all three hosts. See the
[SDK integration and remaining discovery work](removal-platform-metadata.md).

[APFS PR192](https://github.com/deploymenttheory/go-apfs-v2/pull/192) is merged and
released in v0.17.0 after all 63 applicable upstream checks passed. Its rooted
`ReadEntryType` separates basic-attribute discovery from content acquisition.
Codesign now prefers `Info-macos.plist`, retains an acquired empty plist's raw
URL and applies `CFBundleExecutable-macos` precedence on Linux, macOS and Windows.
Explicit AppleDouble bindings retain object-identity checks when unrelated ACL
visibility is denied, using the released content reader.

The new corpus contains 33 native selection cases across Contents apps, flat
frameworks and versioned frameworks. All replay through API/CLI tests; 66 foreign
records are mandatory in Apple's import job. Eighteen additional live permission
cases compare native removal with Go's native attributes and explicit carriers.
Real Windows, Linux and Darwin authorization tests remain mandatory. Nonempty
malformed metadata, broader key normalization, aliases and other operations
remain gaps. [PR83](https://github.com/deploymenttheory/go-macos-codesign/pull/83)
records this increment's validation results and current CI status; earlier green
runs are not proof of these changes. See the [remaining PR estimates](implementation_plan.md) for
the difference between this discovery profile and full parity.

Merged [missing/empty metadata discovery](removal-empty-metadata.md) adds bundle-stem
selection where native removal permits it, the versioned-framework distinction,
and a no-mutation error when neither executable nor plist exists. Twenty-seven
native cases replay on every host and add 54 mandatory foreign observations.
Clang evidence now covers six complete functions on both Mac architectures.

PR79 passed [all CI gates](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/36985960267).
Codesign coverage was 95.25% Linux, 95.50% macOS and 95.09% Windows, with discovery
functions at 100% on all three. Both Windows permission regression classes passed,
as did Apple's comparison of all 102 generic-removal records. This increment
must pass those unchanged gates plus its new cases.

[Bundle-removal discovery](bundle-removal-discovery.md) now selects Info.plist
when executable candidates are missing or metadata discovery is denied in supported
layouts. Removal has its own
metadata requirements and modern/legacy/stem executable-name selection. Eight
fallback shapes extend the native/carrier matrix; each foreign producer exports
51 generic-removal records, all required by the existing native import job.
Twenty retained native probes qualify the earlier discovery profile. Twelve
native permission comparisons and effective metadata denials
on each host qualify selection before data reads. Wider discovery remains open. PR78
passed every CI gate; codesign coverage was 95.19% Linux, 95.44% macOS and 95.04%
Windows. This increment must pass the same unchanged gates.

[Generic removal](generic-removal.md) adds attribute-backed signature removal for
standalone files and selected generic bundle executables. It preserves data forks,
requires writable access before mutation, and retains partial removals on later
failure. Explicit AppleDouble carriers work on all producers alongside native
metadata. Eight complete Apple methods have two-target Clang evidence; forty
native probes retain dispatch and permission outcomes. Generic signing, display,
verification and broader discovery remain outstanding. The inventory still has
32 partial, 48 not implemented, eight blocked and zero fully verified obligations.

[Signature removal](signature-removal.md) now operates on the selected executable
and signature directory without scanning resources, nested code or unselected
framework versions. It adds 27 portable cases and 79 native comparisons, including
effective permission denials, malformed children, symlinks and internal hard links.
Twenty new foreign-produced removal archives are required by Apple's existing
import-verification job. Selected executable errors retain their API cause and
receive native CLI permission diagnostics. PR77 passed every CI gate, including
all twenty foreign archives; codesign coverage was 95.32% Linux, 95.56% macOS and
95.16% Windows. The current increment requires its own unchanged CI gates.

The [signing-metadata contract](signing-sideband.md) describes default preflight,
`--strip-disallowed-xattrs`, explicit mutable AppleDouble inputs, dry-run effects
and independent-child completion after resource failures. The new acceptance
matrix runs on every producer and adds native comparisons on macOS.
[Permission qualification](signing-permissions.md) adds 400 real Darwin ACL
comparisons, six portable CLI write-denial cases, and portable partial-removal
and error-identity tests. Executable preflight ordering, nested permission
diagnostics and readable-resource traversal are corrected. Merged PR76 moves final
security restoration after the last explicit access-time write, retains the
source handle until restoration, and adds 72 native comparisons of writeattr,
writesecurity and append ACLs, including actual final ACL records. Shared lifecycle
tests cover success, failure, cancellation and handle cleanup on all three hosts.
Broader discovery, signature-directory metadata denial and denied-delete
temporary-artifact differences remain roadmap items alongside parent ACL inheritance.
PR76 passed all CI, with codesign coverage of 95.32% on Linux, 95.18% on Windows
and 95.54% on macOS. Its native and portable tests remain unchanged.
Broader permission/concurrency profiles and the remaining compatibility inventory
are still open; this does not declare full codesign parity.

## Current published APFS dependency

Codesign pins [APFS v0.17.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.17.0)
and uses its `hostdata` and `hostdata/accesstime` packages for existing replacement,
directory metadata, metadata-only discovery and read/access-time operations. No local APFS replacement or
copied metadata codec is used. The earlier v0.15.0 correction removes
purego through the approved finite typed Darwin wrappers and preserves portable
metadata support on Linux and Windows.

APFS PR186 fixes writable replacement staging with denied source ACLs; release
PR187 publishes v0.15.1. Native executable ACL inheritance remains a separate
codesign policy obligation and is not declared complete by that SDK fix.

APFS PR188 supplies `hostdata.StatMetadata` and corrects Windows metadata-handle
acquisition. Its query files reached 100% statement coverage on all three hosts;
all upstream gates passed. Codesign uses the released API and tests an effective
NTFS metadata denial with both file-attribute and parent directory-list access
denied. Existing denied-data tests remain mandatory and must not select Info.plist.

[APFS PR184](https://github.com/deploymenttheory/go-apfs-v2/pull/184) passed all
64 applicable checks; wrapper coverage on the Mac runner was 98.8%. Both downstream
PRs adopted the published module and are merged: codesign PR70 and macOS-pkg PR72.
See the
[dependency boundary and validation gate](apfs-dependency.md). The prior
purego publication blocker is resolved. Subsequent green codesign PR71–73
qualified the adapter and standalone/bundle sideband verification on that pin.

## Strict-attribute research baseline

[APFS PR #131](https://github.com/deploymenttheory/go-apfs-v2/pull/131) adds strict
size, bounded read and removal by descriptor or no-follow path on Linux, macOS
and Windows. The initial Windows stub was rejected and replaced by real native
EA operations and required runtime tests. Its
[corrected CI](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/36333046033)
passed all three OS suites, six builds, lint and race; associated fuzz checks
passed. Strict-API coverage is 98.85% Mac/Linux and 98.69% Windows, with zero
skipped strict tests. Those APIs remain included in the current dependency.
[The contract](sideband-policy.md) now records twelve complete Apple bodies on two
Clang targets and 203 native verification controls. Another 42 directory-fork
setups are unavailable and explicitly unexecuted. The probe establishes that
verification-time stripping is inert in the measured CLI profile. Standalone and
bundle sideband/plain/all verification are merged; signing-time policy and
stripping are the current implementation phase.

## Merged resource-suppression slice

[`--ignore-resources`](ignore-resources.md) skips the envelope, ordinary resources
and parent-sealed child code, even with deep verification. Main executable pages,
CMS/trust, non-resource slots, requirements and enabled structure still apply.
Verbose output and JSON explicitly identify this scope. The 385 portable cases
have 767 comparable hashes; Mac adds 11 independent producer/applicability controls.
Four complete Apple bodies compile into Clang ASTs for both Mac targets. The
inventory is now 30 partial, 50 not implemented, eight blocked and zero verified.
[PR #68](https://github.com/deploymenttheory/go-macos-codesign/pull/68) merged as
`78825e4ac1efb579ca8752e73e68a58505094fcf`. Its
[final compatibility run](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/36321587740)
and lint passed. Library coverage was 95.55% Mac, 95.41% Linux and 95.33% Windows;
CLI was 99.06%, 98.44% and 98.44%, with entry point 100%. The downloaded Mac
package passed 507 native comparisons (497 exact, ten retained bounded).
[The merged record](implementation_plan.md#merged-pr68) preserves revisions,
source/artifact checks and the remaining limits.

## Merged strict-verification slice

[Strict verification](strict-verification.md) adds default Mach-O layout policy,
verification-only symlink selectors, disabling controls and enclosing bundle
resource scopes. There are 561 portable cases, 545 native comparison profiles,
16 JSON reports and 18 complete Apple bodies with two-target Clang evidence.
Sideband/all policy, xattrs, custom rules and broader native filesystem behavior
remain open. [PR #66](https://github.com/deploymenttheory/go-macos-codesign/pull/66)
merged as `eed319dce8c402f5740ea73887032f7220361116` on 2026-09-27.
Its final [compatibility run](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/36319043689)
passed all three OS, native imports, race/eleven fuzz and six GoReleaser packages;
lint passed. Library coverage was 95.60% Mac, 95.46% Linux and 95.38% Windows;
CLI was 99.05%, 98.42% and 98.42%, with entry point 100%. The audit checked
668 source hashes per producer, 4,002 verification hashes and 415 downloaded Mac
package comparisons. The [merged record](implementation_plan.md#merged-pr66)
preserves exact revisions, native-crash evidence and bounded diagnostic differences.

## Merged APFS fixture-validation follow-up

[PR #65](https://github.com/deploymenttheory/go-macos-codesign/pull/65) merged as
`d12364610b80317637566f463558cdc5eb26f052` on 2026-09-27. It pins released
APFS v0.11.2 and re-signs the exact archived LZFSE payload, preserving the native
byte oracle. The final [compatibility run](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/36279963368)
passed Linux, Windows 2025, Mac, native imports, race/eleven fuzz and six GoReleaser
packages. Library coverage was 95.59%, 95.51% and 95.68%; CLI coverage was 98.33%,
98.33% and 99.00%, with the entry point at 100%. Lint passed. The downloaded Mac
package passed 359 native comparisons. The earlier native cyclic-framework
termination is now tracked by the
[PR66 crash investigation](strict-verification.md#native-asynchronous-verification-crash-on-xcode-27);
signal logging and hard assertions are retained.

## Merged symlink-verification and dependency slice

The dependency is updated to released APFS v0.11.1, including its newer DMG and
LZFSE fixes, with no APFS replacement. [Default symlink verification](resource-symlinks.md)
compares sealed text without resolving targets, including dangling, cyclic and
external links. Signing retains its containment policy. There are 352 portable
cases, 68 native-signing cases and 568 comparable hashes. All twelve earlier
dangling-link records now match native output; the four acceptance differences
are resolved. The resource driver now has nine complete bodies on two Clang
targets. Of 102 strict-policy observations, 34 symlink profiles are now implemented; 68 plain/all profiles remain unsupported.
Current-commit coverage and artifact gates belong to the corrective follow-up.
No inventory upgrade.

## Merged resource-verification slice

[Resource verification](resource-verification.md) collects ordinary added, modified
and missing paths, preserves detailed causes, reports selected framework paths,
and supports verbose/JSON and shallow/deep child behavior. Eight complete Apple
bodies have two-target Clang evidence. There are 382 new cases, 358 native profiles
and 686 deterministic hashes per producer. Exact output is required for 306 native
profiles; 40 ordering/summary and twelve dangling-link profiles retain explicit
differences. Four dangling cases expose native acceptance versus portable rejection.
[PR #63](https://github.com/deploymenttheory/go-macos-codesign/pull/63) passed all
three OS, native-import, race/eleven fuzz, lint and package gates. Library coverage
was 95.61% Linux, 95.53% Windows and 95.69% Mac; CLI coverage was 98.33%, 98.33%
and 99.00%. Its actual merge shares the audited tree. [The plan](implementation_plan.md#merged-pr63)
records 660 source hashes per OS, 2,408 producer hashes and 327 packaged native
comparisons. The four dangling-link acceptance differences were resolved above.

## Merged verification-diagnostics slice

[Diagnostic context](verification-diagnostics.md) adds bounded native wording,
failing architecture, nested paths and verbose modified-child details. Error
causes are preserved; JSON stdout remains parseable. Eight complete Apple bodies
have two-target Clang evidence. There are 182 new cases, 170 native comparisons
and 340 deterministic cross-OS hashes; 178 earlier comparisons now require exact
diagnostics. [PR #61](https://github.com/deploymenttheory/go-macos-codesign/pull/61)
passed all three OS, native-import, lint, race/eleven fuzz and packaging gates.
Library coverage was 95.56% Linux, 95.48% Windows and 95.64% Mac; CLI coverage was
98.32%, 98.32% and 98.99%, with entry point 100%. The actual merge shares the
tested CI tree. [The plan](implementation_plan.md#merged-pr61) records 655 source
hashes per OS, producer audits and 251 exact packaged native comparisons.

## Merged requirement-verification slice

Quiet verification now accepts intact signatures with false stored designated
requirements. Verbose self checks, explicit caller predicates and parent-sealed
constraints have separate stages and architecture scopes. Failed parent predicates
remain integrity failures; the first failing operand determines the CLI status.
Explicit certificate trust is unchanged. The [contract](requirement-verification.md)
documents API migration, 822 new cases, six complete Apple bodies on two Clang
targets and remaining malformed-structure differences. Merged
[PR #60](https://github.com/deploymenttheory/go-macos-codesign/pull/60) passed all
three OS, native import, lint, race/eleven fuzz and packaging gates. Library
coverage was 95.56% Linux, 95.47% Windows and 95.64% Mac; CLI coverage was
98.28%, 98.28% and 98.97%, with entry point 100%. Its actual merge shares the
audited tree. [The plan](implementation_plan.md#merged-pr60) records revisions,
649 source hashes per OS and 1,382 deterministic hashes per foreign producer.
The broad inventory is unchanged.

## Merged requirement-default slice

Certificate signing fills missing designated requirements in empty and partial
sets, preserves explicit overrides and repacks binary entries canonically.
Nested objects receive their own defaults; replacement uses fresh options.
The [contract](requirement-defaults.md) defines 277 portable/native comparison cases
and 48 additional Mac certificate cases, with six complete Apple bodies and
two-target Clang evidence. [PR #59](https://github.com/deploymenttheory/go-macos-codesign/pull/59)
passed the three OS jobs, native imports, race/eleven fuzz targets, lint and
packaging. Library coverage was 95.55% Linux, 95.47% Windows and 95.64% Mac; CLI
was 98.92%, 98.92% and 99.64%, with entry point 100%. Its actual merge shares the
audited tree. [The plan](implementation_plan.md#merged-pr59) records exact revisions,
643 source hashes per OS, 1,338 deterministic hashes per foreign producer and
retained matrices/package audits. The thirty quiet-verification differences found
in that slice are resolved by the current increment above. Representation defaults
and metadata preservation remain open.

## Merged requirement-set compiler slice

Signing now compiles all five named requirement kinds and unsigned decimal kinds
through the shared expression parser. Entries sort by kind; the last duplicate
wins. Comments, semicolons and implicit extension-existence boundaries match the
measured native grammar. Six complete Apple bodies have two-target Clang ASTs;
33 native compiler records, 18 signed-tree comparisons, 12 rejection cases and
12 certificate signing cases establish the bounded profile. The
[contract](requirement-sets.md) retains wider grammar, stdin/substitution and exact
error diagnostics as outstanding. [PR #58](https://github.com/deploymenttheory/go-macos-codesign/pull/58)
passed all three OS jobs, native imports, race/eleven fuzz targets, lint and
packaging. Audited library coverage is 95.51% Linux, 95.42% Windows and 95.59% Mac;
CLI is 98.92%, 98.92% and 99.64%, with entry point 100%. Its actual merge shares
the audited tree; [the plan](implementation_plan.md#merged-pr58) records revisions,
638 source hashes per OS, 117 new deterministic hashes per foreign producer and
all retained matrices/package audits. The inventory remains unchanged.

## Merged requirement-extraction slice

Display now supports `-r-` and file destinations for the existing requirement
expression subset. Named binary sets render in native order; absent designated
requirements are synthesized as comments. Component hashes, truncate-before-check
output, architecture selection and combined extraction behavior have 87 cases:
86 native comparisons and one portable JSON case. Six complete Apple bodies have
two-target Clang ASTs; `FuzzRequirementSet` adds direct binary-set fuzzing.
[The contract](requirement-extraction.md) records bounds and remaining language,
policy, representation and diagnostic work.

[PR #57](https://github.com/deploymenttheory/go-macos-codesign/pull/57) merged with
all three OS jobs, native imports, race/eleven fuzz targets, lint and packaging
passing. Audited library coverage is 95.49% Linux, 95.40% Windows and 95.57% Mac;
CLI is 98.92%, 98.92% and 99.64%, with entry point 100%. The audit checked 634
source hashes per OS, 188 deterministic requirement hashes per foreign producer,
the retained matrices, six binaries and twelve archive/SBOM checksums. The actual
merge shares the audited tree; [the plan](implementation_plan.md#merged-pr57)
records exact revisions. The inventory remains 27 partial, 53 not implemented,
eight blocked and zero verified.

## Merged entitlement-extraction slice

Display now reconstructs compact XML from DER, emits the native typed text dump,
checks component binding and preserves normal diagnostics. It matches append
files, consumed colon prefixes, malformed-data exit distinctions, architecture
selection and certificate/file-list ordering. The 90-case matrix includes 89
native comparisons and one portable JSON interaction. Six complete Apple
functions have two-target Clang evidence; a tenth fuzz target exercises the DER
reader directly. [The contract](entitlement-extraction.md) records bounds and
remaining CMS/slot/locale/filesystem work.

[PR #54](https://github.com/deploymenttheory/go-macos-codesign/pull/54) passed all
three OS jobs, native imports, race/ten fuzz targets, lint and six-target packaging.
Audited library coverage is 95.46% Linux, 95.37% Windows and 95.55% Mac; CLI is
98.86%, 98.86% and 99.62%, with entry point 100%. The audit checked 627 source hashes
per OS, 178 entitlement input/output hashes per foreign producer, all retained
matrices, six binaries and twelve archive/SBOM checksums. Its actual merge shares
the audited tree; [the plan](implementation_plan.md#merged-pr54) records exact evidence.

## Merged file-list slice

Signing/display now support native ordered `--file-list PATH` output, append and
stdout destinations, framework dot spelling, fatal output-open errors, preceding
signing/extraction effects and signed DMG dry-run reports. The matrix adds 76
representation and 17 CLI lifecycle cases plus three library/native external
component comparisons. Mac adds permission handling and six explicitly divergent
native crash profiles. Six complete Apple functions have two-target Clang ASTs.
[File-list limits](file-lists.md) preserve external CLI-layout restrictions and
unproven interactions. PR #53 moved only `--file-list` to partial: 27 partial, 53 not
implemented, eight blocked, zero verified.

[PR #53](https://github.com/deploymenttheory/go-macos-codesign/pull/53) passed all
three OS jobs, native imports, race/fuzz, lint and six-target packaging. Audited
library coverage is 95.31% on Linux, 95.22% on Windows and 95.40% on Mac; CLI is
98.77%, 98.77% and 99.59%, with the entry point at 100%. The audit checked 620 source
hashes per OS and 327 file-list path/tree values per foreign producer, retained
previous matrices, six packaged binaries and twelve checksums. Its actual merge
matches the audited tree; [the plan](implementation_plan.md#merged-pr53) records
exact revisions, artifacts and the six explicit native crash differences.

## Merged bundle-parent path slice

Bundle directory parents now resolve physically before lexical cleanup, sharing
the existing framework-directory resolver. This closes the extraction display
gap and ensures `link/..` selects the physical neighbour on Windows. Final bundle
root aliases remain unsupported; structural Current validation and internal
containment rules are retained. A 108-case matrix covers nine layouts, three
architectures and four operand forms, with native signing/removal bytes, five
display levels, verification, dry-run preservation and unchanged aliases/decoys.
See [bundle directory operands](bundles.md#directory-operands-and-parent-aliases).

[PR #52](https://github.com/deploymenttheory/go-macos-codesign/pull/52) passed all
three OS jobs, native imports, race/fuzz, lint and packaging. Its actual merge
matches the independently audited CI tree. Coverage is 95.31% library / 98.70%
CLI on Linux, 95.22% / 98.70% on Windows and 95.40% / 99.57% on Mac; the entry point
is 100% everywhere. The audit checked 611 source hashes per OS, all 108 parent
signing/removal hashes and 96 DER sets per foreign producer, 606 signed imports,
88 removals, 140 DMG dry-run imports, six packaged binaries and twelve checksums.
The hosted verbose-date profile remains an explicit difference; parent-alias
extraction display is now exact. [The plan](implementation_plan.md#merged-pr52)
records the revisions and complete combined gates.

## Merged certificate-extraction slice

Display accepts `--extract-certificates[=PREFIX]` and writes supported CMS chains
as leaf-first DER files, including an embedded root. It reuses owned certificate
metadata without adding a trust decision or a platform dependency. Default/empty
prefixes, in-place overwrite, preserved stale files, partial failures, multiple
targets and architecture selection have independent native comparisons. The new
matrix has 115 portable cases and two Mac-specific cases; the current path slice
upgrades the bundle-parent alias case to require identical display. Certificate verbose
cases also record the hosted Mac's native date-format difference using two exact
observed profiles, without normalizing actual output. Eight complete Apple
path/notice/CMS-accessor functions have two-target Clang records.

[Certificate extraction](certificates.md#certificate-extraction) documents the
write contract and remaining chain, signature-slot, entitlement-display and
filesystem limits. PR #51 moved only extraction to partial: 26 partial,
54 not implemented, eight blocked and zero fully verified. Its final PR workflow
passed Linux, Windows, packaging and race/fuzz, but Mac failed on the native date
profile and imports were skipped. [The plan](implementation_plan.md#merged-pr51)
records the exact merged revision and validation limits. PR #52 subsequently established the passing combined gates, retaining the
localized-date difference explicitly.

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
