# Detailed implementation plan: remaining codesign equivalence

Status: updated 2026-09-21 after [PR #39](https://github.com/deploymenttheory/go-macos-codesign/pull/39) merged.
D01/D02's initial evidence, D04 bundle Mach-O replacement, regular stale-file
cleanup, new signature-directory stat metadata and the bounded failure profile
for stale directories and symlinks, plus case-insensitive APFS ASCII cleanup
ordering, signing-envelope failures and Darwin executable creation time, are on `main`.
Codesign pins released APFS v0.7.0 without a local replace or workspace.

PR #39 adds 210 native creation-time comparisons covering past/future modification
times, nested code, external hard links and dry runs. Final three-OS execution,
coverage, packaging, race/fuzz, lint and artifact audits passed; the actual merge
matches the audited tree. Apple verified all 606 signed imports and 88 removal
comparisons. [Merged validation](#merged-pr39) records the exact commits and results.

Executable ACL inheritance, explicit signature-directory ACL copying, access-time
behavior and wider permission/filesystem profiles remain open. Symlinked signing
envelopes retain the documented containment difference. D04/WP-02 is not complete.
The original PR #25 baseline below remains historical. Releases still require approval.

The current inventory retains 88 obligations: 25 partial, 55 not implemented,
eight blocked and zero fully verified. No feature status was upgraded merely
because the parser recognized an option or one writer profile passed. WP-01 and
WP-02 remain open. [PR #27 evidence](#merged-pr27), [PR #29/#30 evidence](#merged-pr30),
[PR #31 evidence](#merged-pr31), [PR #32/#33 evidence](#merged-pr33),
[PR #34 evidence](#merged-pr34), [PR #35 evidence](#merged-pr35),
[PR #36/#37 evidence](#merged-pr37), [PR #39 evidence](#merged-pr39) and the
[delivery status](#delivery-status) distinguish
delivered profiles from remaining work; [file writes](file-writes.md) records the exact metadata and filesystem limits.

This is the detailed execution companion to [implementation stages](implementation.md).
It includes missing features, unfinished behavior within existing features,
unproven compatibility, deliberate limits, and dependencies on unavailable state.
Work packages remain outstanding except for explicitly checked, bounded tasks
and already delivered baseline behavior. Unchecked proposed APIs, tests and
artifacts are future work, not existing capabilities. Continuous verification and
inventory-maintenance tasks remain open for every subsequent implementation slice.

## 1. Objective, baseline and meaning of completion

The objective remains a pure Go library and Cobra/Viper CLI reproducing Apple's
`codesign` behavior, with no Apple code-signing runtime, framework, helper binary,
SDK, Clang or CGO requirement in production. Supported workflows must execute on
Linux, macOS and Windows. Clang/AST research and independent Apple acceptance
belong to development and testing. GoReleaser owns production builds and packaging.

### Historical PR #25 baseline

The original planning baseline is deliberately specific:

| Item | Recorded baseline |
| --- | --- |
| Native reference | `/usr/bin/codesign`, macOS 27.0 build 26A428, arm64 |
| Binary and manual identity | SHA-256 values in [spec/compatibility.json](../spec/compatibility.json) |
| Production feature baseline | [PR #25](https://github.com/deploymenttheory/go-macos-codesign/pull/25), tested commit `e3de6c447101e469211ded2d85fca11066391e20` |
| Merge into main | `4145fd27e7079e6e22ecea9279ecb1b4a6f1aaac` |
| Shared filesystem/DMG dependency | `github.com/deploymenttheory/go-apfs-v2 v0.4.0` |
| Compatibility checklist | 55 entries: 25 partial, 25 not implemented, five blocked, zero fully verified |
| Documented-option subtotal | 47 entries: 22 partial, 22 not implemented, three blocked |
| Additional capability subtotal | Eight entries: three partial, three not implemented, two blocked |

The [completed PR #25 workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35525819487)
establishes the following starting evidence. These numbers describe that commit,
not future changes or all native behavior:

| Runner | Library statements | CLI statements | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,923/4,098, 95.73% | 417/425, 98.12% | 1/1, 100% |
| Windows 2025 | 3,920/4,098, 95.66% | 417/425, 98.12% | 1/1, 100% |
| macOS 27 | 3,930/4,098, 95.90% | 423/425, 99.53% | 1/1, 100% |

The same run passed race detection, nine fuzz targets, six-target packaging,
354 imported signature verifications and 88 imported removal byte comparisons.
The artifact audit checked 567 source/fixture hashes per OS, twelve archive/SBOM
checksums, and all 169 Linux plus 169 Windows alias/allocation hashes against
the independently Apple-compared macOS outputs. The [lint run](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35525819499)
also passed.

<a id="merged-pr27"></a>
### Merged milestone: PR #27 (2026-09-20)

| Item | Delivered evidence |
| --- | --- |
| Merge into main | `c2461355e23b9cc7b65a01c0d380aa88dcdf0b14`, merged 2026-09-20 at 19:51 UTC |
| Tested PR head | `4f138a7e0a7a2a8fb20f08a6dc1c9c0ca5ca6129` |
| Tested CI merge | `533f1f20e7b1a792eb9a271963cf64fba05ca0e5`, with the same tree as the tested head |
| Shared metadata API | [APFS PR #102](https://github.com/deploymenttheory/go-apfs-v2/pull/102), released and pinned as [v0.5.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.5.0); no APFS replace or workspace requirement |
| D01 inventory | 47 documented plus 32 undocumented parser-recognized switches, each with seven operation cells; ten rejected binary-string candidates; `CODESIGN_ALLOCATE` recorded separately |
| Current compatibility checklist | 88 entries: the original 55 plus 32 switches and the environment hook; 25 partial, 55 not implemented, eight blocked, zero fully verified |
| D02 writer evidence | Nine complete Apple writer methods on two Clang targets; 126 native tree/inode cases and 15 macOS metadata profiles |
| First D04 implementation | Root-relative staged replacement of bundle main/nested Mach-O executables; external hard-link neighbours retain original bytes; existing CodeResources updates in place and unlinks on removal |

The [completed final workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35532899802)
and [lint workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35532899792)
passed for the tested head above. Coverage from the downloaded artifacts is:

| Runner | Library statements | CLI statements | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 3,972/4,161, 95.46% | 417/425, 98.12% | 1/1, 100% |
| Windows 2025 | 3,969/4,161, 95.39% | 417/425, 98.12% | 1/1, 100% |
| macOS 27 | 3,979/4,161, 95.63% | 423/425, 99.53% | 1/1, 100% |

All three producer jobs, six-target packaging, race detection and nine fuzz
targets passed. Apple verified all 522 imported signed artifacts, including 168
new writer archives; all 88 imported removal outputs matched native bytes. The
final audit checked 573 source/fixture hashes per OS, with only seventeen expected
Windows text conversions; twelve archive/SBOM checksums; and all six binaries'
APFS v0.5.0 dependency and disabled CGO. Each foreign producer's 126 writer-tree
hashes and 184 standalone/alias/allocation hashes matched hosted Apple-compared
outputs. These results apply to that tested commit, not future changes.

The first writer slice stages every executable before any bundle commit and
checks target identity before rename. Cancellation/preparation failures preserve
the original tree; later failures can leave earlier descendant/envelope commits
in place. At this milestone, native executable ACL inheritance and creation-time
behavior, new signature-directory security, stale signature-file cleanup, broader
permissions and non-cloning/compressed/protected files remained outstanding.
PR #30 subsequently delivered the regular-file cleanup profile below. The native
inventory records unavailable live-state contexts explicitly; it does not establish
complete operation applicability or resolve the private-parser source gap.

<a id="merged-pr30"></a>
### Merged milestones: PR #29 and PR #30 (2026-09-20)

[PR #29](https://github.com/deploymenttheory/go-macos-codesign/pull/29) merged the
plan update documenting PR #27 and APFS v0.5.0. It changed documentation only;
[PR #30](https://github.com/deploymenttheory/go-macos-codesign/pull/30) delivered
the next bounded D04/WP-02 implementation: regular stale signature-file cleanup.

| Item | Delivered evidence |
| --- | --- |
| PR #29 merge into main | `f0dcdca1b366ed7fe8a4db71c66338734bb407be`, merged at 20:23:55 UTC |
| PR #30 merge into main | `3ad9e15d300621ca3b935e62a7c68532d983c570`, merged at 20:59:17 UTC |
| Tested PR #30 head | `92f7b050003457d7f15793f2e84412a51af80422` |
| Tested CI merge | `0ae6276b5aa7a31c5094bb87694673508078bfba` |
| Audited source tree | `3c0305e7e7f0501c10d906f57d41ff8cb21ecc68`, shared by the tested head, CI merge and actual PR #30 merge |
| Shared dependency | APFS v0.5.0 retained; this slice required no additional upstream API or release |
| Native cleanup corpus | 105 complete tree comparisons across seven layouts, three architectures and five operations; eight directory/symlink profiles record explicit behavior differences |
| Expanded native-import gate | 606 signed artifacts, including 84 new cleaned bundle archives from Linux/Windows; all 88 existing removal comparisons retained |

The [completed PR #30 workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35536380623)
and [lint workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35536380625)
passed for the tested head above. Downloaded coverage artifacts report:

| Runner | Library statements | CLI statements | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 4,024/4,221, 95.33% | 417/425, 98.12% | 1/1, 100% |
| Windows 2025 | 4,021/4,221, 95.26% | 417/425, 98.12% | 1/1, 100% |
| macOS 27 | 4,031/4,221, 95.50% | 423/425, 99.53% | 1/1, 100% |

All three producer jobs, race detection, nine fuzz targets, six-target packaging
and independent Apple import verification passed. The final audit checked 575
source/fixture hashes per OS, with only seventeen expected Windows text conversions;
twelve archive/SBOM checksums; and all six clean, CGO-disabled binaries' APFS v0.5.0
dependency. Each foreign producer's 105 cleanup-tree hashes, 126 existing writer-tree
hashes and 184 standalone/alias/allocation hashes matched hosted Apple-compared
outputs. Apple verified all 606 signed imports and all 88 removal byte comparisons.
The final Windows tests capture file identity before unlinking, accounting for Go's
lazy Windows file-ID lookup. These results apply to the tested tree above.

Signing now excludes stale regular signature files from resource seals and purges
them after each rewritten main executable commits, keeping the new CodeResources.
Removal empties only the selected signature directory and retains the directory
itself; external hard-link neighbours, descendant signatures during outer removal
and dry-run contents are preserved. Unexpected signature files still fail verification.
At that milestone, non-regular entries retained early rejection: native sign/removal
could instead fail after replacement, and native dry runs could succeed. ACL
inheritance, creation time, new-directory security, broader permissions and failure-diagnostic parity remained
open at that milestone. PR #31 subsequently delivered the directory-stat profile
below, and PR #33 delivered bounded directory/symlink failure timing. The 88-entry
inventory and umbrella work-package statuses are unchanged.

<a id="merged-pr31"></a>
### Merged milestone: PR #31 (2026-09-21)

| Item | Delivered evidence |
| --- | --- |
| Merge into main | `f2af473a9fd2566bb24df5a5b04c9a1d06cbe9bd`, merged at 06:38:57 UTC |
| Tested PR head | `3555e32bd4e3e4a37517e0db20fe29438dce16d4` |
| Tested CI merge | `c2119fceea8373950ee21f1f5e16bb59ff8bb8fd` |
| Audited source tree | `bf44a92f3c47e8b7ed0c876312bd409dccb4c5de`, shared by the tested head, CI merge and actual PR #31 merge |
| Shared API and dependency | [APFS PR #104](https://github.com/deploymenttheory/go-apfs-v2/pull/104), released and pinned as [v0.6.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.6.0); no APFS replace or workspace requirement |
| D04 directory profile | Copy canonical bundle-root stat metadata only when creating `_CodeSignature`; selected physical framework roots, existing-directory preservation and explicit failure boundaries |
| Added evidence | 40 directory cases across eight layouts/selections and five operations; eight macOS security profiles; complete `copyfile_stat` AST evidence on both Clang targets |

The [completed PR #31 workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35568396303)
and [lint workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35568396248)
passed for the final head above. Downloaded coverage artifacts report:

| Runner | Library statements | CLI statements | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 4,049/4,252, 95.23% | 417/425, 98.12% | 1/1, 100% |
| Windows 2025 | 4,046/4,252, 95.16% | 417/425, 98.12% | 1/1, 100% |
| macOS 27 | 4,057/4,252, 95.41% | 423/425, 99.53% | 1/1, 100% |

All three producers, six-target packaging, race detection and nine fuzz targets
passed. The artifact audit checked 579 source/fixture hashes per OS, with only
seventeen expected Windows text conversions; twelve archive/SBOM checksums; and
all six clean, CGO-disabled binaries' APFS v0.6.0 dependency. Each foreign producer's
40 directory-tree hashes, 126 writer-tree hashes, 105 cleanup-tree hashes and 184
standalone/alias/allocation hashes matched independently Apple-compared macOS
outputs. Apple verified all 606 signed imports and all 88 removal byte comparisons.
The new metadata profiles add observations, not extra foreign signature archives.

New directories copy Unix ownership/modes/times, supported Darwin BSD flags or
ordinary Windows attributes/times through the shared API. Existing directories
retain their metadata; dry runs and removal do not create them. Source xattrs,
contents and explicit ACL entries are not copied. Native explicit-source-ACL
copying and subsequent envelope inheritance remain different, as do executable
ACL/birth-time behavior and broader permissions/failure ordering. Errors can leave
an empty or partially updated directory before its envelope/executable commit;
unit tests retain staging cleanup and cancellation guarantees. The inventory still
has zero fully verified entries; D04/WP-02 remains open beyond this bounded profile.

<a id="merged-pr33"></a>
### Merged milestones: PR #32 and PR #33 (2026-09-21)

[PR #32](https://github.com/deploymenttheory/go-macos-codesign/pull/32) merged the
documentation update for PR #31 and APFS v0.6.0 as
`90909a41ebfc2b5033ce20fb9457e4c961b382a9`.
[PR #33](https://github.com/deploymenttheory/go-macos-codesign/pull/33) then delivered
the next bounded D04/WP-02 implementation: stale-directory/symlink cleanup failures.

| Item | Delivered evidence |
| --- | --- |
| PR #33 merge into main | `d322e85441e5299e55d687212d79155195010fa1`, merged at 07:57:44 UTC |
| Tested PR head | `3a9049caf19fa43757db6668b3e141020c07c250` |
| Tested CI merge | `74fbd49b4bdbf7576ee687260586b7e18d249d87` |
| Audited source tree | `5ef9b10d47de8127d26c53b3eba74f87b176d33d`, shared by the tested head, CI merge and actual PR #33 merge |
| Shared dependency | Released APFS v0.6.0 retained; no new upstream API, release, replace or workspace requirement |
| Native failure corpus | 210 complete tree comparisons across seven layouts, five entry types and six operations on arm64, plus four nested child-failure/dry-run cases |
| Source evidence | Re-extracted writer AST retains every pinned source, SDK, excerpt, translation-unit and target result; its scope now records the added failure corpus |

The [completed PR #33 workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35573938808)
and [lint workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35573938782)
passed for the tested head above. Downloaded coverage artifacts report:

| Runner | Library statements | CLI statements | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 4,060/4,267, 95.15% | 417/425, 98.12% | 1/1, 100% |
| Windows 2025 | 4,057/4,267, 95.08% | 417/425, 98.12% | 1/1, 100% |
| macOS 27 | 4,068/4,267, 95.34% | 423/425, 99.53% | 1/1, 100% |

All three producer jobs, six-target packaging, race detection, nine 60-second fuzz
targets and independent Apple import verification passed. The final audit checked
579 source/fixture hashes per OS, with only seventeen expected Windows text
conversions; twelve archive/SBOM checksums; and all six clean, CGO-disabled binaries'
exact CI revision and APFS v0.6.0 dependency. Each foreign producer matched all
210 failure trees and four nested failure trees, including statuses and recorded
inode/neighbour effects. The 126 writer, 105 regular-cleanup, 40 directory and 184
standalone/alias/allocation hash comparisons per producer also passed. Apple
verified all 606 signed imports, including 168 writer and 84 cleanup archives,
and all 88 removal byte comparisons. Failed-operation cases add observations,
not signed imports. These results apply to the tested tree above.

Ordinary stale directories and symlinks are now rejected during cleanup after
executable replacement; dry-run signing preserves them and succeeds. Removal
deletes regular CodeResources before scanning stale entries. Child cleanup failure
retains its earlier commits and stops the parent commit. Verification, root
containment, internal write-alias rejection and staging cleanup remain enforced.
Non-regular envelopes, special files, unreadable subtrees and unsafe paths/aliases
can still fail early. Native named-component removal ordering beyond CodeResources,
multiple-entry enumeration order, broader permissions, exact diagnostics and the
remaining ACL/birth-time profiles stay open. D04/WP-02 remains open, and no status
in the 88-entry inventory is upgraded.

<a id="merged-pr34"></a>
### Merged milestone: PR #34 (2026-09-21)

| Item | Delivered evidence |
| --- | --- |
| Merge into main | `f4d7e284f5ce21deeae80890238d1344f155ce72`, merged at 09:22:55 UTC |
| Tested PR head | `eba869d93b7e802878007caf5e0301b29c348d38` |
| Tested CI merge | `efb8502d5ca33a2d089b6900b8bdcd26ab5b1dd2` |
| Audited source tree | `6eca03f7a8d77bebdb0b23cedf1389583782ef73`, shared by the tested head, CI merge and actual PR #34 merge |
| Dependency in the merged code | APFS v0.6.0 was pinned; the concurrency fix in merged APFS PR #106 was not yet consumed |
| Native ordering corpus | 278 complete tree comparisons across seven layouts, including named components, two hash-collision pairs, opposite creation orders and entries before CodeResources |
| Source evidence | Ten complete Apple writer methods plus `copyfile_stat` on both Clang targets, adding the complete `SecCodeSigner::Signer::remove` method |

The [completed PR #34 workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35581091931)
and [lint workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35581091975)
passed for the tested head above. Downloaded coverage artifacts report:

| Runner | Library statements | CLI statements | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 4,070/4,273, 95.25% | 417/425, 98.12% | 1/1, 100% |
| Windows 2025 | 4,067/4,273, 95.18% | 417/425, 98.12% | 1/1, 100% |
| macOS 27 | 4,077/4,273, 95.41% | 423/425, 99.53% | 1/1, 100% |

All three producers, six-target packaging, race detection, nine fuzz targets and
independent Apple import verification passed. The artifact audit checked 580
source/fixture hashes per OS, with seventeen expected Windows text conversions;
twelve archive/SBOM checksums; and six clean, CGO-disabled binaries with the
exact CI revision and provisional APFS v0.6.0 dependency. Each foreign producer's
278 new trees, survivor sets, exit statuses and recorded inode/neighbour effects
matched independent native outputs. The previous 126 writer, 105 regular-cleanup,
40 directory, 214 failure and 184 standalone/alias/allocation comparisons per
producer remain intact. Apple verified all 606 signed imports and 88 removal byte
comparisons. Failed-operation cases do not add signed import artifacts.

Cleanup now follows case-insensitive APFS ASCII name-hash order, using folded
name comparisons on collisions, and stops at the first non-regular entry.
CodeResources participates in that order during removal; an earlier failure can
retain it. A non-regular removal envelope is rejected after executable replacement
when reached. Signing retains early envelope validation. These results supersede
PR #33's CodeResources-first assumption, preserving containment, bounds, internal
write-alias checks, dry runs, strict verification and partial-purge cancellation.

APFS PR #106 merged as `1989afea6a0de3cbfe99930f20ec24b420666db9` at 09:02:26 UTC.
Its tested head `0820e44cd0e095bf51932359bc42431e495a357a` passed the
[upstream workflow](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/35580019373),
including a fresh-process regression that reproduced the old first-use race.
Release Please [PR #107](https://github.com/deploymenttheory/go-apfs-v2/pull/107)
passed its [CI](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/35581097944)
and merged as `3210dbb112d180d5a53232daaaee0752c06d62a3` at 09:27:21 UTC.
[v0.6.1](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.6.1) was
published at 09:27:31 UTC and contains the tested fix. PR #35 subsequently pinned
that release and passed its own final CI and artifact audit, recorded below;
PR #34's evidence above still describes v0.6.0.
Other filesystem orders, non-regular signing envelopes, broader permissions and
diagnostics, executable ACL/birth-time behavior and explicit directory ACL copying
remain open. D04/WP-02 and the 88-entry inventory retain their partial status.

<a id="merged-pr35"></a>
### Merged milestone: PR #35 (2026-09-21)

| Item | Delivered evidence |
| --- | --- |
| Merge into main | `0457f52db4bbce4b55de8dc1564b5040923e4f54`, merged at 09:54:59 UTC |
| Tested PR head | `14d14a6d254f5ef9fa08b9f135087bc39fa8c469` |
| Tested CI merge | `30edbbaa3da7c525bbbb2ff5bfea22144b8aa1e3` |
| Audited source tree | `395520d539c54d79bd70f783345190f0ebdd82fe`, shared by the tested head, CI merge and actual PR #35 merge |
| Released dependency | APFS v0.6.1, containing PR #106's concurrent name-hash initialization fix, published through release PR #107 |
| Integration | Released module and checksums; no APFS replace or development workspace |

The [completed final PR #35 workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35584561129)
and [lint workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35584561149)
passed for the tested head above, including its README update. Downloaded coverage
artifacts report:

| Runner | Library statements | CLI statements | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 4,070/4,273, 95.25% | 417/425, 98.12% | 1/1, 100% |
| Windows 2025 | 4,067/4,273, 95.18% | 417/425, 98.12% | 1/1, 100% |
| macOS 27 | 4,077/4,273, 95.41% | 423/425, 99.53% | 1/1, 100% |

All three producers, six-target packaging, race detection, nine fuzz targets and
independent Apple import verification passed. The final artifact audit checked
580 source/fixture hashes per OS, with seventeen expected Windows text
conversions; twelve archive/SBOM checksums; and all six clean, CGO-disabled
binaries' exact CI revision and APFS v0.6.1 dependency. Each archive contained
the audited binary and final README. A local fresh-process race regression also
passed directly against the released APFS module.

Each foreign producer's 278 ordering cases matched the independent native trees,
survivor sets, exit statuses and recorded inode/neighbour effects. The previous
126 writer, 105 regular-cleanup, 40 directory, 214 failure and 184
standalone/alias/allocation comparisons per producer remained intact. Apple
verified all 606 signed imports and 88 removal byte comparisons.

This closes the released-dependency integration gate for the merged ordering
profile. It does not close D04/WP-02 or change any of the 88 inventory statuses.
Executable ACL/birth-time behavior, explicit directory ACL copying, non-regular
signing envelopes and wider filesystem/permission failures remain outstanding.

<a id="merged-pr37"></a>
### Merged milestones: PR #36 and PR #37 (2026-09-21)

[PR #36](https://github.com/deploymenttheory/go-macos-codesign/pull/36) updates the
plan for PR #35. [PR #37](https://github.com/deploymenttheory/go-macos-codesign/pull/37)
delivers the bounded D04/WP-02 signing-envelope directory/permission profile.

| Item | Delivered evidence |
| --- | --- |
| PR #36 merge into main | `17ab8d54c387ac4a644ce9a88d7c65c7bfe684d2` |
| PR #37 merge into main | `83e8f895f13180aed3cf4f315f86dc53a92f379d` |
| Tested PR #37 head | `4b76b3a4ebaac8897c862f7ef140c3afbf9b317c` |
| Tested CI merge | `6cfb19a5bfc21409fabe20c19f6fdc0c54bf2665` |
| Audited source tree | `4e3967849fe2633ec11a09eac4b91a1d9c7ee45d`, shared by the tested head, CI merge and actual PR #37 merge |
| Released dependency | APFS v0.6.1 retained; no upstream change or release required |
| Added native corpus | 84 envelope-directory cases across seven layouts, 20 nested commit-order cases and 20 POSIX permission cases |
| Native references | Local macOS 27.0 build 26A428 and hosted macOS 27.0 build 26A5406e; separate binary identities recorded in the audit |

The [final PR #37 workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35592781111)
and [lint workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35592781286)
passed. Downloaded coverage artifacts report:

| Runner | Library statements | CLI statements | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 4,074/4,276, 95.28% | 417/425, 98.12% | 1/1, 100% |
| Windows 2025 | 4,070/4,276, 95.18% | 417/425, 98.12% | 1/1, 100% |
| macOS 27 | 4,081/4,276, 95.44% | 423/425, 99.53% | 1/1, 100% |

All three producers, six-target packaging, race detection and nine fuzz targets
passed. The audit checked 582 source/fixture hashes per OS, seventeen expected
Windows text conversions, twelve archive/SBOM checksums and six clean, CGO-disabled
binaries with the exact CI revision and APFS v0.6.1. Archives match the audited
binaries and README. Linux matched all 124 new native cases; Windows matched 104
and explicitly skipped the 20 POSIX mode-bit cases. The existing writer, cleanup,
directory, failure, ordering and standalone comparisons passed, as did Apple's
606 signed-import verifications and 88 removal byte comparisons.

Envelope-directory rejection occurs before the affected executable commits;
earlier child commits survive. Signing and removal avoid unused old child-envelope
reads; verification retains required reads and limits. Bounded traversal, internal
alias checks, early signing-symlink rejection and staging cleanup remain enforced.
These filesystem observations add no signed-import archives and do not close
D04/WP-02 or change the 88 inventory statuses.

<a id="merged-pr39"></a>
### Merged milestone: PR #39 (2026-09-21)

Darwin bundle executables receive a new creation time capped by their source
modification time. Dry runs, external hard-link neighbours, existing envelopes and
untouched descendants retain their creation times. Failure or cancellation during
preparation preserves originals and removes staging. The 210 native comparisons cover seven
layouts, three architectures, past/future modification times and five operations.

| Item | Verified evidence |
| --- | --- |
| Merge into main | `448c4090eda0afc63b8f8def3e671dd85f712e8f`, merged at 13:06:34 UTC |
| Tested PR head | `14ae93a0b109adb14aa690ae9c79020fbb101b1b` |
| Tested CI merge | `692e32a09d7dfce22ea10d0941c2d523beda18b4` |
| Audited source tree | `3c7cc8547af213f08a3957ebf89cb7983cb9ddd4`, shared by the tested head, CI merge and actual merge |
| Released dependency | [APFS PR #108](https://github.com/deploymenttheory/go-apfs-v2/pull/108), consumed as [v0.7.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.7.0); no local replace/workspace |

The [final workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35601272902)
and [lint workflow](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/35601273069)
passed. Downloaded coverage artifacts report:

| Runner | Library statements | CLI statements | Entry point |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 4,078/4,281, 95.26% | 417/425, 98.12% | 1/1, 100% |
| Windows 2025 | 4,074/4,281, 95.16% | 417/425, 98.12% | 1/1, 100% |
| macOS 27 | 4,087/4,281, 95.47% | 423/425, 99.53% | 1/1, 100% |

All three producers, six-target packaging, race detection and nine fuzz targets
passed. The audit matched 584 source/fixture hashes per OS, allowing seventeen
expected Windows text conversions, and checked twelve archive/SBOM checksums.
All six CGO-disabled binaries contain APFS v0.7.0 and the exact CI revision;
archives match those binaries and the README. The existing writer matrices,
606 Apple-verified signed imports and 88 removal comparisons passed.

Local release-backed verification and lint passed, with the native suite using a
twenty-minute test timeout after exceeding the default ten minutes. Local macOS
27.0 build 26A428 and hosted build 26A5406e retain separate native binary identities
in their provenance. Both Clang targets record the creation-time attribute and
timestamp layout. Linux/Windows retain their existing replacement metadata policy;
this Darwin-only corpus adds no import archives. ACL/access-time and wider filesystem
profiles remain open, with no D04/WP-02 or inventory status upgrade.

### Completion criteria

Completion has several separate meanings:

1. **Implemented:** production code handles a precisely documented input and
   operation profile. Merely recognizing an option is insufficient.
2. **Independently verified:** native tools or independent reference encoders
   establish the expected behavior; tests do not generate both sides with our code.
3. **Portable:** execution succeeds on the three producer operating systems;
   cross-compilation alone does not establish execution or filesystem behavior.
4. **Feature equivalent:** the feature's supported native inputs, defaults,
   failures, interactions and observable side effects have a completed matrix.
5. **Full equivalent:** every inventory entry and subsequently discovered native
   behavior is resolved, including host-state blockers. A supported-subset release
   does not satisfy this final condition.

Statement coverage above 95% is required in every production package. It is not a
percentage of Apple's functionality implemented. Neither the historical 55-entry
count nor the current 88-entry count is a useful completion-percentage denominator;
the obligations have unequal scope.

## 2. Non-negotiable implementation boundaries

- Keep Cobra and Viper. Native option semantics must remain independent of ambient
  Viper configuration; portable extensions need explicit documentation.
- Keep production pure Go. Audit the complete dependency graph on Darwin,
  Linux and Windows. `CGO_ENABLED=0` alone does not prove absence of Apple bridges.
- Retain the current production guard against `crypto/x509`, `crypto/tls`,
  `net/http`, subprocess helpers, native binding directives and direct raw syscalls.
  A future networking or cryptography dependency must pass that audit; no quiet
  exception is part of this plan. Test-only independent oracles remain separate.
- Reuse APFS `pkg/disk` for disk-image structure and APFS `pkg/hostmeta` for host
  metadata operations. Put missing general filesystem/image functionality into
  the APFS project, expose a documented public API, release it, then consume it.
  Do not copy its implementation into codesign or import another repository's
  `internal` package.
- Ordinary host filesystem I/O through supported Go/x/sys wrappers is compatible
  with this boundary. Security.framework, CoreFoundation execution and invoking
  Apple's signing services are not production fallbacks.
- Keep GoReleaser for builds, archives and SBOM generation. Existing Python
  verification/research orchestration is not a replacement production build system;
  new research drivers should follow the existing Go-driver pattern.
- Use golangci-lint for Go linting. Do not reintroduce Super-Linter.
- Preserve bounded parsing and explicit errors. Do not copy observed native
  memory corruption, unsafe pointer behavior or unbounded resource consumption.
  Record safe divergences honestly; they prevent an unconditional parity claim.
- Preserve byte APIs' ownership contracts: inputs remain unchanged and callers
  own returned data. Newly introduced streaming APIs must state lifetime and
  concurrency contracts.
- Do not change existing explicit-trust library APIs into weaker verification
  silently. Native-compatible validation and optional trust policies need distinct
  result semantics and a migration plan where behavior changes.

## 3. Work-package map and delivery order

Work-package IDs are stable references, not estimates of equal effort. Each
package below contains implementation tasks, independent acceptance and an exit
condition. Dependencies can be delivered incrementally; unresolved portions must
remain visible instead of holding unrelated portable work indefinitely.

| ID | Work package | Main prerequisite or boundary |
| --- | --- | --- |
| [WP-01](#wp-01) | Native baseline, source/AST research and complete option inventory | Start first; continue throughout |
| [WP-02](#wp-02) | Bundle file replacement and wider metadata preservation | APFS public API, native writer probes |
| [WP-03](#wp-03) | Bundle discovery, paths and layout coverage | Path identity and containment contract |
| [WP-04](#wp-04) | Resource policy, xattrs and strict verification | WP-02/WP-03; shared APFS metadata APIs |
| [WP-05](#wp-05) | Signature metadata preservation and signing-option semantics | Existing signature readers; WP-07/WP-08/WP-09 as needed |
| [WP-06](#wp-06) | Mach-O allocation, architecture and removal coverage | Native allocation evidence; streaming work for large offsets |
| [WP-07](#wp-07) | CodeDirectory versions, digest selection and special slots | WP-06; CMS and nested-code integration |
| [WP-08](#wp-08) | Entitlement representation and option equivalence | Typed plist/DER evidence |
| [WP-09](#wp-09) | Complete requirements compiler, decoder, formatter and evaluator | Certificate/constraint/notarization contexts where predicates require them |
| [WP-10](#wp-10) | Certificate validation and native verification semantics | WP-09/WP-12 interfaces; explicit policy separation |
| [WP-11](#wp-11) | Identity formats and provider selection | Existing signer interface; host-state boundary |
| [WP-12](#wp-12) | CMS representations and signature algorithms | WP-07/WP-11; independent crypto verification |
| [WP-13](#wp-13) | Timestamp compatibility and transport policy | WP-10/WP-12 and portable transport audit |
| [WP-14](#wp-14) | Launch/library constraints and validation | Typed plist/DER plus WP-07 special-slot binding |
| [WP-15](#wp-15) | Native detached signature files | Representation dispatch, architecture IDs and external data |
| [WP-16](#wp-16) | Generic/xattr signatures and other native representations | WP-15 and APFS xattr support |
| [WP-17](#wp-17) | Wider DMG representations and streaming signing | APFS format APIs and WP-21 |
| [WP-18](#wp-18) | Hybrid/PQC signatures, signature slots and detached certificates | Native fixtures, WP-07/WP-11/WP-12 |
| [WP-19](#wp-19) | Notarization ticket checking | Native protocol/policy evidence and portable authenticated transport |
| [WP-20](#wp-20) | Complete CLI, extraction, diagnostics and display behavior | Incremental integration with every work package |
| [WP-21](#wp-21) | Streaming, limits, cancellation and resource accounting | Cross-cutting; start before widening allocation/DMG limits |
| [WP-22](#wp-22) | Live macOS state and non-exportable identity blockers | Feasibility investigation now; actual state/key access required |
| [WP-23](#wp-23) | Differential acceptance, portability, CI and distribution evidence | Continuous gate, not a final testing phase |
| [WP-24](#wp-24) | Documentation, inventory maintenance and full-parity audit | Continuous updates; final closure after all relevant gates |

Recommended sequence:

1. Establish WP-01's expanded inventory and WP-22's access constraints. Maintain
   WP-23/WP-24 continuously so the goal cannot shrink silently.
2. Complete bundle writer behavior, path/layout coverage and resource/xattr policy
   in WP-02 through WP-04. Deliver small native-proven profiles, not one large
   filesystem rewrite.
3. Add WP-05 preservation, useful WP-20 extraction/reporting options and WP-21
   interfaces. These improve everyday re-signing without waiting for PQC.
4. Widen Mach-O and CodeDirectory forms, entitlements and requirements in WP-06
   through WP-09. Implement pure grammar/encoding portions before predicates that
   require trust or remote state.
5. Extend identities/CMS, then native validation and timestamp policy in WP-11,
   WP-12, WP-10 and WP-13. Resolve circular integration incrementally through
   explicit format and policy interfaces rather than mutual package dependencies.
6. Deliver constraints, native detached signatures, generic representations and
   wider DMGs in WP-14 through WP-17.
7. Deliver WP-18 and WP-19 once algorithms, formats, credentials and service
   behavior are evidenced. Do not postpone their discovery/fixture work until then.
8. Complete remaining CLI interactions and final audits. WP-22 remains a blocker
   for full equivalence unless its inputs/access constraints are actually resolved.

No calendar estimate is assigned to private-format, credential-dependent or
host-state work before investigation. Each implementation PR should identify a
bounded observable behavior, its tests, remaining exclusions and dependent APFS PR.

## 4. Traceability for every existing inventory entry

Statuses below are copied from the PR #25 baseline. They are not upgraded by this
plan. The work-package column maps every existing entry to remaining work.

| Inventory entry | Baseline | Work packages and remaining obligation |
| --- | --- | --- |
| `--all-architectures` | partial | WP-06/WP-07/WP-20: precedence with architecture selection, every slice and damaged unselected slices |
| `--architecture` | partial | WP-06/WP-20: names, numeric CPU/subtypes, host defaults, invalid/missing slices and non-Mach-O applicability |
| `--bundle-version` | partial | WP-03/WP-04/WP-20: wider version layouts, malformed selectors, operation and nested-version interactions |
| `--check-notarization` | not-implemented | WP-19: authenticated forced online ticket lookup, failures and native diagnostics |
| `--display` | partial | WP-20 plus each format owner: complete metadata, extraction, architecture/slot selection and damaged signatures |
| `--detached` | not-implemented | WP-15: native detached container creation, reading, validation and extraction |
| `--deep` | partial | WP-03/WP-04/WP-09: wider nested layouts, alternate directories/digests, preservation and validation policy |
| `--detached-database` | blocked | WP-22: actual native system database state/access; offline file support is not equivalence |
| `--input-detached-certificates` | not-implemented | WP-18: native certificate interchange input and signature linkage |
| `--output-detached-certificates` | not-implemented | WP-18: native interchange output, ordering and omission rules |
| `--keep-root-detached-certificates` | not-implemented | WP-18: root classification, inclusion and merge interaction |
| `--merge-detached-certificates` | not-implemented | WP-18/WP-20: standalone merge operation, repeated inputs, deduplication and output behavior |
| `--use-software-signing-cert` | not-implemented | WP-01/WP-10/WP-20: establish documented software-update validation policy and operation interactions; identity-provider or hybrid behavior is unproven |
| `--force` | partial | WP-05/WP-20: preservation, linker-signed inputs, nested signatures and invalid old metadata |
| `--force-library-entitlements` | partial | WP-08: all applicable file types and conflict/default behavior |
| `--generate-entitlement-der` | partial | WP-08/WP-20: confirm baseline no-op/deprecation behavior and XML/DER combinations |
| `--hosting` | blocked | WP-22: live process hosting chain, validity and authorization |
| `--identifier` | partial | WP-05/WP-20: embedded metadata defaults, Unicode/case/path rules, empty/duplicate options and formats |
| `--options` | partial | WP-05/WP-07/WP-20: complete flags, numeric masks, applicability, preservation and conflicts |
| `--pagesize` | partial | WP-06/WP-07/WP-17: boundaries, architecture/image defaults and interaction with CodeDirectory forms |
| `--remove-signature` | partial | WP-02/WP-06/WP-15/WP-16: writer side effects, legacy layouts and additional signature representations |
| `--requirements` | partial | WP-09/WP-20: complete source/binary forms, all requirement types and display/extraction |
| `--test-requirement` | partial | WP-09/WP-10/WP-20: complete evaluation contexts, trust predicates and error behavior |
| `--sign` | partial | WP-02 through WP-19 as applicable: format, identity, metadata, policy and complete operation matrix |
| `--verbose` | partial | WP-20: all levels, overloaded short syntax, localization and channels |
| `--verify` | partial | WP-04/WP-07/WP-09/WP-10/WP-13/WP-19/WP-22: validation, policy, representations and process targets |
| `--continue` | partial | WP-20: mixed success/failure targets, output ordering, aggregate exit status and write preservation |
| `--dryrun` | partial | WP-02/WP-05/WP-13/WP-20: all write forms, identity/TSA effects and failures |
| `--entitlements` | partial | WP-08/WP-20: full typed input/output, missing slots and failure behavior |
| `--enforce-constraint-validity` | not-implemented | WP-14: strict constraint validation during signing and default warning behavior |
| `--extract-certificates` | not-implemented | WP-20/WP-12/WP-18: chain order, DER bytes, filenames and multiple signatures |
| `--file-list` | not-implemented | WP-20/WP-02/WP-04: accurate reported files for signing and display, append/overwrite/failure semantics |
| `--ignore-resources` | not-implemented | WP-04: native scope of resource suppression without bypassing executable integrity |
| `--keychain` | blocked | WP-22/WP-11: native identity lookup, search lists, preferences and authorization |
| `--prefix` | not-implemented | WP-05/WP-20: native identifier-prefix rules for each default/explicit identifier source |
| `--preserve-metadata` | not-implemented | WP-05: signature fields, abbreviations, override precedence and linker-signed exception |
| `--strict` | not-implemented | WP-04/WP-20: supported strictness selectors, all/default behavior and diagnostics |
| `--timestamp` | partial | WP-13: native defaults, transport, TSA policy and error/output interactions |
| `--runtime-version` | partial | WP-05/WP-07/WP-20: derivation, boundaries, preservation and architecture/platform defaults |
| `--launch-constraint-self` | not-implemented | WP-14: native serialization, binding and validation |
| `--launch-constraint-parent` | not-implemented | WP-14: native serialization, binding and validation |
| `--launch-constraint-responsible` | not-implemented | WP-14: native serialization, binding and validation |
| `--library-constraint` | not-implemented | WP-14: library constraint encoding, signing and inspection |
| `--strip-disallowed-xattrs` | not-implemented | WP-04/WP-02: native disallowed-attribute policy, shared metadata mutation and preservation |
| `--single-threaded-signing` | not-implemented | WP-04/WP-20: resource-seal scheduling contract and identical results |
| `--validate-constraint` | not-implemented | WP-14/WP-20: separate operation, typed schema, known keys and optional extensions |
| `--signature-slot` | not-implemented | WP-18/WP-20: native slot numbering, default preference and selected verification/display |
| `certificate-signing` | partial | WP-09 through WP-13/WP-18: formats, algorithms, native policy and real credential evidence |
| `bundles` | partial | WP-02/WP-03/WP-04/WP-09/WP-21: layout, resources, metadata, requirements and limits |
| `dmg` | partial | WP-17/WP-07/WP-13/WP-19: APFS-backed representations, digests, timestamps and ticket policy |
| `hybrid-pqc` | not-implemented | WP-18: complete evidenced native algorithms, combined signatures and interchange |
| `generic-files` | not-implemented | WP-16: native non-Mach-O/xattr representations |
| `legacy-formats` | not-implemented | WP-06/WP-07/WP-12: native-supported old architectures, digests and signature structures |
| `live-process-verification` | blocked | WP-22: actual process/kernel state and dynamic validity |
| `hardware-identities` | blocked | WP-22/WP-11/WP-18: access to the original non-exportable key/device/service |

The table above preserves the original 55-entry inventory and its statuses.
PR #27 added 32 directly observed undocumented switches plus `CODESIGN_ALLOCATE`;
all 33 additions remain in the [machine-readable inventory](../spec/compatibility.json)
and [native operation record](../spec/apple-cli-inventory.json). WP-01/WP-20 own
further applicability/semantic research and assignment to the relevant format or
policy work package; option names alone do not establish a contract. WP-22 owns
the added `--remote-signing`, `--signing-dylib` and allocator-hook blockers.
The allocator and signing-library execution conflicts with the no-helper boundary
are recorded, not resolved. The current total is 88; none of the new entries is verified.

<a id="wp-01"></a>
## WP-01: Native baseline, source research and inventory closure

**Current state after PR #39:** the expanded inventory and writer AST are merged.
The writer record contains ten complete methods plus `copyfile_stat` and SDK flag
values on both Clang targets. Its twelve constants include the creation-time
attribute and timestamp layout; its scope includes signing-envelope failures and
the 210 creation-time comparisons, against the same pinned source.
[Native inventory](native-inventory.md) describes the
pinned host profile, parser-only evidence, unavailable operation contexts and the missing
current parser source. Full semantics, ignored-option behavior, wider fixtures
and later-discovered options remain open.

**Delivered in PR #27:**

- [x] Record the D01 oracle's OS/build, architecture, locale/timezone, filesystem,
  case sensitivity and binary/manual/fixture/driver hashes.
- [x] Record 79 recognized switches and ten rejected candidates, retaining all
  55 original obligations and adding 33 to the compatibility inventory.
- [x] Populate seven operation cells per option with bounded probes or explicit
  unavailable contexts; retain argv, outputs, exit/signal and before/after hashes.
- [x] Extend writer research to nine complete methods on both targets, with
  source/excerpt/translation-unit/SDK-header hashes and explicit private shims.
  Keep missing current-parser source and observed source/native differences visible.

**Remaining research and continuing maintenance:**

- [ ] Record host OS/build, architecture, locale, timezone, filesystem type,
  case sensitivity, native binary hash and installed manual hash for each oracle.
- [ ] Extend the merged enumeration with further manual/parser/SDK evidence and
  binary-visible option names. Use isolated probes to distinguish
  accepted options, ignored options, aliases, deprecated forms and unknown switches.
- [ ] Create a complete applicability table for sign, verify, display, remove,
  hosting, constraint validation and detached-certificate merging. Include options
  accepted but ignored for particular operations.
- [ ] Inventory undocumented features only after direct evidence. Candidate names
  found in older source, such as digest selection or resource-rule options, are
  research leads rather than promises that the current binary supports them.
- [ ] Expand Clang extraction to complete relevant C/C++/Objective-C function bodies,
  enums, constants and control flow on arm64 and x86_64 targets. Pin source,
  excerpt, translation-unit and relevant SDK-header hashes.
- [ ] Record private declarations/macros that need shims, excluded preprocessor
  branches and unavailable source. Do not infer struct wire encoding from a shim.
- [ ] Compare source-derived expectations with the installed binary. Retain the
  discrepancy and version it when published source lags the host.
- [ ] Use independent GitHub references for design and cross-checking; inspect
  licenses and transitive dependencies before any reuse. Pin newly used revisions.
- [ ] Add newly discovered native behavior to the machine-readable inventory;
  retain the original entries and their meaning rather than narrowing them to pass.

**Acceptance and exit:** every documented option is mapped; every discovered
undocumented option has an observed applicability/status record; each claimed
source fact has reproducible provenance; unresolved private behavior remains
explicit. Existing full-parity guards continue to fail until the actual gaps close.

**Touchpoints:** [spec](../spec/), [research drivers](../scripts/),
[research guide](research.md), [reference review](reference-implementations.md),
[CLI parser](../internal/cli/cli.go).

<a id="wp-02"></a>
## WP-02: Bundle writes and wider filesystem metadata preservation

**Current state after PR #39:** standalone Mach-O uses APFS `PrepareReplacement`;
bundle main/nested Mach-O uses `PrepareReplacementAt` under an opened `os.Root`.
Both detach the selected hard-link name. DMGs and existing CodeResources retain
in-place updates. Signing purges stale regular signature files after each rewritten
main executable, keeping CodeResources; successful removal empties only the selected signature
directory and retains it. Stale directories/symlinks now fail at cleanup after
executable replacement; dry runs preserve them and succeed. Child cleanup failure
stops the parent commit. Cleanup uses APFS ASCII hash/collision order; non-regular
removal envelopes fail when reached after executable replacement. Signing rejects
envelope directories at the envelope write before the affected executable commits;
earlier child commits survive. Signing/removal skip unused old child-envelope reads,
while verification retains required reads and limits. Released APFS v0.7.0 supplies
the shared APIs, name-hash race fix and explicit creation-time setter. Darwin
bundle executables receive a new creation time capped by source modification time;
standalone replacement retains its source creation time. New signature directories
copy canonical-root stat metadata; existing directories retain theirs. Explicit
source ACL copying remains outside that profile. Internal write-target hard links
and symlinked signing envelopes remain rejected.

**Delivered in PR #27 and APFS PR #102/v0.5.0:**

- [x] Add 126 native tree/inode cases across seven layouts, three architectures and
  six operations; include nested executables, external executable/envelope links,
  new/existing envelopes, unsigned removal and dry runs.
- [x] Add fifteen macOS metadata profiles for signing, read-only executables,
  re-signing, removal and dry runs; record ACL inheritance, xattrs, flags and stat
  observations, including native ACL/creation-time differences.
- [x] Release and consume shared root-relative staging and metadata restoration
  with explicit source/root/file lifetimes and caller-owned rename decisions.
  Preserve containment without an APFS local replacement or copied platform code.
- [x] Stage all executable replacements before bundle commits. Test cancellation,
  preparation failure, changed targets and cleanup after partial commits; document
  descendant-first commits with each envelope preceding its main executable.

**Delivered in PR #30:**

- [x] Purge stale regular signature files after each rewritten main executable;
  preserve the new CodeResources on signing and empty the selected directory on
  removal. Retain external hard-link neighbours, descendant signatures on outer
  removal, dry-run contents and rejection of unexpected files during verification.
- [x] Add 105 native cleanup tree cases across seven layouts, three architectures
  and five operations, eight non-regular rejection profiles, and unit checks for
  cancellation, partial commits, root containment and internal write aliases.
  Export another 42 cleaned archives per foreign producer for native verification.
  See [merged validation](#merged-pr30) and [file-write evidence and limits](file-writes.md).
- [x] Pass final Linux/macOS/Windows execution and native-import gates, retaining
  verification policy and early rejection of non-regular entries. Capture Windows
  file identity before unlinking and reject case-variant CodeResources names.

**Delivered in PR #31 and APFS PR #104/v0.6.0:**

- [x] Copy stat metadata only into newly created signature directories, using held
  source/target handles and the selected physical root for versioned frameworks.
  Retain existing-directory metadata and no-creation behavior for dry runs/removal.
- [x] Add 40 directory cases, eight native security profiles and unit tests for
  held roots, cancellation, pre-commit metadata failure and staging cleanup.
  Record explicit ACL copying and subsequent envelope inheritance as differences.
- [x] Parse complete `copyfile_stat` source on both targets with pinned flag masks
  and SDK constants; keep private state/helper interfaces explicit as shims.
- [x] Release/pin the shared API and pass the final three-OS, package, race/fuzz and
  native-import gates. Audit the actual merged source tree and retain the existing
  606-import/88-removal gate. See [merged validation](#merged-pr31).

**Delivered in PR #33:**

- [x] Defer stale directory/symlink rejection until cleanup after executable commit;
  exclude them from resource seals, retain dry-run trees and strict verification.
- [x] Remove the regular CodeResources component before the removal stale scan
  for the original one-stale-entry corpus. The follow-up below supersedes this
  implementation assumption for multiple entries. Keep rejected entries, link
  targets and external hard-link neighbours intact.
- [x] Expand the original eight observations into 210 complete native comparisons:
  seven layouts, five entry types and six operations; add four nested child-failure
  cases proving earlier child commits survive and the parent remains unchanged.
- [x] Retain bounded metadata traversal/internal alias rejection, cancellation and
  staging cleanup; cover aliases hidden inside stale directories and changed
  non-regular envelopes. Reuse APFS v0.6.0 without an upstream API change.
- [x] Pass final three-OS execution/coverage, packaging, race/fuzz and native-import
  gates. Audit the final artifacts and confirm that the actual merge shares the
  tested source tree. See [merged validation](#merged-pr33).

At PR #33, this was a bounded failure-timing profile. Named-component and
multiple-entry ordering remained open, and non-regular envelopes could fail early.
PR #34 subsequently delivers the ordering/removal-envelope behavior below;
broader permissions, raw diagnostics, special files, unreadable subtrees and
unsafe names/aliases remain outside the claim.
The final validation and artifact audit are complete for PR #33's tested tree.
The 88-entry inventory and existing 606-import/88-removal gate remain unchanged.

**Delivered in PR #34 and PR #35, with APFS PR #106/v0.6.1:**

- [x] Establish native case-insensitive APFS ASCII enumeration order, including
  equal-hash names of different case/length and opposite creation orders.
- [x] Parse complete `SecCodeSigner::Signer::remove` on both Clang targets. The
  Mach-O path calls allocate/commit and flushes directly; generic removal alone
  invokes the canonical-slot loop. CodeResources has no special removal priority.
- [x] Implement bounded ordered cleanup through APFS's public hash/comparison API.
  Reject non-regular removal envelopes when reached after executable replacement;
  retain early signing validation, containment, bounds and write-alias rejection.
- [x] Add 278 native tree comparisons across seven layouts, with cancellation and
  entry-limit unit tests. Retain all merged writer/metadata/failure corpora.
- [x] Pass the three-OS, packaging, race/fuzz and native-import gates on PR #34's
  tested tree; audit its artifacts and confirm the actual merge has the same tree.
  These binaries still use APFS v0.6.0. See [merged evidence](#merged-pr34).
- [x] Merge [APFS PR #106](https://github.com/deploymenttheory/go-apfs-v2/pull/106)
  as `1989afea6a0de3cbfe99930f20ec24b420666db9`. The APFS
  regression reproduces the old race in a fresh process and passes after the fix.
  Upstream head `0820e44cd0e095bf51932359bc42431e495a357a` passed its
  [final PR workflow](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/35580019373):
  three-OS unit/acceptance execution, the first-use race regression and six builds.
- [x] Publish v0.6.1 through [APFS release PR #107](https://github.com/deploymenttheory/go-apfs-v2/pull/107)
  and replace codesign's provisional v0.6.0 pin in merged PR #35.
- [x] Complete final codesign three-OS execution/coverage, package, race/fuzz,
  606-import/88-removal and actual-final-commit artifact audit after the release pin.
  Confirm PR #35's actual merge shares that audited tree. See [merged evidence](#merged-pr35).

**Delivered in PR #37:**

- [x] Compare empty/populated signing-envelope directories across seven layouts:
  84 native trees cover first signing, re-signing, signed/unsigned dry runs,
  no-force rejection and verification. Affected executables stay intact while
  earlier child commits survive; the directory and stale sidecars remain.
- [x] Add 20 nested parent/child cases covering earlier sibling commits, shallow
  signing, dry runs and outer-only removal. Defer directory rejection to the
  envelope write while retaining bounded traversal and internal alias checks.
- [x] Avoid reading old child envelopes when signing or removing signatures.
  Keep required verification reads and limits. Twenty POSIX permission cases
  compare read-only/write-only parent and child envelopes; Windows explicitly
  skips this mode-bit profile. Successful deep rewrites pass native verification.
- [x] Retain early rejection of signing-envelope symlinks, including outside and
  dangling targets. Native probes may mutate their targets; reproducing that
  behavior would violate the existing containment/no-follow boundary.
- [x] Pass final three-OS coverage, packaging, race/fuzz, 606-import/88-removal
  gates and the final-commit artifact audit. Confirm the actual merge shares the
  audited tree. APFS v0.6.1 remains the released pin. See [merged evidence](#merged-pr37).

Other filesystem orders, signing-envelope symlinks, special files, broader
permission/ACL failures, raw diagnostics and explicit directory ACL copying
remain open alongside executable ACL inheritance and access-time behavior.

**Delivered in PR #39, with APFS PR #108/v0.7.0:**

- [x] Establish Darwin APFS behavior with 210 native comparisons: seven layouts,
  three architectures, past/future modification times and five operations.
  Rewritten executables receive a new creation time capped by the source
  modification time; dry runs, external hard-link neighbors and existing envelopes
  retain their creation times. Outer removal preserves descendant signatures.
- [x] Release an explicit descriptor-based `hostmeta.SetCreationTime` primitive from
  [APFS PR #108](https://github.com/deploymenttheory/go-apfs-v2/pull/108), preserving
  replacement API defaults. Darwin sets nanosecond creation time; other hosts
  return an unsupported error without changing their metadata policy.
- [x] Pass [APFS final CI](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/35599205383)
  on head `9b27bfd89d739e51440ac9f40a42b05f25f18219`: three-OS unit/image acceptance,
  vet, the hash race regression and all six builds. The CI merge shares its tree.
- [x] Apply the timestamp only to staged bundle executables; retain original-file
  preservation and cleanup on metadata failure or cancellation. Extend both Clang
  targets with the creation-time attribute and timestamp layout constants.
- [x] Merge APFS PR #108 as `4e9d024c904c7cf08cc0cdf028a486b22d2c210b` and publish
  [v0.7.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.7.0).
  Pin its released module/checksums in codesign without a local replace or workspace.
- [x] Validate the released pin locally and in final three-OS CI, including coverage,
  lint, packaging, race/fuzz, native imports and all 210 creation-time comparisons.
  Audit the final artifacts and confirm the actual merge shares the tested tree.
  Keep ACL inheritance, access-time and broader filesystem differences explicit.
  See [merged validation](#merged-pr39).

**Implementation tasks:**

- [ ] Probe native first signing, re-signing, removal and dry runs separately for
  main executables, nested Mach-O code and existing/new `CodeResources` files.
  Measure inodes, link counts, alias text, ownership, permissions, ACLs, xattrs,
  creation/modification times and supported flags before/after. Extend the merged
  corpus to the remaining metadata, permission and failure profiles.
- [ ] Include internal/external hard links, read-only files, inherited directory
  ACLs, signed/unsigned inputs and an existing signature directory. Do not assume
  the standalone replacement policy applies to resource envelopes.
- [ ] Resolve native executable ACL-inheritance and access-time differences.
  Shared replacement defaults preserve source metadata; PR #39 uses the explicit
  creation-time setter only for staged bundle executables. Preserve those API
  contracts when adding independently evidenced metadata policies.
- [ ] Implement any additional general metadata, clone-fallback or cleanup
  primitive in APFS first, test it on the claimed platforms, release it, then
  consume it. The initial root-relative staging gap is already resolved in v0.5.0.
- [ ] Establish creation modes/inheritance for newly created signature files,
  versus metadata restoration for existing files. Do not clone metadata from an
  unrelated bundle file merely to populate a new envelope. Apple source's new
  signature-directory stat copying is merged and verified in PR #31 against
  released APFS v0.6.0. Copying explicit source ACL entries and subsequent envelope inheritance remain
  unimplemented; the destination's existing/inherited ACL is retained.
- [ ] Complete signature-file cleanup beyond the regular-file and bounded stale
  directory/symlink failure profiles. PR #33 matches post-replacement
  rejection and successful dry runs for the latter. PR #34 delivers
  APFS ASCII named-component ordering; PR #35 pins and validates its released upstream
  fix. Other filesystem orders, special files, broader permissions and raw diagnostic
  parity remain open; retain stricter bounds and internal write-alias rejection.
- [ ] Investigate safe non-cloning filesystem support on Darwin, including HFS+,
  and compressed/protected inputs. Measure native behavior and leave unsupported
  cases explicit until the APFS replacement contract can preserve their metadata.
- [ ] Extend Linux/Windows metadata preservation where representable: ACLs,
  xattrs, streams, read-only flags and rename/share-mode behavior. Separate native
  macOS metadata from host-specific equivalents and state unavoidable differences.
- [ ] Preserve all pre-write validation/staging guarantees. Document commit order,
  cancellation points, failures after an earlier child has committed, and cleanup.
  Native signing is not a whole-tree transaction; do not promise stronger atomicity
  without implementing it as an explicitly separate behavior.
- [ ] Re-evaluate internal hard-link rejection only after demonstrating how native
  writes affect each name and how resource seals remain correct.

**Acceptance:** architecture × bundle layout × operation × link/metadata profile;
compare complete file/tree bytes and observable metadata separately. Force failure
before staging, after staging, before rename, during writing and after a child
commit. Check original bytes where preservation is promised, no leaked staging,
correct neighbour behavior and repeatable errors on all three OSes. APFS owns
platform-specific preservation tests; codesign owns signing/write integration tests.

**Exit:** each bundle write kind has a native-proven policy and a shared APFS
implementation where required; metadata exclusions and partial-commit behavior
are documented. Standalone alias/hard-link and DMG behavior remain regression gates.

**Touchpoints:** [bundle.go](../pkg/codesign/bundle.go),
[bundle_tree.go](../pkg/codesign/bundle_tree.go),
[bundle_writer.go](../pkg/codesign/bundle_writer.go), [io.go](../pkg/codesign/io.go),
[APFS hostmeta](https://github.com/deploymenttheory/go-apfs-v2/tree/v0.7.0/pkg/hostmeta).

<a id="wp-03"></a>
## WP-03: Bundle discovery, path identity and layout coverage

**Starting point:** Contents-based APPL/BNDL/XPC! layouts, supported frameworks,
main-executable discovery, physical version selection and standalone aliases work.
Directory/resource symlinks follow a narrower policy. Bundle paths require portable
ASCII names and reject case collisions and Windows-reserved components.

**Implementation tasks:**

- [ ] Catalogue native layout selection for flat bundles, additional package types,
  missing/partial Info.plist data, executable-name fallbacks and ambiguous roots.
  Distinguish codesign-supported representations from installer package signing
  that belongs to other Apple tools or the separate package project.
- [ ] Extend path selection without confusing the root bundle, a physical framework
  version, its Current alias, its main executable and an unrelated helper/hard link.
- [ ] Probe root/intermediate/final symlinks, absolute/relative/chained targets,
  `link/..`, broken/cyclic links, trailing separators and moved bundles. Record
  which paths select an object and which paths native diagnostics display.
- [ ] Add Unicode names, composed/decomposed forms and case-sensitive versus
  case-insensitive lookup tests. Do not use simplistic lowercasing as a substitute
  for native filesystem name equivalence.
- [ ] Define how names valid on macOS but unrepresentable on a Windows filesystem
  can be handled. Investigate an archive/virtual filesystem input abstraction;
  do not silently rename sealed paths and claim identical bundles.
- [ ] Expand nested-code locations and package discovery from native evidence,
  including alternate framework versions and unsealed root entries.
- [ ] Test selectors on framework roots, direct version directories, executable
  paths, unversioned bundles, parents containing frameworks and non-bundle files.
- [ ] Expand plist types only where needed by native-compatible metadata. Separate
  structural parser errors, absent keys, incorrect types and unsupported layouts.
- [ ] Preserve bounded traversal and containment while exposing the selected
  representation/path consistently to sign, inspect, verify and remove.

**Acceptance:** complete-tree signing/removal comparison, display paths, resource
tampering, selector errors and unchanged neighbours. Test filename collisions,
aliases resolving outside the selected boundary and names unsupported by a producer
filesystem. Such cases must be honestly marked blocked or tested through an
equivalent virtual representation, never silently skipped as passing portability.

**Exit:** a versioned layout/path decision table exists and every newly accepted
layout has native and three-OS evidence. Remaining name/representation restrictions
stay visible in the inventory.

**Touchpoints:** [bundle_discovery.go](../pkg/codesign/bundle_discovery.go),
[bundle_layout.go](../pkg/codesign/bundle_layout.go),
[bundle_paths.go](../pkg/codesign/bundle_paths.go),
[bundle_versions.go](../pkg/codesign/bundle_versions.go), [bundle guide](bundles.md).

<a id="wp-04"></a>
## WP-04: Resource envelopes, extended attributes and strict verification

**Starting point:** the supported resource-envelope profile handles XML/binary
metadata, nested requirements and relative symlink text seals. Default checking
is conservative. The native `--strict`, `--ignore-resources`,
`--strip-disallowed-xattrs` and `--single-threaded-signing` controls are absent.

**Implementation tasks:**

- [ ] Extract native resource-rule precedence, weighting, omission, optionality,
  nested-code classification and v1/v2 interactions. Validate extra/missing entries,
  localization exceptions, symlink seals and legacy digest combinations.
- [ ] Determine support for custom/deprecated resource specifications on the pinned
  binary before adding a CLI surface. Implement only an observed native contract.
- [ ] Introduce explicit strictness options separate from default verification.
  Model plain/all, `symlinks`, `sideband`, combinations, invalid selectors and any
  additional selectors found by WP-01. Native strictness may evolve by OS version.
- [ ] Match default versus strict treatment of broken, external, unsealed and
  cyclic resource links without weakening path containment during writes.
- [ ] Detect native disallowed sideband attributes, including FinderInfo and
  resource forks, on applicable code/resource objects. Preserve unrelated xattrs.
- [ ] Implement `--strip-disallowed-xattrs` through APFS APIs, including native
  diagnostic order, offending paths, partial failure and dry-run behavior. Do not
  use the legacy best-effort attribute reader where exact failures matter.
- [ ] Implement `--ignore-resources` with precisely measured scope. It must not
  accidentally suppress Mach-O page checks, CMS integrity or explicit requirements.
- [ ] Support nested signatures with multiple/alternate CodeDirectories and the
  expanded requirement language when WP-07/WP-09 provide them.
- [ ] Implement the native single-thread resource-seal option. A currently serial
  implementation may already have the scheduling property, but applicability,
  parsing and byte/output equivalence still need tests.
- [ ] If parallel sealing is added, retain deterministic entry ordering, global
  budgets, error ordering and cancellation. Parallelism is not a parity shortcut.

**Acceptance:** sign natively and mutate one resource property at a time; compare
default, strict selectors, deep/shallow and ignore-resources outcomes. Include
xattrs on executable, ordinary resource, symlink and signature directory; test
absence, empty values, inheritance, permission failure and unrelated attributes.
Compare envelope bytes, diagnostics, exit codes and filesystem side effects.

**Exit:** the project's CLI implements the flags itself. Having Apple verify our
outputs with `--strict` is useful evidence but does not satisfy this package.

**Touchpoints:** [bundle_resources.go](../pkg/codesign/bundle_resources.go),
[bundle_tree.go](../pkg/codesign/bundle_tree.go),
[bundle_nested.go](../pkg/codesign/bundle_nested.go),
[verify.go](../pkg/codesign/verify.go), [CLI](../internal/cli/cli.go).

<a id="wp-05"></a>
## WP-05: Signature metadata preservation and signing-option semantics

**Starting point:** force signing and explicit options work for the tested profile.
There is no `--preserve-metadata` or `--prefix`. Filesystem metadata preservation
through APFS is a different capability from reusing fields of an old signature.

**Implementation tasks:**

- [ ] Represent option presence separately from its value so an explicit empty,
  zero or false setting can be distinguished from an omitted setting.
- [ ] Add preservation selectors for identifier, entitlements, requirements,
  flags, runtime, launch constraints and library constraints. Implement abbreviations,
  comma lists, repeated options, unknown names and the deprecated bare form based
  on native probes, without confusing an optional value with the following path.
- [ ] Establish precedence: explicit new metadata, selected preserved metadata,
  derived defaults. Measure the linker-signed exception and unsigned/malformed
  old signatures rather than assuming they supply usable values.
- [ ] Preserve internal requirements as the correct native group; do not replace
  all requirement kinds with the designated requirement alone.
- [ ] Establish per-slice metadata rules for universal files with different old
  identifiers, flags, requirements or runtime values. Do not copy the first slice
  indiscriminately to every architecture.
- [ ] Apply deep/force/preserve rules independently to the parent and eligible
  children. Preserve the tested behavior for already-signed children when force
  is absent.
- [ ] Implement `--prefix` against each identifier source: explicit identifier,
  embedded Info.plist, bundle metadata, canonical filename, ad-hoc UUID/hash suffix
  and preserved identifier. Prefixing every string unconditionally is not a plan.
- [ ] Complete flag masks/names and runtime-version syntax, overflow handling,
  defaults by architecture/platform and applicability to non-Mach-O formats.
- [ ] Preserve current native trailing-allocation-byte behavior when new metadata
  shrinks or grows the signature, and define how retained bytes interact with
  larger CMS allocations and additional signature slots.

**Acceptance:** a pairwise matrix first, then high-risk combinations of force,
deep, preserve selectors, explicit overrides, dry run, identity changes,
timestamps and linker signatures. Compare bytes for deterministic cases, exact
authenticated fields for nondeterministic ones, and untouched files on failures.

**Exit:** every preservation selector has its own native tests, the CLI grammar
matches native optional-value handling, and no unsupported preserved field is
silently dropped. Constraints can remain a separately blocked selector until WP-14.

**Touchpoints:** [types.go](../pkg/codesign/types.go),
[sign.go](../pkg/codesign/sign.go), [identifier.go](../pkg/codesign/identifier.go),
[bundle_tree.go](../pkg/codesign/bundle_tree.go), [CLI](../internal/cli/cli.go).

<a id="wp-06"></a>
## WP-06: Mach-O allocation, architectures and removal

**Starting point:** bounded thin/universal parsing, ad-hoc/certificate allocation,
force replacement and removal have substantial native evidence. That evidence
does not cover every native architecture, load-command layout or file type.
Universal output assembly currently rejects offsets above 32 bits; file APIs
also have the memory limits listed in WP-21.

**Implementation tasks:**

- [ ] Build an explicit matrix of 32/64-bit, little/big-endian, thin/FAT32/FAT64,
  CPU/subtype and Mach-O file type. Separate what the parser accepts, what the
  writer produces, what the installed native tool accepts and what needs an older
  native oracle. Synthetic CPU-tag changes are not evidence for real binaries.
- [ ] Implement signing when there is insufficient load-command padding. First
  enumerate every affected file offset, virtual address, section, relocation,
  symbol table, export/bind/rebase record, chained fixup and link-edit reference
  from pinned headers/source. Do not insert bytes and update only `__LINKEDIT`.
- [ ] Preserve alignment and mapping relationships when adding or resizing
  `LC_CODE_SIGNATURE`. Define behavior for unknown offset-bearing commands;
  reject an unproven transformation before writing any output.
- [ ] Handle native-supported nonterminal signatures, trailing data, sparse or
  unusually ordered link-edit contents and larger existing signature allocations.
  Keep PR #25's native allocation-padding behavior as a regression invariant.
- [ ] Add FAT64 output and offsets through the streaming interfaces, with checked
  arithmetic. Preserve observed slice order, alignment, inter-slice padding and
  architecture-table representation rather than canonicalizing without evidence.
- [ ] Complete architecture selection: names and aliases, numeric CPU with optional
  subtype, duplicate/unavailable slices, subtype capability bits, `--architecture`
  versus `--all-architectures`, and options ignored for non-Mach-O representations.
- [ ] Make the reference architecture/default explicit. Current universal selection
  follows the arm64 baseline across producer OSes; using a Linux runner's host
  architecture would silently change that behavior. Record any future profile
  selection/API change and test Intel-native defaults separately.
- [ ] Extend removal only to forms native `codesign` removes. Preserve its measured
  load-command padding, link-edit size, virtual size, truncation and trailer rules.
  A format supporting signing does not imply native removal support.
- [ ] Investigate legitimate older binaries and other file types only within the
  installed/declared native version's scope. Keep unsupported historical cases
  explicit if no independent oracle is available.

**Acceptance:** native-to-Go and Go-to-native cases for every added matrix cell;
compare entire output bytes, parsed offsets and untouched regions. Include old
signatures smaller/equal/larger than the new allocation, slice-specific failures,
integer boundaries, missing padding, truncated load commands and removal followed
by re-signing. Use independent structural tools as supplemental evidence, not a
replacement for native signing comparisons.

**Exit:** layout transformations have complete offset coverage and bounded failure
behavior. Real architecture fixtures establish claims; unavailable legacy evidence
continues to limit the corresponding inventory entry.

**Touchpoints:** [macho.go](../pkg/codesign/macho.go),
[sign.go](../pkg/codesign/sign.go), [remove.go](../pkg/codesign/remove.go),
[writer evidence](../spec/apple-writer.json),
[removal evidence](../spec/apple-removal.json).

<a id="wp-07"></a>
## WP-07: CodeDirectory versions, digests and special-slot binding

**Starting point:** signing emits the supported SHA-256 CodeDirectory profile;
readers understand a wider bounded subset. Scatter directories are rejected, and
CMS verification rejects multiple CodeDirectories using the same digest.

**Implementation tasks:**

- [ ] Inventory every CodeDirectory header version and extension in the pinned
  SDK/source and actual fixtures. Document wire offsets, length prerequisites,
  byte order, optional fields and reserved values independently of C struct padding.
- [ ] Extend parsing, inspection and verification for native-supported scatter,
  pre-encrypt, 64-bit code-limit, executable-segment, platform, runtime, linkage and
  newer fields. Reading a field without applying its verification semantics is
  not implementation of that field.
- [ ] Implement applicable legacy/alternate digest forms, including selection rules
  across multiple directories. Derive supported algorithms, truncation and
  preferred-CDHash rules from native evidence; do not assume every Go hash belongs
  in an Apple signature or change default signing to a weaker algorithm.
- [ ] Support repeated digest families where native signatures require them.
  Associate each directory with its CMS hash-agility binding and relevant signature
  slot instead of indexing solely by digest name.
- [ ] Complete page-size semantics: native defaults, zero/special values where
  accepted, maximum values, final partial pages and representation-specific rules.
- [ ] Model every special slot with its authenticated source, presence rules and
  verifier. Distinguish an absent slot, a present empty blob, an externally supplied
  value and a zero-filled unused hash. Unknown slots must not be reported verified.
- [ ] Integrate requirements, XML/DER entitlements, resources, constraints and
  external representation data without duplicate independent hashing logic.
- [ ] Update allocation calculations before adding bytes. Use a checked two-pass
  size/encode flow and ensure offsets remain consistent after larger CMS or
  multiple-signature additions.
- [ ] Propagate selected-directory rules into nested resource seals, display,
  requirement evaluation, detached formats and notarization lookup.

**Acceptance:** independent native fixtures for each version/field/hash combination;
exact deterministic output comparisons; mutations of every newly authenticated
field, directory ordering, omitted alternate hashes, duplicate slot IDs and
inconsistent counts/lengths. Verify that a valid alternate directory cannot conceal
a damaged directory which native verification would require.

**Exit:** each supported directory variant has parser, writer where applicable,
verifier, display and allocation coverage. SuperBlob slot IDs, native signature
slots and architecture slices remain separate concepts in the API and tests.

**Touchpoints:** [blob.go](../pkg/codesign/blob.go),
[sign.go](../pkg/codesign/sign.go), [verify.go](../pkg/codesign/verify.go),
[cms.go](../pkg/codesign/cms.go), [types.go](../pkg/codesign/types.go).

<a id="wp-08"></a>
## WP-08: Entitlement representations and option equivalence

**Starting point:** supported XML entitlements and generated DER already bind into
signatures. The remaining work is full native type/format behavior, applicability,
extraction and interaction coverage, not simply adding a DER encoder.

**Implementation tasks:**

- [ ] Enumerate native-accepted plist types and their DER mapping: booleans,
  integers, strings, data, arrays and dictionaries, with evidence for any additional
  type. Distinguish accepted plist syntax from accepted entitlement values.
- [ ] Establish integer widths/signs, dictionary ordering, duplicate-key handling,
  Unicode, escaping, empty collections and nested collection rules. Preserve XML
  bytes where native preserves them and canonicalize only where native does.
- [ ] Compare XML-only, DER-only, matching/mismatched XML+DER, malformed DER and
  missing slots during sign, display and verification. Determine which
  representation native uses for requirements and each display operation.
- [ ] Complete `--force-library-entitlements` applicability for executable, dylib,
  bundle and non-Mach-O inputs. Test omission and explicit override when old
  entitlements are preserved by WP-05.
- [ ] Pin the installed baseline's `--generate-entitlement-der` behavior, including
  any deprecated/no-effect behavior, and avoid inventing a toggle absent in native.
- [ ] Keep native CLI input compatibility separate from library extensions. The
  current baseline rejects binary-plist entitlement CLI input; supporting library
  conversion does not justify accepting it in the native-compatible CLI path.
- [ ] Complete extraction of raw and decoded forms, empty/absent-slot behavior,
  stdout/file destinations and interactions with verbosity/architecture/slot.
- [ ] Retain bounded plist/DER decoding, reject external entity expansion and
  invalid encodings, and account for nested values under one operation budget.

**Acceptance:** native-generated typed fixtures and independent DER inspection;
full signature bytes for deterministic cases; malformed XML/DER corpus; mutations
which independently break the XML slot, DER slot or selected entitlement predicate.
Compare exact output channels, not just successful parsing of extracted content.

**Exit:** entitlement data can round-trip through supported native and Go workflows
with the same authenticated values, wire bytes where deterministic, and defaults.
Runtime authorization to exercise an entitlement is a separate host policy claim.

**Touchpoints:** [entitlements.go](../pkg/codesign/entitlements.go),
[bundle_plist.go](../pkg/codesign/bundle_plist.go),
[sign.go](../pkg/codesign/sign.go), [CLI](../internal/cli/cli.go).

<a id="wp-09"></a>
## WP-09: Complete requirements language and evaluation

**Starting point:** a bounded subset is compiled, decoded, displayed and evaluated,
including the predicates used by current bundle/certificate fixtures. Numerous
anchor, certificate-field, extension-match and opcode forms remain unsupported.

**Implementation tasks:**

- [ ] Expand Clang/source research to the requirement lexer/parser, opcode
  definitions, binary builder, dumper and interpreter. Record inaccessible/private
  paths and prove behavior with native `csreq`/`codesign` fixtures where possible.
- [ ] Build a grammar and opcode checklist covering precedence, parentheses,
  escaping, comments, numeric/date literals, certificate positions, named
  requirements, binary input and requirement-set syntax.
- [ ] Support all native requirement kinds, including designated, host, guest,
  library and plug-in forms where accepted. Preserve an entire requirement set;
  do not flatten it into a single designated expression.
- [ ] Complete comparison operators and field contexts from evidence: existence,
  absence, equality/order, string matching, Info.plist, entitlements, certificate
  subjects/extensions/policies/dates and hash/identifier matching.
- [ ] Complete Apple anchor and certificate-chain predicates using authenticated
  chain context. A subject OU, familiar certificate name or an unverified marker
  extension alone must not establish an Apple-issued identity.
- [ ] Inventory platform, notarization, legacy, dynamic or other predicates exposed
  by the pinned source/binary. Route each to an explicit evaluator context; mark
  predicates needing unavailable state as unresolved instead of returning true.
- [ ] Separate syntax acceptance, binary decoding, canonical rendering and
  evaluation. Unsupported evaluation must not be mistaken for a false predicate,
  successful verification or a successfully enforced policy.
- [ ] Complete designated-requirement synthesis for all supported identity and
  code representations, including explicit overrides and preserved requirements.
- [ ] Match native `--requirements`/`--test-requirement` source/file/binary forms,
  operation applicability and failure distinctions. Cover requirement extraction
  and native canonical text, not just semantically equivalent custom formatting.
- [ ] Preserve expression/depth/byte limits and avoid exponential evaluation,
  unbounded certificate searches or repeated plist decoding.

**Acceptance:** compile identical source with native and Go, compare binary bytes,
decompile each other's output and compare native canonical text. Evaluate against
independently signed objects; exercise true, false, malformed and unavailable-context
outcomes for every predicate. Add operator/precedence metamorphic tests only as a
supplement to the independent oracle.

**Exit:** the grammar/opcode checklist is complete for the declared baseline and
every supported predicate has a real context and failure test. Host-dependent
predicates remain linked to WP-19/WP-22 until their inputs are obtainable.

**Touchpoints:** [requirements.go](../pkg/codesign/requirements.go),
[requirement_text.go](../pkg/codesign/requirement_text.go),
[certificate.go](../pkg/codesign/certificate.go),
[bundle_nested.go](../pkg/codesign/bundle_nested.go).

<a id="wp-10"></a>
## WP-10: Certificate validation and native verification semantics

**Starting point:** portable ASN.1 certificate decoding, bounded chain validation,
explicit leaf pins/CA roots, purpose/time checks, Team IDs and separate TSA trust
are implemented for a defined profile. This is not complete Apple policy, and
the current explicit-trust library contract is not identical to every native
`codesign --verify` invocation.

**Implementation tasks:**

- [ ] Probe native default verification separately from explicit requirement,
  certificate trust, timestamp validity, revocation and notarization checks.
  Define which checks are actually requested by each operation/option combination.
- [ ] Establish `--use-software-signing-cert` software-update validation policy,
  defaults, errors and operation interactions from independent native cases;
  the merged D01 probes do not establish an identity-selection contract.
- [ ] Design separate result/policy concepts for signature integrity, requirement
  satisfaction, chain validity, trust decision, timestamp validity and ticket status.
  Do not label parsed CMS or a valid page hash as a trusted signing identity.
- [ ] Preserve existing explicit-trust APIs or introduce a documented migration
  before changing defaults. A native-compatible CLI policy must not silently
  weaken callers who currently require supplied pins or roots.
- [ ] Complete evidenced certificate handling: chain ordering and alternatives,
  cross-signs, self-issued versus self-signed certificates, name comparison,
  constraints, critical extensions, policies, path length, key usage and EKU.
  Document each unsupported PKIX feature instead of claiming general PKIX support.
- [ ] Measure native handling of expired/not-yet-valid certificates, missing
  intermediates, weak/legacy algorithms and validation time with/without trusted
  timestamps. Avoid replacing native behavior with an assumed stricter policy.
- [ ] Add issuer retrieval, OCSP/CRL and cache/freshness behavior only where required
  by the observed operation. Make network/offline modes, cancellation, trust and
  soft/hard failure decisions explicit; WP-13 owns reusable transport boundaries.
- [ ] Complete Team ID derivation, missing/duplicate OU handling and equality
  requirements across leaf, CodeDirectory and nested signatures. Validate Apple
  marker extensions in the correct authenticated chain context.
- [ ] Expand Developer ID and other Apple-issued signing evidence using legitimate
  fixtures and authorized opt-in credentials. Synthetic look-alike certificates
  are useful negative tests and cannot prove Apple-issued policy compatibility.
- [ ] Keep cryptographic inspection separate from Gatekeeper execution policy.
  Native `codesign` verification alone does not prove Gatekeeper acceptance or
  launch eligibility under all system policies.

**Acceptance:** native-produced and independently constructed chains covering
positive/negative path decisions, alternate issuers, ambiguous subjects, missing
and duplicate extensions, timestamps crossing validity boundaries and revocation
states. Record evaluation time and trust inputs so tests are reproducible rather
than dependent on the runner's changing trust store.

**Exit:** operation-specific policy tables explain each native acceptance/rejection;
tests cover the supported table, and the API reports integrity and trust distinctly.
Unavailable credentials or live policy services remain explicit evidence gaps.

**Touchpoints:** [certificate.go](../pkg/codesign/certificate.go),
[certificate_sign.go](../pkg/codesign/certificate_sign.go),
[verify.go](../pkg/codesign/verify.go), [types.go](../pkg/codesign/types.go),
[certificate guide](certificates.md).

<a id="wp-11"></a>
## WP-11: Identity formats and provider selection

**Starting point:** identities already expose `crypto.Signer`; PEM supports RSA,
EC and unencrypted PKCS#8, and authenticated PKCS#12 supports a documented cipher
and MAC subset. Native `codesign` identity lookup uses keychain semantics; portable
PEM/PKCS#12 inputs are project extensions, not equivalent native CLI switches.

**Implementation tasks:**

- [ ] Add encrypted PEM/PKCS#8 through portable, reviewed cryptographic components.
  Specify accepted encryption/KDF profiles, password encoding, authentication,
  resource budgets and errors; do not accept unauthenticated contents accidentally.
- [ ] Inventory unsupported PKCS#12 bag/content/cipher/integrity forms against
  independent exported archives. Prioritize legitimate identity interchange needs;
  distinguish interoperability extensions from native CLI feature parity.
- [ ] Design explicit selection for archives containing multiple private keys,
  certificates, friendly names or local key IDs. Reject ambiguity unless a
  documented selector resolves it. Preserve current one-identity API behavior or
  provide a separately named API rather than choosing a new arbitrary first key.
- [ ] Support useful extra chain certificates and cross-signs with deterministic
  path selection, while retaining proof that the selected private key matches the
  selected leaf. Do not conflate archive ordering with validated chain ordering.
- [ ] Expand key/signature algorithms only after native acceptance and dependency
  review. RSA-PSS parameters, additional key encodings and hybrid identities require
  coordinated certificate, CMS and timestamp changes rather than only key parsing.
- [ ] Establish any native software-identity/provider selection contract from
  independent evidence. D01 found that `--use-software-signing-cert` documents
  software-update validation policy; route that option's behavior to WP-10/WP-20.
  Do not treat it as evidence of identity lookup, key pairing or hybrid selection.
- [ ] Reuse the existing signer interface for external/provider-backed signing;
  document supported public keys, signer options, signature encoding and cancellation
  limitations. Do not invent an export operation for a non-exportable private key.
- [ ] Complete password-file behavior, empty versus absent passwords, newline
  handling, malformed Unicode, wrong-password diagnostics and log redaction.
  Do not claim guaranteed key-memory erasure from ordinary Go garbage collection.

**Acceptance:** independent OpenSSL/LibreSSL or platform-exported archives with
known public keys and native-accepted signatures; correct/wrong/empty passwords,
multiple identities, duplicate bags, mismatched keys, unsupported algorithms and
KDF budget exhaustion. Use public test identities in CI; no production key material
in fixtures, logs, manifests or PR artifacts.

**Exit:** each newly supported identity form has independent import/sign/verify
evidence and a stated selection contract. Native keychain search and authorization
remain WP-22 responsibilities; portable file input does not close those entries.

**Touchpoints:** [identity.go](../pkg/codesign/identity.go),
[pkcs12.go](../pkg/codesign/pkcs12.go),
[certificate_sign.go](../pkg/codesign/certificate_sign.go),
[types.go](../pkg/codesign/types.go), [CLI](../internal/cli/cli.go).

<a id="wp-12"></a>
## WP-12: CMS representations and signature algorithms

**Starting point:** code-signing CMS supports a bounded SHA-256 RSA/ECDSA profile,
Apple hash-agility attributes and selected indefinite-length BER outer containers.
It does not provide a general CMS/BER implementation, all algorithms or all signer
and attribute combinations.

**Implementation tasks:**

- [ ] Inventory native-created CMS variants by signing identity, algorithm,
  timestamp, legacy form, multiple CodeDirectories and hybrid signature slot.
  Record SignedData/SignerInfo versions, identifier forms and algorithm parameters.
- [ ] Extend only evidenced envelope encodings while retaining original
  authenticated bytes. Re-encoding a certificate or signed-attribute set before
  verification can change what was signed; parser normalization must not repair
  malformed authenticated data into a successful signature.
- [ ] Implement native-supported digest/signature combinations and strict parameter
  validation, including RSA-PSS if accepted. Distinguish absent versus NULL parameters,
  key algorithm constraints, digest identifiers and signature octet encoding.
- [ ] Complete both hash-agility attributes for multiple/alternate directories,
  including repeated digest families, preferred-directory selection and ordering.
  Check all required bindings, not just the primary directory's content digest.
- [ ] Investigate additional signer identifiers/counts, certificate choices, CRLs,
  countersignatures and unsigned attributes. Support them where native requires
  them; document rejection where outside the observed native profile.
- [ ] Calculate signature allocation for larger keys, variable-length ECDSA,
  timestamps, larger chains and PQC. Preserve the existing native reservation and
  padding rules for current identities rather than globally changing their output.
- [ ] Define inspection behavior when envelope metadata is readable but signature
  algorithms or attributes are unsupported. Return descriptive metadata without
  implying integrity or trust was verified.
- [ ] Bound total ASN.1 elements/depth/bytes across wrappers, certificates, attributes
  and nested tokens, including indefinite-length and concatenated-input cases.

**Acceptance:** verify native fixtures with Go and Go fixtures with both native
and an independent cryptographic implementation where available. Compare complete
RSA outputs at recorded signing times. For randomized signatures, compare exact
authenticated attributes/layout and independently verify signatures; declare only
the genuinely nondeterministic byte ranges. Exercise wrong algorithm parameters,
duplicate attributes, ambiguous signer certificates and partial hash-agility data.

**Exit:** supported CMS profiles are explicit and independently verified, with
allocation, display and failure coverage. A permissive parser alone never closes
a CMS verification gap.

**Touchpoints:** [cms.go](../pkg/codesign/cms.go),
[cms_ber.go](../pkg/codesign/cms_ber.go),
[certificate_sign.go](../pkg/codesign/certificate_sign.go),
[identity.go](../pkg/codesign/identity.go), [CMS evidence](../spec/apple-cms.json).

<a id="wp-13"></a>
## WP-13: Timestamp compatibility and portable transport

**Starting point:** explicit HTTP acquisition, nonce/imprint checking, supported
RFC 3161 verification, separate TSA roots, deadlines/cancellation and native replay
fixtures are delivered. Transport, CMS, TSA policy and native default selection
remain a bounded subset.

**Implementation tasks:**

- [ ] Establish implicit/default timestamp selection for each identity/representation,
  including Developer ID, ad-hoc, preserved metadata and explicit `none`. Test
  omitted, bare and URL-valued options and malformed options before any mutation.
- [ ] Probe native redirects, proxy settings, URL authentication, compression,
  chunk extensions, retries, DNS/IPv6, connection failure and timeout behavior.
  Implement the observed profile, with explicit cancellation and operation budgets.
- [ ] Keep the recorded baseline distinction: native macOS 27 rejects HTTPS TSA
  URLs too. HTTPS is not automatically a missing native feature; a future native
  version or separate authenticated service may create a different requirement.
- [ ] Preserve the production dependency guard. Any secure transport needed for
  WP-10/WP-19 must have an audited pure-Go dependency path without the forbidden
  Darwin trust bridge; adding `net/http` is not an implicit approved solution.
- [ ] Extend TSTInfo/ESS handling where native accepts it: multiple certificate IDs,
  policy information, supported TSA name forms, extensions, fractional time,
  accuracy/ordering and nonce-present/absent contexts. Acquisition's nonce-bound
  contract must remain distinct from verification of an imported token.
- [ ] Complete TSA policy-OID, certificate-chain, revocation and trusted-time
  behavior. Measure clock-skew tolerance, expired TSA/code certificates and
  malformed optional attributes against the native operation being reproduced.
- [ ] Extend token algorithms/BER/signer forms through WP-12 rather than creating
  a second inconsistent CMS verifier. Account for larger signature octets from WP-18.
- [ ] Define retry/idempotence behavior per architecture and per nested code object.
  A dry run currently calls the provider; new behavior must preserve or explicitly
  reconcile that contract with native evidence.
- [ ] Keep recorded-token replay for deterministic tests, with exact binding to the
  code signer's signature octets. Fresh online acquisition needs separate tests;
  replay cannot prove a new signing event or current endpoint availability.

**Acceptance:** deterministic offline fixtures plus local protocol-oracle tests
for framing, cancellation, redirects and malformed responses. Use opt-in live TSA
acceptance with recorded endpoint/time/native result; keep mandatory CI reliable
without relying on external service uptime. Compare native acceptance and metadata
while allowing only case-declared nonce/time/signature differences.

**Exit:** default selection, transport and policy have separate completed matrices;
TSA trust remains distinct from code trust and notarization. Unresolved transport
or policy cases stay visible rather than becoming undocumented fallback behavior.

**Touchpoints:** [timestamp.go](../pkg/codesign/timestamp.go),
[timestamp_http.go](../pkg/codesign/timestamp_http.go),
[timestamp_request.go](../pkg/codesign/timestamp_request.go),
[timestamp_roots.go](../pkg/codesign/timestamp_roots.go),
[timestamp guide](timestamps.md).

<a id="wp-14"></a>
## WP-14: Launch constraints, library constraints and validation

**Starting point:** the six constraint-related inventory options are unimplemented.
They need format, schema, signing, display and CLI work. Successful encoding does
not prove that a non-macOS host can enforce Apple's runtime launch policy.

**Implementation tasks:**

- [ ] Extract versioned constraint keys/operators and slot definitions from the
  SDK/source using Clang. Obtain native examples for self, parent, responsible and
  library constraints, including minimal/empty and nested expressions.
- [ ] Determine the native plist-to-DER format and canonical ordering. Reuse common
  typed primitives only after proving equivalence; do not assume constraint DER
  is identical to entitlement DER.
- [ ] Implement `--validate-constraint` as its own operation, including input syntax,
  schema/type errors, unknown keys, supported optional-extension mechanisms and
  native output/exit behavior. Version the schema where native versions differ.
- [ ] Implement the four signing inputs and bind each to its correct special slot.
  Handle omission, explicit empty values, preservation, replacement and file-type
  applicability. Carry them through allocation, inspection and removal.
- [ ] Implement `--enforce-constraint-validity`, establishing the default warning
  versus failure policy and the precise validation point before filesystem changes.
- [ ] Integrate preservation selectors with WP-05 and architecture/slot selection
  with WP-07/WP-18. A forced re-sign must not silently discard requested constraints.
- [ ] Determine native deep-signing behavior: which constraints apply to the parent,
  which are inherited/ignored for descendants and how per-object inputs are selected.
- [ ] Separate structural validity, authenticated constraint binding and runtime
  evaluation. Expose unavailable runtime context explicitly rather than reporting
  that launch restrictions were enforced on Linux or Windows.

**Acceptance:** byte-for-byte native constraint blobs and complete deterministic
signatures; validation diagnostics for wrong types/operators/unknown keys; mutations
of each slot; preserve/override/deep interactions. Where runtime behavior is part
of the claim, use controlled harmless Mac fixtures and record OS-policy prerequisites.

**Exit:** all six CLI options have positive, negative and interaction tests; slot
binding and validation match native, and any runtime-only limitation is explicit.

**Touchpoints:** [blob.go](../pkg/codesign/blob.go),
[entitlements.go](../pkg/codesign/entitlements.go),
[types.go](../pkg/codesign/types.go), [CLI](../internal/cli/cli.go).
New constraint-specific codecs/schema files should keep common primitives shared.

<a id="wp-15"></a>
## WP-15: Native detached signature files

**Starting point:** native `--detached` is unimplemented. Existing detached-content
CMS is an internal cryptographic structure, not Apple's detached-signature file
container. Reference projects' custom detached formats are not interchangeable
without direct native evidence.

**Implementation tasks:**

- [ ] Recover the native container, indexing and per-architecture/object identity
  rules from source/AST and native files. Distinguish detached signatures from
  detached certificate interchange and the system detached-signature database.
- [ ] Establish creation and consumption semantics for Mach-O, bundles, DMGs and
  generic files where native accepts them, including required external resources.
- [ ] Probe whether each operation changes the source object, which old embedded
  metadata it reads, and how force/preserve/dry-run affect output. Do not assume
  an external signature always means an entirely untouched input representation.
- [ ] Add byte and streaming APIs with explicit detached-data ownership and path
  lookup. Bind the signature to the intended object and selected architecture;
  filenames alone are insufficient authentication.
- [ ] Implement native precedence when embedded and detached signatures coexist,
  disagree, are malformed or refer to different input bytes. Reject ambiguous
  selection rather than silently choosing whichever verifies first.
- [ ] Implement CLI output creation, multiple-target behavior, overwrite/append or
  merge behavior where native supports it, stdout use and failure preservation.
- [ ] Reuse the same CMS, requirements, timestamp, special-slot and trust validators
  as embedded signatures. Detached verification must not bypass missing external
  Info.plist, resources or constraint inputs.
- [ ] Complete detached display/extraction and native errors for missing/stale files,
  malformed containers, unsupported versions and invalid architecture indexes.

**Acceptance:** native creates/Go reads and Go creates/native reads in both valid
and tampered cases; exact container bytes for deterministic identities; multiple
architectures/objects, moved paths, mismatched content and embedded/detached conflicts.
Record input and output file hashes/metadata before and after each operation.

**Exit:** native file interchange is independently demonstrated. This does not
close `--detached-database`, which requires the actual system state in WP-22.

**Touchpoints:** [blob.go](../pkg/codesign/blob.go),
[verify.go](../pkg/codesign/verify.go), [sign.go](../pkg/codesign/sign.go),
[types.go](../pkg/codesign/types.go), [CLI](../internal/cli/cli.go).
Container encoding and lookup should live in dedicated new representation files.

<a id="wp-16"></a>
## WP-16: Generic files, xattr signatures and representation dispatch

**Starting point:** the current public workflows concentrate on Mach-O, supported
bundles and supported UDIF images. Native generic-file signatures and wider
representation selection remain unimplemented.

**Implementation tasks:**

- [ ] Inventory native representation dispatch from source and probes: ordinary
  files, scripts, recognized bundle layouts, disk images and any additional format
  actually accepted by the baseline. Record rejection as a valid native result.
  Do not assume installer package signing belongs to `codesign` because another
  Apple tool can sign a package.
- [ ] Recover native xattr names, blob layout, allocation/chunking rules and
  fallback behavior for generic signatures from the relevant disk-representation
  code. Establish interactions with resource forks and existing unrelated xattrs.
- [ ] Implement generic sign, verify, display, force, dry-run and removal where
  supported. Probe unsigned removal, partial signature attributes, empty files,
  executable permission changes and content changes independently.
- [ ] Put missing strict xattr enumeration/read/write/remove operations in the APFS
  public metadata API. Retain aggregate size bounds, no-follow behavior and error
  propagation; do not add a second syscall/xattr implementation here.
- [ ] Decide how Linux/Windows can ingest and emit the complete native metadata
  representation. Their filesystems do not automatically provide the same xattr
  namespace/semantics as a Mac. Evaluate an explicit archive/virtual-filesystem
  carrier or native detached files rather than silently renaming attributes.
- [ ] Label a portable carrier/sidecar as an extension unless native accepts it
  directly. Demonstrate restoration on a Mac before claiming preservation of a
  native generic signature; a JSON description alone is not a signed native file.
- [ ] Define format precedence for ambiguous/malformed inputs, symlinks, executable
  paths inside bundles and files with both embedded and attribute signatures.
- [ ] Reuse identifier, requirements, certificate and timestamp policies across
  representations with explicit per-format applicability.
- [ ] Treat resource sidecars such as AppleDouble as a researched representation
  issue where encountered, not an automatic substitute for native xattr storage.

**Acceptance:** native generic signatures imported into Go on every OS through the
declared carrier; Go-produced objects restored and accepted by native; content and
attribute mutations; unrelated-xattr preservation; permission failures and partial
attribute sets. Verify bytes, metadata, diagnostics and carrier limitations.

**Exit:** the native-supported representation inventory is accounted for, and each
portable storage path has a demonstrated native restoration/interchange story.
Unrepresentable host filesystem behavior remains an explicit compatibility limit.

**Touchpoints:** [io.go](../pkg/codesign/io.go),
[bundle_discovery.go](../pkg/codesign/bundle_discovery.go),
[types.go](../pkg/codesign/types.go), [file-write guide](file-writes.md),
[APFS public metadata API](https://github.com/deploymenttheory/go-apfs-v2/tree/v0.7.0/pkg/hostmeta).

<a id="wp-17"></a>
## WP-17: Wider APFS-backed DMG support and streaming

**Starting point:** codesign directly reuses APFS v0.7.0's UDIF model. Its own
adapter currently accepts a single-segment version-4 image, flags equal to one,
a resource plist, bounded non-overlapping ranges and a 1 GiB in-memory profile.
APFS supporting a broader image format does not mean this signing adapter already
handles that format.

**Implementation tasks:**

- [ ] Audit public APFS APIs against the signing adapter's remaining needs before
  designing new code. Reuse existing footer/range/format handling and document any
  genuinely missing public primitive as an upstream APFS issue/PR.
- [ ] Introduce `ReaderAt`/size-based inspection and hashing, then bounded staged or
  in-place output according to the native write contract. Avoid reading/rebuilding
  the entire image merely to append or replace a signature.
- [ ] Establish every byte participating in the image signature: code range,
  footer/trailer canonicalization, special-slot binding, old signature allocation,
  resource plist and any permitted trailing data. Preserve opaque image payload.
- [ ] Probe encrypted, segmented, sparse or other native-accepted image forms and
  malformed footer variants. Determine which operations need one segment versus
  the full set, password access or additional APFS parsing before committing APIs.
- [ ] Extend adapter checks for the evidenced cases rather than bypassing current
  overlap/length/flag checks wholesale. Use checked 64-bit arithmetic throughout.
- [ ] Keep image codecs, decryption, segment reconstruction and filesystem parsing
  in APFS. Signing unchanged compressed bytes should not require unnecessary
  decompression/recompression or a new codec implementation in this project.
- [ ] Separate fixture-generation problems from signing compatibility. For example,
  a failing upstream encoder does not prove an independently native-created image
  cannot be signed or verified.
- [ ] Complete identifier, page-size, digest, preservation, entitlement, timestamp,
  architecture-option applicability and detached-signature behavior per image form.
- [ ] Retain native rejection of DMG `--remove-signature` on the recorded baseline;
  implementing a custom remover would be an extension, not closing a parity gap.
- [ ] Keep disk-image signature validation separate from filesystem mountability,
  decryption success, notarization and Gatekeeper policy. Add those only where the
  native codesign operation actually requires them.

**Acceptance:** native-created images with different payload encodings, large/sparse
sizes, supported encryption/segmentation and signature histories; deterministic
whole-output or chunk-manifest comparisons; native verification of Linux/Windows
outputs; footer/resource/trailer mutations; bounded memory and cancelled I/O.
Use native tools only for fixtures/oracles, never as the portable production path.

**Exit:** the supported image matrix extends beyond the current adapter profile
with evidence and measured memory behavior. Any APFS change is released and consumed
through its public API; no copied disk-image implementation is introduced.

**Touchpoints:** [dmg.go](../pkg/codesign/dmg.go),
[io.go](../pkg/codesign/io.go), [DMG guide](dmg-integration.md),
[DMG evidence](../spec/apple-dmg.json),
[APFS disk model](https://github.com/deploymenttheory/go-apfs-v2/tree/v0.7.0/pkg/disk).

<a id="wp-18"></a>
## WP-18: Hybrid/PQC signatures, native signature slots and detached certificates

**Starting point:** the macOS 27 inventory includes hybrid/PQC-related behavior,
slot selection and certificate interchange. None is implemented. The precise
algorithms, wire formats and credential availability require early investigation;
this plan does not assume an algorithm or OID from the word “PQC.”

**Implementation tasks:**

- [ ] Obtain legitimate native-created examples and record the native version,
  identity class, required entitlements/provider and availability constraints.
  If creation requires unavailable credentials or hardware, record the blocker
  immediately; public parse fixtures and fabricated test identities prove less.
- [ ] Recover the relationship between classical and PQC components: certificate
  representation, public keys, algorithm parameters, signed content, directory
  binding, CMS structure and native acceptance rules for each component.
- [ ] Implement native `--signature-slot` selection, numbering and default preferred
  slot for display and verification. Keep this distinct from architecture slices
  and SuperBlob slot identifiers. Probe missing, duplicate and out-of-range slots.
- [ ] Define verification results for supported/unsupported components, damaged
  classical/PQC parts and downgrade attempts. A passing classical signature must
  not imply the required hybrid policy succeeded if the second component failed.
- [ ] Select reviewed pure-Go cryptographic implementations with independent test
  vectors and dependency/license audits. Do not translate unreviewed cryptographic
  arithmetic merely to remove a dependency or claim performance equivalence.
- [ ] Extend allocation, CMS, certificate parsing, timestamp imprint inputs and
  resource budgets for the actual signature/key sizes. Avoid reusing the current
  8 KiB timestamp-signature limit as an unexplained incompatibility.
- [ ] Implement native detached-certificate input/output file format, chain/slot
  linkage, ordering, duplicate handling and missing-certificate errors. A plain
  concatenated PEM/DER file is not assumed equivalent without evidence.
- [ ] Implement `--keep-root-detached-certificates` using native root classification;
  self-issued, self-signed and trusted-anchor are not interchangeable properties.
- [ ] Implement standalone `--merge-detached-certificates`: repeated inputs,
  deduplication keys, cross-signed variants, ordering, output creation and collisions.
  Define whether malformed/partial inputs leave an existing output untouched.
- [ ] Test mixed classical/hybrid identity and explicit-slot interactions with
  evidenced policy options. D01 did not establish that `--use-software-signing-cert`
  selects a hybrid identity; its documented software-update validation policy
  needs WP-10/WP-20 evidence before claiming any hybrid interaction.
- [ ] Decide versioned library/report models before adding fields that assume
  exactly one signature/certificate chain per architecture.

**Acceptance:** native interchange in both directions for every supported identity
and slot; independent algorithm vectors; exact deterministic container/certificate
bytes; separately tampered components; missing chains; duplicate/merged inputs;
all three OS producers. Record which tests require restricted credentials and
which are reproducible from public fixtures.

**Exit:** actual native hybrid signatures can be produced and validated according
to native slot policy, and the four detached-certificate interchange flags plus
`--signature-slot` have complete evidence. Any interaction with software-update
validation policy requires its own evidence. Parser-only support or unavailable
signing credentials cannot close the entire hybrid-signing entry.

**Touchpoints:** [types.go](../pkg/codesign/types.go),
[blob.go](../pkg/codesign/blob.go), [cms.go](../pkg/codesign/cms.go),
[identity.go](../pkg/codesign/identity.go), [CLI](../internal/cli/cli.go).
New codecs and algorithms require dedicated provenance and compatibility records.

<a id="wp-19"></a>
## WP-19: Notarization checking and ticket policy

**Starting point:** `--check-notarization` is unimplemented. Existing Apple chain
and timestamp validation does not imply notarization, and a successful native
signature check does not imply a Gatekeeper allow decision.

**Implementation tasks:**

- [ ] Research the baseline's ticket discovery, lookup request/response, authenticated
  ticket format, trust roots, object identifiers and forced-online behavior.
  Pin source/fixtures and record private or undocumented protocol uncertainty.
- [ ] Establish what the flag checks for Mach-O, bundles and DMGs, including which
  architecture, CodeDirectory or signature slot identifies the submitted object.
- [ ] Implement ticket parsing and cryptographic/content binding independently of
  retrieval. Reject a valid ticket bound to different code, an unsupported ticket
  version or an unauthenticated response presented as a positive result.
- [ ] Reproduce required service lookup, cache/freshness, revoked/unknown/rejected
  status and offline/error behavior. Forced online lookup must not silently succeed
  from stale local data if native requires a fresh result.
- [ ] Resolve portable authenticated transport under the dependency guard. Existing
  HTTP TSA authentication depends on signed tokens; that does not justify using
  unauthenticated transport for a different protocol without proving its security.
- [ ] Connect requirement-language notarization predicates to an explicit verified
  context. Do not let caller-provided metadata strings establish notarized status.
- [ ] Complete CLI output, aggregate exit status and interaction with ordinary
  verification, explicit requirements, timestamps and signature-slot selection.
- [ ] Keep submission, account management and stapling out of this work unless
  evidence establishes them as `codesign` operations. Other Apple tools' features
  do not automatically belong in a codesign-equivalence backlog.

**Acceptance:** legitimate public notarized artifacts and authorized opt-in live
tests; bound/unbound ticket mutations; unknown/revoked/offline/service-error cases;
native side-by-side results with recorded times and cache conditions. Replay tests
prove decoder/policy behavior, not current remote service status.

**Exit:** the requested native check is implemented with authenticated results and
documented service dependencies. Missing protocol access, credentials or portable
transport remains an explicit blocker rather than a hardcoded positive answer.

**Touchpoints:** [requirements.go](../pkg/codesign/requirements.go),
[certificate.go](../pkg/codesign/certificate.go),
[verify.go](../pkg/codesign/verify.go), [types.go](../pkg/codesign/types.go),
[CLI](../internal/cli/cli.go). Ticket and service logic need separate new modules.

<a id="wp-20"></a>
## WP-20: CLI equivalence, display, extraction and diagnostics

**Starting point:** Cobra/Viper wrap a native-style parser and the main portable
operations. Many flags are absent, and covered flags still lack complete native
grammar, output, applicability and error behavior. The library having a capability
does not prove CLI compatibility.

**Implementation tasks:**

- [ ] Build the complete operation matrix for sign, verify, display, remove,
  hosting, constraint validation and detached-certificate merging. Cover missing
  and conflicting operations, implicit modes, aliases and deprecated options.
- [ ] Complete short-option clusters, repeated `-v`, optional values, equals forms,
  abbreviations where native supports them, `--`, dash-prefixed paths, repeated
  options and last-value/error precedence. Retain Cobra/Viper while preventing
  their generic behavior from overriding native semantics.
- [ ] Reproduce options accepted but ignored for a particular operation only after
  native evidence. Unknown or unsupported behavior must not become a silent no-op.
- [ ] Route numeric targets according to native process-versus-path rules, including
  explicit `./` filename disambiguation. Until WP-22 exists, report unavailable
  live-process behavior instead of treating every PID as an ordinary filename.
- [ ] Complete verbosity-level display: architecture, flags, CodeDirectory fields,
  hash candidates/preference, signature allocation, authorities, Team ID, runtime,
  requirements, entitlements, constraints, timestamps and alternate signature slots.
- [ ] Match canonical/physical path reporting, quoting, ordering, stdout versus
  stderr, trailing newlines and exit codes. Preserve PR #25's physical-target
  display/default-identifier behavior for standalone aliases.
- [ ] Replace the current fixed English UTC date approximation with an explicit
  native locale/timezone contract. Test fixed baseline locale first; retain other
  localized/native-version outputs as separate unproven profiles until evidenced.
- [ ] Implement `--extract-certificates`: DER bytes, chain ordering, default/custom
  prefixes, numbering, root inclusion, existing files, multiple targets and partial
  failures. Extraction must not imply that the certificate chain is trusted.
- [ ] Implement `--file-list`: discover exact native signing/display contents,
  file order, path spelling, newline/output destination and append/overwrite rules.
  Track actual affected files; listing every scanned file is not a substitute.
- [ ] Complete requirement/entitlement/constraint extraction through the format
  owners. Test absent/malformed slots, raw versus decoded output, architecture
  and signature-slot selection, stdin/stdout where supported and multiple targets.
- [ ] Finish `--continue` aggregate behavior: mixed successes/failures, processing
  order, diagnostics and final exit code. Confirm which targets are mutated before
  and after a failure, including nested and detached outputs.
- [ ] Complete `--dryrun` across every writer. Record identity/provider/network
  activity separately from filesystem changes; “no files changed” is not proof
  that no signing or timestamp operation occurred.
- [ ] Keep portable extensions such as JSON, explicit trust and file identities
  documented separately. Evolve report fields without confusing parsed metadata,
  integrity, policy, trust and actual native success.
- [ ] Audit help and usage against overloaded native short flags; in particular,
  a generic CLI help shortcut must not steal an actual native operation.

**Acceptance:** execute identical argument vectors through native and Go against
equivalent isolated inputs; capture raw stdout/stderr, exit status and filesystem
snapshots. Include malformed options, unknown algorithms, missing files, permission
errors, broken links, mixed targets and all new extraction outputs. Normalize only
documented fixture-specific differences, never broad error text or missing fields.

**Exit:** every documented and evidenced undocumented option has operation-specific
tests and an honest status. Output compatibility is measured, not inferred from
human-readable similarity or equal success codes.

**Touchpoints:** [CLI](../internal/cli/cli.go),
[entry point](../cmd/macoscodesign/), [types.go](../pkg/codesign/types.go),
[acceptance tests](../acceptance/), [compatibility inventory](../spec/compatibility.json).

<a id="wp-21"></a>
## WP-21: Streaming, operational limits and cancellation

**Starting point:** bounded inputs are intentional protections, but some bounds
also exclude ordinary native-supported workloads. Increasing a constant is not
an adequate streaming or performance implementation.

The following baseline limits need explicit evaluation. This is an audit starting
list, not permission to remove all limits:

| Area | Current bound/profile | Remaining implementation question |
| --- | --- | --- |
| File/image processing | 1 GiB in-memory input/output profile | Seekable streaming, large offsets and bounded output staging |
| Bundle traversal | Shared byte budget, 10,000 entries, 64 nested code objects, depth eight | Scalable traversal with global resource accounting |
| Bundle plist | 8 MiB, binary graph depth 32 and 100,000 expanded values | Real native limits, graph amplification and larger resource envelopes |
| Bundle paths | Portable ASCII restriction, 1,024-byte path, 255-byte component, bounded depth | Native Unicode/case semantics and cross-host representability |
| Requirements | Depth 128 and 4,096 expression nodes | Bounded full grammar and deterministic evaluation cost |
| CMS normalization | Bounded ASN.1 structure/element processing | Shared budgets across larger signatures and nested tokens |
| Chain building | 64-certificate pool, 32-certificate path, 256 visits | Cross-sign/path policy without combinatorial search |
| PKCS#12 | 16 MiB archive, 1,024-byte password, bounded salt and KDF work | Larger/multi-identity inputs with explicit resource policy |
| Timestamp | 1 MiB token/response, 8 KiB signature input, 160-bit serial/nonce | Native-supported larger signatures and bounded protocol variants |
| HTTP framing | 32 KiB framing/header budgets, 8 KiB lines, bounded line counts | Native-required transport forms without parser ambiguity |
| Shared metadata | APFS metadata APIs have their own bounds/contracts | Upstream extension where needed; no local duplicate implementation |

**Implementation tasks:**

- [ ] Define seekable input, known size, hashing, output reservation and commit
  interfaces. Preserve existing byte APIs as convenience wrappers with documented
  memory limits and unchanged ownership contracts.
- [ ] Use incremental page/resource hashing and bounded buffers. Design two-pass
  allocation so adding a signature does not require keeping every input/output in
  memory, including universal slices, bundle descendants and disk images.
- [ ] Account for total memory, temporary disk space, open files, parsed objects,
  network requests and cryptographic work across the entire operation. Per-child
  limits alone do not prevent a large nested tree from exhausting resources.
- [ ] Detect source changes between discovery, hashing and commit. Define stable
  file identity and concurrent-write handling; avoid signing one byte sequence
  while committing or reporting a different one.
- [ ] Preserve path containment through root-relative handles and shared APFS
  metadata operations. A streaming refactor must not reintroduce symlink races.
- [ ] Make cancellation effective during reading, hashing, traversal, remote requests
  and staging, with a documented last cancellable point before commit. External
  signer callbacks need an explicit contract if they cannot be interrupted.
- [ ] Add checked conversions for signed/unsigned sizes and host `int` values;
  reject overflow before allocation, seeking or writing.
- [ ] Define disk-full, short-write, permission-change and cleanup behavior. Do not
  promise whole-bundle atomicity where native semantics and the filesystem cannot
  provide it; document recoverable partial commits precisely.
- [ ] Measure realistic large application/image workloads and worst-case malformed
  inputs. Report peak memory, temporary storage, time and file descriptors against
  a pinned environment; do not claim native performance parity without measurements.
- [ ] Separate configurable operational budgets from fundamental unsupported
  formats. If a deliberate bound still rejects native-accepted data, preserve that
  compatibility limitation in documentation and the full-parity audit.

**Acceptance:** files around every size boundary, large sparse files, many small
resources, deep layouts, repeated plist references, ambiguous certificate graphs,
cancelled reads/writes, disk exhaustion and changing inputs. Assert bounded resource
usage and preserved original data on pre-commit failures; verify actual committed
state for failures after the documented commit boundary.

**Exit:** supported large workloads have measured bounded-memory behavior and
portable failure semantics. Remaining limits are explicit, tested and not hidden
by increasing test fixtures only slightly beyond the old bound.

**Touchpoints:** [io.go](../pkg/codesign/io.go),
[macho.go](../pkg/codesign/macho.go), [dmg.go](../pkg/codesign/dmg.go),
[bundle_tree.go](../pkg/codesign/bundle_tree.go),
[types.go](../pkg/codesign/types.go), [file-write guide](file-writes.md).

<a id="wp-22"></a>
## WP-22: Live-state, key-provider and external-helper blockers

**Current state after PR #39:** eight inventory entries are explicitly blocked:
the original five plus `--remote-signing`, `--signing-dylib` and `CODESIGN_ALLOCATE`.
D01 records the missing inputs and helper-boundary conflicts in
[native inventory](native-inventory.md). Pure Go can implement file formats;
it cannot infer unavailable live state or recover a non-exportable key from a
certificate. Inventorying these constraints does not resolve them.

| Blocked feature | State needed for native-equivalent behavior | Useful portable work | What would still be missing |
| --- | --- | --- | --- |
| `--hosting` | Actual process, guest/host chain and dynamic validity | Decode documented representations; design explicit process-context models | A snapshot is not the current native hosting chain |
| `live-process-verification` | Target process identity, loaded code and kernel-enforced signing state | Share static validation and model authenticated process evidence | File verification cannot prove the current process state |
| `--keychain` | Search lists, identity preferences, unlock/ACL decisions and usable private-key provider | Offline supported archive formats and explicit provider interfaces | Native lookup/authorization behavior and protected key access |
| `--detached-database` | Actual native system database contents, update semantics and permissions | Research/read/write a supplied offline database copy | Registering a record in the real system database and observing its effect |
| `hardware-identities` | Authorized access to the original device/service and signing operation | Existing `crypto.Signer` integration and portable device protocols if available | A local substitute key is not the same hardware identity |
| `--remote-signing` | Actual signer/provider protocol, identity and authorization | Research an explicit pure-Go provider contract where available | Parser recognition does not supply authorized provider access or native semantics |
| `--signing-dylib` | Native external signing-library execution | Record required inputs and provider semantics | Executing an arbitrary native library conflicts with the no-native-binding boundary |
| `CODESIGN_ALLOCATE` | Native external allocator override | Independent built-in allocation and native default-output comparisons | Arbitrary helper execution conflicts with the no-helper production requirement |

**Research and resolution tasks:**

- [ ] Enumerate the actual native operations and authorization requirements through
  pinned source/AST and isolated tests. Separate representation decoding from
  current-state access; do not use blanket “host feature” labels to avoid research.
- [ ] For process operations, specify target identity, PID reuse, races, host/guest
  ordering, dynamic invalidation and error behavior. Determine which observations
  can be obtained through allowed portable interfaces and which cannot.
- [ ] For keychain lookup, investigate preference/exact-name/substring/hash selection,
  duplicate certificates, search ordering, explicit keychain scope, intermediate
  lookup, locked stores and user authorization. File-based identities remain a
  separate supported path, not a native search-list implementation.
- [ ] For detached databases, establish the schema/version, matching keys, update
  transaction, precedence over embedded/file-detached signatures and persistence.
  Use disposable test state; reading an offline copy alone proves only the codec.
- [ ] For hardware identities, document each accessible protocol and whether a
  reviewed pure-Go client can use the real provider. Preserve key non-exportability
  and record unavailable device/credential requirements without fabricating success.
- [x] Inventory `CODESIGN_ALLOCATE`, `--remote-signing` and `--signing-dylib` with
  evidence and explicit access/boundary constraints; retain blocked statuses.
- [ ] Investigate additional evidenced environment/helper hooks and the complete
  contracts of those already inventoried. The native external-helper override
  has observable execution/selection behavior;
  a built-in Go allocator can reproduce normal output but cannot also reproduce
  arbitrary helper execution while honoring the no-helper requirement.
- [ ] Record the feasibility outcome for every blocker: achievable within existing
  constraints, needs an external input/provider, or conflicts with the original
  constraints. Describe the exact missing input and independently testable contract.
- [ ] Keep optional snapshots, remote services or experimental adapters visibly
  separate if ever proposed. A macOS bridge/service would require an explicit
  scope change and would not satisfy the original zero-macOS-dependency objective.
- [ ] Maintain deterministic unsupported/unavailable diagnostics in the portable
  CLI until real implementations exist. Correct failure reporting is useful but
  does not upgrade a blocked feature to verified equivalence.

**Acceptance:** real isolated native processes/stores/devices where authorized,
with matching state and before/after observations. Public replay fixtures supplement
those tests but cannot replace live-state proof. Do not access unrelated production
keychains, alter system trust or write the system database to populate CI fixtures.

**Exit:** each blocker is either truly implemented with the required state/key
access inside the original constraints, or remains explicitly blocked. There is
no unconditional full-parity completion while any of these remains unresolved.
An agreed narrower product scope would be a different objective, not silent
completion of this one.

**Touchpoints:** [compatibility inventory](../spec/compatibility.json),
[types.go](../pkg/codesign/types.go), [identity.go](../pkg/codesign/identity.go),
[CLI](../internal/cli/cli.go), [research guide](research.md).

<a id="wp-23"></a>
## WP-23: Differential acceptance, portability, CI and distribution

**Starting point:** three-OS tests, native verification of foreign-produced files,
per-package coverage, race/fuzz checks, GoReleaser packaging, release workflows and
golangci-lint already exist. They must expand with each feature; their existence
alone does not prove a newly added capability.

**Implementation and validation tasks:**

- [ ] For each new feature, add native-produced public fixtures that Go consumes on
  all three OSes, and Linux/Windows-produced outputs that a downstream Mac checks.
  Record exact generating commands, tool/source versions, expected results and hashes.
- [ ] Compare entire deterministic outputs and filesystem trees, not only CDHashes
  or native verification success. For timestamps/randomized cryptography, declare
  exact permitted differences per case and verify every authenticated invariant.
- [ ] Extend evidence beyond bytes: mode/ownership/ACL/xattrs, link/inode behavior,
  path spelling, stdout/stderr, exit status, changed-file lists and failure state.
- [ ] Keep mandatory Ubuntu, Windows 2025 and baseline macOS execution jobs. Treat
  missing native tools or skipped required cases as missing evidence; do not turn
  a failed platform into a green job by excluding the difficult cases.
- [ ] Preserve Windows diagnostics: operation, target path, current working
  directory, temp volume, relevant access/rename errors and cleanup status, with
  no private keys/passwords. Retain relative-input fixtures under the working
  directory when cross-volume relative paths are impossible.
- [ ] Pin the native OS/build/binary identity in each run. When a hosted runner
  changes, detect drift and explicitly update the baseline/fixtures; do not silently
  compare a new Apple behavior to old expected output and normalize the difference.
- [ ] Enforce statement coverage strictly above 95% in every production package on each
  required OS. Add meaningful behavior/mutation tests for new paths; no excluding
  difficult files or packages merely to keep the coverage report green.
- [ ] Keep race detection test-only where it needs a C toolchain. Expand the current
  nine fuzz targets for new codecs, constraints, detached containers and tickets;
  retain minimized regression inputs with provenance and reproducible failure cases.
- [ ] Run dependency guards for Darwin, Linux and Windows, including transitive
  production imports, vendored/local adapters and build tags. Inspect all six
  packaged binaries for `CGO_ENABLED=0`, actual dependency versions and unintended
  local replacements; source `go.mod` alone is insufficient evidence.
- [ ] Keep production builds and archives in GoReleaser. Preserve Linux/macOS/Windows
  amd64/arm64 packaging, SBOM contents, checksums and executable/version smoke tests
  where the runner can execute the architecture.
- [ ] Maintain Release Please and tag-release workflows using the established
  go-macos-pkg reference patterns. Check manifest/version/config consistency,
  credential/event triggering and permissions after changes; do not replace the
  repaired workflow with an unrelated release system.
- [ ] For an authorized tagged release, verify downloaded archives/SBOMs against
  checksums and validate signed-checksum provenance with the expected repository
  and workflow identity. A signature file existing is not signature verification.
- [ ] Hash fixture bytes after checkout and preserve binary fixtures against line
  ending conversion. Record expected text line-ending differences separately;
  do not normalize signed binary content to make Windows comparisons pass.
- [ ] Audit artifacts from the exact final PR commit after all implementation fixes.
  Link the tested SHA and completed workflow; stale green runs from an earlier
  commit are not final evidence.

**Acceptance:** a complete feature PR has a green three-OS/native-import matrix,
required coverage/lint/dependency gates and inspectable independent artifacts.
Credential-dependent live tests may be opt-in, but their absence must remain a
stated limitation on the feature claim. A documentation-only PR needs documentation
checks and required CI, not invented new cryptographic acceptance results.

**Exit:** every claimed feature/input profile has traceable independent evidence
and the shipped binary contains the code/dependencies which produced it. Keep the
full-parity guard failing while genuine inventory gaps remain.

**Touchpoints:** [test workflow](../.github/workflows/test.yml),
[lint workflow](../.github/workflows/go-lint.yml),
[release workflow](../.github/workflows/release.yml),
[Release Please workflow](../.github/workflows/release-please.yml),
[guards](../scripts/guards.py), [testing guide](testing.md),
[release guide](releases.md).

<a id="wp-24"></a>
## WP-24: Documentation, compatibility inventory and final audit

**Starting point:** progress, focused guides, source manifests and the machine-readable
inventory exist. Some focused guides retain historical phase counts; current
aggregate evidence belongs to the dated progress record, not a sum of stale totals.

**Implementation/documentation tasks:**

- [ ] Update the inventory in the same PR as each behavior change. Retain `partial`
  when only a bounded profile is proven; use `verified` only when the entire
  entry's declared native scope and relevant interactions have evidence.
- [ ] Expand coarse umbrella entries into traceable subprofiles where useful while
  retaining their original obligations. Splitting entries must not make missing
  behavior disappear or inflate a misleading completion percentage.
- [ ] Keep this plan's baseline historical. Add dated completion/evidence links for
  delivered work and revised outstanding tasks rather than rewriting past evidence
  as though it applied to later commits.
- [ ] Update CLI help, public API comments, README examples, focused guides and
  compatibility limitations when behavior/defaults change. Explain portable
  extensions and native-compatible paths distinctly.
- [ ] Document per-format, per-operation, per-architecture and per-native-version
  support. Include size/path/storage limitations, trust/network inputs and actual
  runtime requirements for each profile.
- [ ] Publish a migration note for changed trust defaults, signature/report models,
  new option precedence or removal of a prior restriction. Version public API and
  CLI compatibility deliberately rather than treating every pre-1.0 change as free.
- [ ] Maintain Apple/source/Clang provenance, reference-project pins, attribution
  and license obligations. Reference implementations inspire tests/design; none
  independently proves our output matches Apple.
- [ ] Reconcile tests, manifests, narrative counts and inventory at each milestone.
  Verify fixture paths, local documentation links, public artifact links and the
  exact commit associated with reported coverage.
- [ ] Complete a final native delta audit beyond the original 55 entries: newly
  discovered flags, environment hooks, live-state behavior, error conditions,
  storage semantics and supported native-version differences.
- [ ] Run `make release-check` only as a genuine full-parity closure check. Do not bypass
  `--require-complete`, remove blocked entries or set `full_parity` merely to permit
  a release. Supported-subset releases must continue to say they are partial.

**Acceptance and exit:** every full-parity claim can be traced to current code,
independent tests and shipped artifacts, with no unresolved original requirement.
If an original constraint makes a feature impossible, preserve that fact and the
blocked objective instead of declaring success through rewording.

**Touchpoints:** [documentation index](README.md), [progress](progress.md),
[compatibility guide](compatibility.md),
[implementation stages](implementation.md),
[machine-readable inventory](../spec/compatibility.json),
[reference review](reference-implementations.md).

## 5. Research inputs and ownership boundaries

Research should answer a concrete implementation question before expanding a
parser or writer. These are existing reviewed reference families; new revisions
must be pinned and reviewed before relying on changed behavior.

| Work | Primary evidence | Supplemental reference/design input | Required caution |
| --- | --- | --- | --- |
| Operation grammar and defaults | Installed manual/binary; Apple CLI source; differential probes | Existing CLI acceptance harness | Public source may lag the installed binary |
| Mach-O and CodeDirectory | Apple Security/SDK declarations and native files | Go linker, LLVM LLD, go-macho | Linker ad-hoc signing is a narrower use case |
| Allocation/removal/file writes | Apple writer and disk-representation source; filesystem snapshots | Existing writer/path/removal AST manifests | Output hashes alone miss inode/metadata differences |
| Bundle discovery/resources | Apple bundle and resource code; native complete trees | apple-platform-rs, sigtool, zsign | Do not import their host helpers or assume identical resource rules |
| Requirements | Apple lexer/compiler/interpreter; `csreq` and `codesign` output | apple-platform-rs and existing local compiler fixtures | A semantically similar expression can still have different native bytes/text |
| Certificates/CMS/PKCS#12 | Apple CMS/policy source; independent encoded fixtures | Relic, ipsw, zsign-rs, signapple | Audit native-framework dependencies and preserve signed bytes |
| Timestamping | Apple timestamp source/AST and recorded/live native exchanges | Relic and existing independent protocol tests | Replay and live service evidence answer different questions |
| DMG and filesystem APIs | Existing APFS public implementations and native signed images | Relic as a signature-placement cross-check | APFS owns image codecs and metadata mechanics |
| Detached signatures | Apple native container and disk-representation source | Other projects' external-signature designs | signapple's custom detached format is not Apple's format |
| Constraints, PQC and tickets | Current SDK, native fixtures and available Apple source | Reviewed independent implementations if found | Do not guess private wire formats, algorithms or trust decisions |

Exact pins, reviewed limitations and URLs are in [research.md](research.md) and
[reference-implementations.md](reference-implementations.md). Third-party licenses
must be checked before copying code; a reference is not automatically a dependency.

The ownership split for future changes is:

| Layer | Owns | Must not absorb |
| --- | --- | --- |
| APFS project | Disk-image models/codecs and reusable host metadata/file primitives | codesign CLI semantics, requirements or CMS policy |
| `pkg/codesign` | Native signature representations, hashing/signing/verification and format-specific write decisions | CLI argument policy or duplicated low-level APFS implementations |
| `internal/cli` | Cobra/Viper integration, native arguments, operation dispatch, output and exit behavior | A second cryptographic verifier or private format implementation |
| Research/acceptance | Clang extraction, native tools, independent encoders and captured evidence | A production runtime fallback to macOS or external helpers |
| CI/release | Portability/coverage/provenance gates and GoReleaser artifacts | Unverified declarations that a partial profile is full equivalence |

<a id="delivery-status"></a>
## 6. Delivery status, remaining slices and merge order

The following are review boundaries, not promised PR numbers or a claim that one
row will always fit one PR. Split further by observed behavior when necessary.
Each implementation slice includes tests, documentation and inventory updates;
none leaves independent acceptance for a later “testing PR.”

| Slice | Status after PR #39 | Scope and first reviewable result | Dependency / gate |
| --- | --- | --- | --- |
| D01 | Initial evidence merged; wider applicability open | Expand baseline option/applicability inventory and record live-state/PQC/ticket research unknowns | WP-01/WP-22; no speculative feature-status upgrades |
| D02 | Writer, cleanup, directory-stat, failure, ordering, envelope and creation-time corpora merged | PR #39 adds 210 Darwin creation-time comparisons; remaining metadata/failure profiles need evidence | D01; final three-OS and artifact gates passed; platform-specific metadata scope remains explicit |
| D03 | Root-relative/directory-stat APIs, name-hash race fix and creation-time setter consumed | APFS v0.7.0 is pinned and validated in merged PR #39 | Released-dependency and actual-merge audit gates complete for this profile |
| D04 | Replacement, cleanup, directory-stat, ordering, envelope and creation-time profiles merged | Next: executable ACL inheritance and access-time behavior, then wider permission profiles | Each additional profile needs native evidence and final CI/artifact validation; D04 remains open |
| D05 | Outstanding increment | Native Unicode/case/path handling and one additional bundle layout profile | WP-03 evidence; do not combine a broad discovery rewrite with writer changes |
| D06 | Outstanding increment | Disallowed xattr enforcement/stripping and baseline strict/resource-ignore options | APFS public mutation API and native mutation matrix |
| D07 | Outstanding increment | Signature preservation for existing supported fields, then prefix/option precedence | Constraints explicitly deferred until D16; unsupported selectors still fail |
| D08 | Outstanding increment | Certificate extraction and accurate file-list output for existing representations | Complete raw output/file side-effect comparisons |
| D09 | Outstanding increment | Seekable hashing/output interfaces and first large-file/image path | WP-21 budgets and source-change detection; preserve existing byte APIs |
| D10 | Outstanding increment | Mach-O header expansion, then FAT64/legacy layout/removal profiles | D09 where large offsets apply; every transformation independently evidenced |
| D11 | Outstanding increment | One CodeDirectory/digest/slot family per slice, with CMS/nested integration | WP-07; no parser-only feature completion |
| D12 | Outstanding increment | Complete entitlement types, extraction and applicability | D11 as needed; native XML/DER byte comparisons |
| D13 | Outstanding increment | Requirement grammar/encoding/rendering families, then contextual predicates | WP-09; unavailable contexts remain explicitly unsupported |
| D14 | Outstanding increment | Identity/PFX extensions and CMS algorithms in matching increments | Independent identity and signature fixtures; no native dependency regression |
| D15 | Outstanding increment | Native-compatible verification policy and broader timestamp/transport behavior | WP-10/WP-13; explicit-trust migration decision and independent chain tests |
| D16 | Outstanding increment | Constraint codec/validator, then four signing slots and enforcement/preservation | D11/D12; validate operation separately from launch enforcement |
| D17 | Outstanding increment | Native detached container reading/writing and operation matrix | D10–D15 as applicable; bidirectional native interchange |
| D18 | Outstanding increment | Generic signatures and declared portable metadata carrier | D06/D17 and APFS support; native restoration proves the carrier |
| D19 | Outstanding increment | Additional DMG representations, one APFS-backed profile at a time | D09; upstream release first if any new API is needed |
| D20 | Outstanding increment | Native hybrid fixtures/model, detached certificate interchange, then signing/slot policy | Early research complete; real credentials/algorithm availability determine sequencing |
| D21 | Outstanding increment | Authenticated notarization ticket decoding, then live checking and requirements integration | Early protocol research and portable transport must resolve first |
| D22 | Outstanding increment | Remaining CLI errors/defaults/locale and multi-operation interactions | Feature implementations ready; each remaining option retains its owner |
| D23 | Outstanding increment | Any feasible live-state/provider implementation within original constraints | Requires actual state/key access; no scope downgrade disguised as implementation |
| D24 | Outstanding increment | Final inventory, baseline-version, distribution and full-parity audit | All original obligations satisfied; otherwise publish only an honest partial milestone |

CI improvements and documentation corrections can accompany any slice. APFS PRs
remain separate upstream changes. After the user merges a project PR, start the
next slice from the new `main`, carry only needed work, and link its dependent
upstream release. Do not accumulate unrelated feature packages in one long branch.

### Completed PR #33 delivery

PR #33 merged the cleanup-failure slice described [above](#merged-pr33), starting
from PR #32's documentation update. Its implementation, 214 native comparisons,
three-OS execution, packaging, race/fuzz checks and final artifact audit are
complete. The actual merge `d322e85` shares the tested source tree.

APFS v0.6.0 remained the released pin at PR #33, which needed no upstream change. Its
directory-stat API was delivered through APFS PR #104, merged as
`b77926ec2b33b178084015f94b5f1e1043401026`; the user published v0.6.0 on 2026-09-21.
That upstream tested head `59f15729c46ed2cce75c866174f7cb9f81814a34` passed the
[upstream final workflow](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/35562856598).
Codesign consumes that published API without an APFS replace or workspace.

### Completed PR #34 and PR #35 delivery

PR #34 merged the ordering implementation and its 278 native comparisons as
`f4d7e284f5ce21deeae80890238d1344f155ce72`. Its actual merge shares the tested and
audited source tree documented [above](#merged-pr34), which still pinned APFS
v0.6.0. Those historical results do not validate a subsequent dependency change.

APFS PR #106's concurrency fix was released in v0.6.1 through PR #107. PR #35
pins that published release and removes obsolete v0.6.0 sums, without a local
APFS replace/workspace. Its final three-OS, packaging, race/fuzz, native-import
and artifact checks passed, and its actual merge `0457f52` shares the tested tree.
The [PR #35 milestone](#merged-pr35) records those results. The released-dependency
follow-up is complete.

### Completed PR #36 and PR #37 delivery

PR #36's plan update and PR #37's signing-envelope failure profile are on `main`.
The [PR #37 milestone](#merged-pr37) records the 104 portable and 20 POSIX cases,
final three-OS and native-import gates, packaging, race/fuzz and artifact audit.
Actual merge `83e8f895` shares the audited source tree. This profile used APFS v0.6.1.

### Completed PR #39 delivery

PR #39's creation-time implementation, released APFS v0.7.0 integration and final
validation are on `main`. Actual merge `448c4090` shares the audited source tree.
The [PR #39 milestone](#merged-pr39) records its 210 native comparisons, three-OS
coverage, packaging, race/fuzz, lint, native-import and artifact results.

### Next implementation work after PR #39

Native explicit ACL copying, destination envelope inheritance from those entries,
broader permissions/failure order, executable ACL inheritance and access-time
behavior remain open. The supported x/sys Darwin API has no ACL reader; the
implementation does not add raw syscalls, native binding directives or a helper fallback. Failed stat
copying can leave an empty or partially updated directory before its envelope and
executable commit. No feature or work-package status is upgraded to fully verified.

1. Investigate remaining executable ACL inheritance and access-time behavior as
   separate bounded D04/WP-02 profiles. Retain the 210 creation-time comparisons
   and every merged writer matrix. Symlinked signing envelopes retain the
   documented containment difference. Creation-time release and validation gates
   are complete; do not repeat that profile as outstanding work.
2. If a required general metadata primitive is missing, extend APFS upstream and
   consume its next released API before integrating the dependent writer change.
   Do not repeat the delivered root-relative staging or directory-stat APIs, or
   weaken their existing contracts to accommodate a new profile.
3. After each defined writer profile passes its native and three-OS gates, proceed
   to D05's first additional path/layout profile, then D06 resource/xattr policy.
   Continue D01 applicability/source research and WP-22 access investigations;
   no unavailable context counts as a passing test.
4. Preserve the 88-entry inventory and the merged 606-import/88-removal gate,
   expanding them with each added profile. Keep remaining native metadata
   differences explicit until their implementation and acceptance are complete.

The next implementation branch must start from merged `main` containing PR #39's
`448c4090eda0afc63b8f8def3e671dd85f712e8f`. The creation-time profile, APFS v0.7.0
integration and actual-merge audit are complete. Remaining D04 profiles require
their own implementation and evidence. Merge and release gates still apply.

## 7. Common differential acceptance matrix

Use this matrix to select cases for each slice. Cover every relevant value and use
pairwise combinations for broad interactions, then exhaustive combinations for
high-risk trust, preservation, alias and multi-signature cases. The full Cartesian
product is not required, but exclusions need a reason and an explicit scope limit.

| Dimension | Cases to include where applicable |
| --- | --- |
| Producer/consumer | Native to Go on all OSes; each Go OS to native; committed public fixtures to all OSes |
| Operation | Sign, force re-sign, verify, display/extract, remove, dry run, standalone validate/merge |
| Representation | Thin/universal Mach-O; supported app/bundle/framework layouts; DMG; detached; generic/xattr |
| Architecture | arm64, x86_64, real supported legacy/subtype fixtures; native default and explicit selection |
| Identity | Ad-hoc, RSA, each supported EC curve, real Apple-issued public fixtures, new algorithms/providers |
| Signature state | Unsigned, valid, linker-signed, malformed, oversized old allocation, multiple directories/slots |
| Metadata | Default, explicit, preserved, explicit override of preserved, missing, malformed and contradictory |
| Bundle structure | Nested code, alternate framework versions, helper paths, resource-only changes, shallow/deep |
| Path | Absolute/relative, canonical/alias, alias followed by `..`, Unicode/case variants, broken/cyclic/outside links |
| Host filesystem | Supported APFS and other claimed Mac filesystems; Linux; Windows volumes, ACLs, ADS and readonly states |
| File identity | No link, internal/external hard link, symlink chain, inode replacement and source changed during operation |
| Resources | Required/optional/omitted/nested/symlink seals, added/removed/changed bytes, xattr sideband, strict selectors |
| Trust | Explicit pin/root, missing root, alternate chain, wrong usage, expired/future/revoked, unavailable service |
| Time/network | Fixed time, valid/invalid timestamp, replay/fresh token, timeout/cancel, proxy/redirect/error framing |
| Output | Whole bytes/tree, parsed authenticated fields, raw stdout/stderr, status, extracted files and file list |
| Failure timing | Parse, identity selection, traversal, hashing, signing, network, staging, metadata restoration, commit |
| Scale | Empty/minimal, typical, boundary, above-boundary, large sparse and adversarial bounded inputs |

High-risk combinations that need explicit named cases include:

1. Force + selected preservation + explicit override + different per-architecture
   old metadata; then repeat for linker signatures and malformed old signatures.
2. Deep signing + nested framework versions + constraints/entitlements + failure
   in a later child, with exact before/after tree and metadata comparison.
3. Symlink input + physical filename-derived identifier + hard-linked target +
   signature growth/shrinkage + dry run/removal.
4. Multiple CodeDirectories + CMS hash-agility + native preferred slot + damaged
   alternate directory or hybrid component.
5. Expired signing certificate + valid/invalid/untrusted timestamp + explicit
   requirement + current-time versus authenticated-time policy.
6. Detached versus embedded signature disagreement + resource changes + selected
   architecture, including a detached certificate set from another object.
7. Multi-target `--continue` + output extraction/file-list collision + one failed
   write, with aggregate exit status and subsequent-target behavior.
8. Large streamed input + cancellation/source mutation/disk exhaustion + metadata
   restoration, with no unexplained partial success.

### Required evidence record per acceptance case

Capture enough information to reproduce and audit the result:

- Case ID, work-package/inventory IDs, profile scope and expected native behavior.
- Input hashes, fixture source/license, generator source revision and command.
- Native OS/build/architecture/tool hash, locale/timezone and relevant filesystem
  properties; producer OS, Go version and tested project commit.
- Exact argument vector, nonsecret configuration, working-directory relationship,
  selected trust roots/time and external-provider prerequisites.
- Raw native and Go stdout/stderr, exit statuses and complete output hashes or
  chunk/tree manifests; metadata snapshots where filesystem behavior matters.
- Explicit nondeterministic fields and independent validation of their meaning.
  Never normalize an unexplained mismatch out of the comparison.
- Verification commands/results from Apple and any supplemental independent
  cryptographic parser, plus negative mutation outcomes.
- Any skipped/unavailable portion and its effect on the compatibility claim.

Store private keys only for deliberately public test identities. Live credential
tests should retain public outputs and redacted command/configuration evidence,
not passwords, access tokens or confidential signing material.

## 8. Decision and risk register

These questions must be resolved by evidence or an explicit scope decision when
their implementation is reached. They do not block writing or reviewing this plan.

| Question/risk | Owner | Required resolution |
| --- | --- | --- |
| Published Apple source differs from the installed macOS 27 binary | WP-01 | Native probe wins for that baseline; record the source discrepancy and hashes |
| Unicode/metadata cannot be represented faithfully on a producer filesystem | WP-03/WP-16 | Prove a declared carrier/virtual representation or retain the limitation; no silent renaming |
| Bundle replacement needs functionality missing from APFS's public API | WP-02 | Small upstream API with tests and release, then consume it |
| Replacing in-place writes changes hard-link, ACL or failure behavior | WP-02 | Compare each write class independently; avoid assuming one strategy fits all formats |
| Native verification differs from the library's explicit-trust contract | WP-10 | Separate policies/results or documented migration; no silent trust weakening |
| A private format/algorithm lacks native fixtures or usable credentials | WP-14/WP-18/WP-19 | Acquire legitimate public evidence/authorized test access or retain an explicit blocker |
| Authenticated networking pulls an Apple bridge through dependencies | WP-13/WP-19 | Audited portable implementation or unresolved transport requirement; preserve guards |
| Larger signatures/files exceed allocation and parser budgets | WP-07/WP-18/WP-21 | Streaming, checked arithmetic and measured budgets before lifting bounds |
| Apple behavior changes with OS, locale, architecture or trust state | WP-01/WP-20/WP-23 | Versioned profiles and recorded environment; no universal claim from one host |
| Native input acceptance would require unsafe/unbounded behavior | WP-21 | Document a safe divergence; it remains an exception to literal full equivalence |
| Live state or a non-exportable key is unavailable | WP-22 | Actual authorized access or explicit unresolved original requirement |
| Coverage rises while native feature evidence stays incomplete | WP-23/WP-24 | Keep statement coverage and feature verification as independent gates |
| Research reference uses incompatible license/runtime dependencies | WP-01 | Independent implementation or compatible reviewed component with attribution |

## 9. Definition of done for a feature PR

- [ ] State the concrete native behavior and baseline/profile being added.
- [ ] Identify the work-package and inventory entries affected, with remaining
  scope spelled out; do not mark an umbrella complete after one successful case.
- [ ] Include pinned source/Clang evidence and independent native fixtures/probes.
- [ ] Implement parser, operation, verifier, inspection and CLI behavior needed by
  the claim, with explicit errors for unsupported subcases.
- [ ] Reuse APFS APIs for image/metadata mechanics; consume a released dependency
  if an upstream change was required.
- [ ] Test failure boundaries, malformed inputs, cancellation and important option
  interactions, including original-file preservation where promised.
- [ ] Pass required execution/native-import checks and coverage strictly above 95%
  for every production package on every required OS.
- [ ] Pass golangci-lint, dependency/provenance guards and relevant race/fuzz checks.
- [ ] Verify deterministic bytes or precisely declared cryptographic invariants;
  inspect required filesystem side effects and raw CLI outputs.
- [ ] Audit the actual final commit's artifacts and record workflow/commit links.
- [ ] Update docs, help/API comments, source/fixture manifests and inventory together.
- [ ] Explain remaining risks, unavailable credentials and untested native profiles
  in the PR; do not count unavailable evidence as passed acceptance.
- [ ] Present a focused PR for the user to merge. Do not publish a release or
  merge the PR as a side effect of finishing an implementation slice.

## 10. Full-objective completion gate

The original objective is complete only when **all** of the following hold:

1. Every original and subsequently discovered codesign capability is implemented
   and independently verified for the declared native scope, including live-state
   and hardware/provider behavior rather than substitutes.
2. Native-compatible defaults, outputs, errors, filesystem effects and interactions
   are covered, not just valid signature creation.
3. The same production Go implementation executes on Linux, macOS and Windows
   without Apple code-signing frameworks, helper executables or runtime SDKs.
4. Every production package exceeds 95% coverage and the full portability,
   provenance, native acceptance and distribution gates pass for the shipped commit.
5. `spec/compatibility.json` truthfully contains no unresolved entry, its
   `full_parity` value is justified, and `make release-check` passes without bypasses.
6. Deliberate limitations, unavailable state and version-specific differences have
   actually been resolved for that claim. Documenting a blocker is not resolving it.

Until then, continue delivering useful, independently proven partial capabilities
with accurate release notes. The historical baseline and dated merged milestones
above are distinct; recording a delivered profile does not close its outstanding
work package or the full original objective.
