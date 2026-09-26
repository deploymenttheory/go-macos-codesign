# Resource symlinks in default verification

Default bundle verification now compares each resource link's text with its V2
seal without resolving or opening the target. This follows Apple's complete
`validateSymlinkResource` body and independent native probes. Matching dangling
links, cycles, chains, directory links, absolute targets and relative targets
outside the resource base can therefore verify successfully. Changing the link
text still reports a modified resource, even if both spellings reach the same
content. Separately discovered regular resources retain their own integrity checks.

The verification scan uses the held `os.Root` to read each link itself. It never
walks through a resource link, hashes a target through it, or promotes target text
into a read/write path. This also applies to `--deep` child-resource scans. Shallow
verification continues to skip a nested child's ordinary resources. Framework
diagnostics retain Current/A/direct selection as before.

Signing, signing dry runs and removal retain their existing discovery policy.
Signing still requires supported relative targets that resolve within the opened
root and pass the lexical resource-base guard. This change does not allow writes
through external links. Structural framework aliases, metadata/executable links,
signature-envelope links and `.DS_Store` links keep their separate rules.

The existing 1,024-byte link-text and shared input budgets remain. Windows target
separators use the existing POSIX conversion. Drive/UNC spellings, Unicode target
normalization, reparse-point classes, concurrent tree mutation and full native
path-limit behavior are not claimed as equivalent.

## Native strict policy remains outstanding

The additional complete Apple body has arm64/x86_64 Clang AST evidence in the
[resource manifest](../spec/apple-resource-verification.json), bringing that driver
to nine complete bodies. It compares `readlink` text before `realpath`; destination
restriction requires both the strict and restrict-symlink flags. Its referenced
outer-scope/resource-rule implementations are declaration-only interfaces here.

Live tests show why this alone is insufficient to implement `--strict`: plain
`--strict` and `--strict=all` can report ENOENT or ELOOP before the resource
validator, whereas `--strict=symlinks` reports an invalid destination with modified
resource details. Existing system targets, sealed internal targets, excluded
targets and external targets also have distinct behavior. All three forms remain
explicitly unsupported by the portable CLI; no strict request silently falls back
to default verification. The next phase must establish selector parsing, earlier
traversal, resource inclusion and outer-bundle scope before exposing those options.

One hosted Mac run terminated the native process while checking a cyclic framework
with `--strict=all` (exit -1, empty output). Its signal was not captured by the
original harness. The same framework case passed 100 consecutive local runs;
the cause remains unresolved. The harness now logs the process state, executable,
arguments and both output streams for signal termination. The assertion remains
a hard failure: termination is neither an accepted strict outcome nor parity
evidence, and there is no automatic retry that could conceal it.

## Acceptance evidence

[The tests](../acceptance/resource_symlink_test.go) add:

| Matrix | Cases | Assertions |
| --- | ---: | --- |
| App/framework × ad-hoc/RSA × 17 link states × unchanged/retargeted × quiet/verbose | 272 | Default result, library validity, exact native raw output and preserved tree |
| App/framework child × three link states × unchanged/retargeted × shallow/deep × text/JSON | 48 | 24 exact native profiles and 24 parseable JSON reports |
| App/framework × eight rejected signing targets × real/dry-run signing | 32 | Existing signing rejection and complete input preservation |
| Apple signs app/framework × 17 states × quiet/verbose | 68 Mac-only | Independently native-produced seals verify with exact output |

All 352 portable cases run on Linux, Windows and Mac; Mac adds 68 native-signing
records. There are 364 new exact native verification profiles in total. The 34
verbose native-signing records also retain 102 native strict observations and
explicit portable unsupported responses. Strict output is evidence of remaining
work, not a parity claim.

The portable matrices carry 568 comparable hashes: 224 relative-target input trees
and 272 normalized diagnostics in the main matrix, 48 nested trees and 24 relative
signing-rejection trees. Another 56 absolute-target input hashes are host-specific;
Windows may store a different absolute target spelling. Native signing contributes
68 additional host-specific hashes. Raw output is retained. Diagnostic hashing
only replaces the temporary fixture root and Windows separators; exact host
comparisons do neither.

The twelve dangling-link records introduced by PR #63 now require exact native
output and status. Removing a required target reports a missing resource;
retargeting a link to a missing target reports a modified link; removing an optional
target is accepted. The four previous native-acceptance differences are resolved.
The retained 382-case resource matrix now has 318 exact profiles and 40 explicit
ordering/primary-summary profiles. Its 686 comparable hashes remain in the audit.

## Dependency integration

This phase first updates [go-apfs-v2 to v0.11.1](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.11.1),
with published module checksums and no APFS replacement. The corrective follow-up
updates again to [v0.11.2](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.11.2),
published during validation, which bounds decmpfs LZFSE decoding to the caller's
buffer. Native DMG signing,
foreign imports and packaged dependency provenance validate the upgrade. Its
streaming APIs and codec fixes remain upstream-owned; codesign's bounded adapter
does not gain streaming behavior merely from this version change.
