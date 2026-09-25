# Testing and release evidence

The [progress report](progress.md#recorded-validation) records the measured
coverage and native results for a specific implementation commit. This guide
explains how to reproduce those checks and interpret their limits.

## Local commands

```sh
make verify
make lint
goreleaser check
make snapshot
```

GoReleaser is the build/packaging tool. Go and Python research drivers perform
development-only Clang AST extraction. Python also checks fixture provenance,
audits dependencies and aggregates coverage.
The acceptance harness builds an instrumented CLI using Go's native coverage
support; it does not invoke an installed copy of the implementation.

`scripts/verify.py` creates fresh coverage directories on every invocation. It
combines atomic statement profiles from unit tests and subprocess CLI tests,
counts each statement once, and requires more than 95% in every package under
`pkg/`, `internal/`, and `cmd/`. Tests and upstream dependency code are not included
in the production statement denominator. New production packages enter the gate
automatically through `go list`.

The resulting files under `artifacts/` include:

| File | Evidence |
| --- | --- |
| `coverage.out`, `coverage.json`, `coverage.html` | Exact statement counts and source-level coverage |
| `unit.jsonl` | Raw `go test -json` unit-test transcript, retained even when tests fail |
| `acceptance.jsonl` | Raw `go test -json` subprocess acceptance transcript |
| `acceptance.json` | Current-run byte comparisons, hashes, and execution attestations |
| `provenance.json` | Host/tool versions, Apple executable hash on Mac, source and fixture hashes, and `.gitattributes` hash |

On failure, the verification script prints the failed tests' output and package
diagnostics in the CI job log. Full transcripts and provenance remain available
in the `evidence-<runner>` artifact uploaded even if a test fails. Apple fixture
comparisons report both file lengths and SHA-256 hashes, the first differing
offset, and nearby bytes. Entitlement cases also record the input XML hash and
line-ending counts. The XML fixture is pinned to LF in `.gitattributes` because
its bytes are embedded verbatim in the signature; automatic CRLF conversion
would change the comparison input on Windows.

The committed fixtures are small executables compiled from this repository's
`testdata/src/hello.c`. `scripts/gen-fixtures.py` regenerates them on a development
Mac and records Apple signing, display, verification, and hashes in the manifest.
Fixture generation is explicit: normal tests never rewrite expected results.
The three [native app fixtures](../testdata/bundles/README.md) wrap those small
programs with public XML/resources and carry a separate manifest. All bundle
fixture bytes, including Info.plist, are protected from CRLF conversion.

## Host acceptance

Set `MACOSCODESIGN_REQUIRE_APPLE=1` to make absence of a Mac reference host a test
failure. On non-Mac hosts, Apple-only tests explicitly skip while portable fixture
comparisons and CLI tests still run. Skipped Apple checks are not evidence of
native parity.

The ad-hoc matrix contains 21 exact signing comparisons, five exact display
comparisons, binary-entitlement rejection, tamper rejection, and successful native
execution of an ad-hoc file signed by the Go CLI. The local baseline is macOS
27.0 build 26A428. A passing case is evidence for that case and baseline only.

Certificate acceptance adds 12 combinations: RSA and ECDSA P-256/P-384/P-521,
each signing arm64, x86_64, and universal files. Apple verifies each output,
OpenSSL independently checks every architecture's detached CMS, and Apple/Go
reject modifications to both code and CMS data. Certificate cases establish
cryptographic integrity and native acceptance, not byte equality with Apple.
Published self-signed identities under `testdata/identities` are test data only.
Two certificate-hash requirement expressions are also compiled by Apple's
`csreq` and compared byte for byte with the Go compiler output.

`TestAppleNativeCertificateLayout` adds 64 native signing comparisons using
temporary keychains containing public test identities: 28 RSA cases require
complete slice byte equality at matched signing times, and 36 ECDSA cases require
matching layout and non-CMS bytes with independent verification. Twelve native
fixtures under `testdata/certificate-layout` are verified by the library and CLI
on all three operating systems. Their provenance and hashes are committed;
authenticated CMS attributes and algorithm encodings are also compared. See the
fixture README for explicit regeneration instructions.

Chain acceptance adds three native organization-anchor comparisons and a
Developer ID requirement comparison against `csreq`. A real public Developer ID
chain establishes Team ID recognition at a fixed historical time. Twelve
PKCS#12 fixtures cover modern and legacy algorithms; 24 signatures from those
imports pass native strict verification. These use public test identities, not
an end-to-end Developer ID signing credential.

Bundle acceptance adds exact executable and CodeResources comparisons for three
ad-hoc apps, fifteen display comparisons (five per architecture), eleven mutation
cases and six ad-hoc/RSA apps verified by Apple. Go reproduces the committed
Apple app fixtures on every OS. Tests also cover force/removal, dry runs and
unchanged files after timestamp failure. Layout, path, XML and filesystem
rejection cases run in unit tests. See [bundle scope](bundles.md).

Signing-envelope acceptance adds 84 directory cases over seven layouts and six
operations, plus 20 parent/child cases for commit order, shallow signing and
outer-only removal. Twenty read-only/write-only envelope cases run on POSIX hosts;
Windows explicitly skips those mode-bit probes. A host that bypasses the intended
permission denial also skips. Complete trees, raw status/output, executable inodes
and external hard-link neighbours are compared independently with Apple on macOS.
Successful deep rewrites pass strict native verification after the test restores
read access for inspection. The existing 606-import/88-removal gate is retained.

Binary bundle metadata adds six native byte comparisons, thirty display cases,
twelve ad-hoc/RSA strict-verification cases, four metadata mutations and one
binary-resource-envelope case. Three Apple-signed fixtures preserve `plutil`
output and run on every OS. Hand-built malformed graphs exercise offset/length
overflow, references, cycles, duplicate keys, Unicode and expansion bounds.
`FuzzBundleResources` includes binary seeds from Apple and malicious graphs.

Nested-code acceptance adds fifteen exact parent/envelope/child comparisons,
75 display cases and nine ad-hoc/RSA/P-256 apps accepted with native strict deep
verification. Six mutations are checked with both shallow and deep verification.
Three native fixtures include real dylibs; seventeen standalone comparisons cover
canonical filenames, UUID suffixes and the UUID-less fallback. Requirement text
is checked against Apple's dumper, including boolean precedence, subject fields,
extension existence and non-ASCII values. Unit tests cover explicit child trust,
hard links, limits, malformed seals, cancellation and preservation on failure.
`FuzzRequirementText` exercises the expanded parser and canonical text stability.

Recursive APPL acceptance adds 24 complete tree byte comparisons, 90 display
cases, eighteen ad-hoc/RSA/P-256 native strict deep checks and 26 mutation/depth
outcomes. Three committed native trees combine XML parents/grandchildren, binary
child metadata, two plain helpers and a dylib. Native lifecycle tests check
preserved signed grandchildren, force, dry runs and outer-only removal. Altered
immediate-child Info.plist, requirements and entitlements fail shallow validation;
resource contents and deeper descendants require `--deep`. Unit tests enforce
shared entry/byte/depth/node limits, cross-bundle hard-link rejection and complete
tree preservation after later signing failures. An independent local TSA signs
all twelve architecture signatures in a universal tree, checks child TSA trust,
and proves dry-run and late-response-failure preservation without native trust setup.

Bundle-layout acceptance adds 36 standalone native byte comparisons, 180 display
cases, twelve mixed-tree byte comparisons and 63 ad-hoc/RSA/P-256 native strict
deep checks. Six layouts cover `.bundle`, `.plugin`, `.xpc`, `.appex`, unversioned
frameworks and single-version frameworks. Thirty-nine mutations are checked in
both shallow/deep modes, including symlink text/type/target changes and framework
aliases. Eighteen native archives are verified and reproduced on every OS; the
plug-in inputs are real Clang-generated MH_BUNDLE files. Mixed trees include
seven bundles and nine Mach-O files. An independent TSA exercises all eighteen
architecture signatures, dry runs and late-failure preservation. Unit tests
cover malformed framework roots, shared limits and cross-layout hard links.
Native removal comparisons now require exact bytes for all six layouts on three
architecture forms and three mixed trees, including the main executable and empty
signature-directory preservation. The earlier eight-byte padding exception is
removed. [Removal acceptance](removal.md) adds 44 independently recorded native
outputs, 44 live host comparisons, and nine native re-signing comparisons. Unit
tests cover malformed symbol ranges, command relocation, endian/32-bit forms and
preservation after later-architecture failure.

Framework-version acceptance adds twelve selected-signing tree comparisons,
ninety exact display comparisons, six selected-removal comparisons and six dry
runs across XML/binary metadata and three architectures. Twenty-one parent cases
check unsigned, differently signed, wrong-requirement, page, resource and metadata
variants in both shallow/deep modes, while standalone Current remains valid.
Nine ad-hoc/RSA/P-256 trees pass native strict deep verification. Three native
app archives are reproduced byte for byte on each OS. That phase expanded the
Clang layout record to seven methods, adding selection and alternate validation.
Unit tests cover selection boundaries, unsafe names, budgets and cross-version
hard links. These checks establish a bounded profile, not all native options.

Direct-version directory acceptance adds eighteen complete signing/removal
comparisons and dry runs, ninety display comparisons, four independent-boundary
cases and 64 selector rejection/preservation checks. Physical A/B and Current
paths cover XML/binary metadata and three architectures. Nine identity/architecture
trees are produced through direct paths; ad-hoc trees reproduce the existing
native archives. Unit tests reject malformed Current targets and retain the
selected directory's hard-link protection. The AST layout record now includes
eight complete methods, adding native directory/file representation discovery.
Two additional path cases compare an intermediate symlink followed by `..` with
Apple, require preservation of the lexical sibling, and verify the physical
target even when that sibling is absent. Different Current targets catch early
Windows path normalization.
Six further direct-path trees include an unsigned Mach-O helper; deep signing
reproduces Apple's complete tree and passes strict deep verification.

Executable-path acceptance adds 54 complete native signing/removal comparisons,
270 exact display comparisons and 54 dry runs across nine input profiles,
XML/binary metadata and three architectures. Four main/helper/file-alias cases
compare complete trees and resource-tampering outcomes. Read-only hard-link
discovery matches native display; [separate writer tests](file-writes.md) cover
standalone hard-link replacement. A parent-link test signs the physical target while
preserving the lexical neighbour, including when that neighbour is absent.
Thirty-two option-operation outcomes compare executable-input version selection.
Nine ad-hoc/RSA/P-256 mixed trees sign every child through its executable before
the parent; eighteen child archives reproduce existing native fixtures. Native
CI checks nine executable paths and the parent of each exported tree. Five
complete CoreFoundation discovery functions have two-target Clang AST evidence.

Standalone aliases add 150 Mach-O cases spanning three architectures, five path
forms, default/explicit identifiers and signing/re-signing/removal/unsigned-removal/
dry-run operations. Ten DMG cases check signing and re-signing in place. All check
preserved alias text and physical target behavior; Mach-O cases also check detached
hard-link neighbours and cleanup. A lexical neighbour catches premature `Clean`
or `Abs` on `link/..`. macOS compares all final file bytes and 350 complete display
outputs with Apple. Nine allocation cases seed nonzero padding before re-signing
with shorter, same-allocation and longer identifiers. Broken/looping links fail
eight CLI operations without writes. These tests emit deterministic output hashes
on every OS for comparison against the native-checked macOS outputs.
Five complete path functions have two-target Clang AST evidence. See
[file-write behavior](file-writes.md) for the supported metadata contract.

Bundle writer acceptance adds 126 layout/architecture/operation cases for main,
nested helper and nested bundle executables. Each checks external hard-link
neighbours, replacement identity, modes, existing/new CodeResources, unsigned
removal and dry runs. macOS compares complete trees against Apple and performs
strict deep verification; each foreign producer exports 84 signed archives.
Fifteen additional native metadata profiles record raw stat timestamps/inodes,
xattrs, ACLs and flags for signing, read-only executables, re-signing, removal and
dry runs. They explicitly preserve evidence of native ACL-inheritance and
creation-time differences. Unit tests cover staging failures before envelope
creation, cancellation, changed targets and cleanup after partial commits.

`make research-inventory` is an opt-in native research driver, outside production
and deterministic CI. Its committed binary/manual hashes and operation records
are checked by the guards. [Inventory boundaries](native-inventory.md) distinguish
parser recognition, executed probes and unavailable live-state contexts.

DMG acceptance adds forty exact signing comparisons and 200 display comparisons
across raw/zlib/LZFSE generated images and APFS/native-LZMA fixtures from go-apfs-v2.
Fifteen ad-hoc/RSA/P-256 images pass native strict signature and checksum checks.
Five committed Apple DMGs are verified on every OS; ad-hoc and matched-time RSA
outputs are byte-identical, while ECDSA compares CodeDirectories and integrity.
Bounds/tampering, replacement, dry runs, native-unsupported removal and TSA
failure preservation are covered. [DMG support](dmg-integration.md) records
the separate live Apple timestamp check and its opt-in command.

`TestDMGDryRun` runs 70 cases on every OS, covering five image profiles, signed and
unsigned inputs, seven option combinations, repeated dry runs and subsequent real
signing without force. The Mac compares complete bytes against native and requires
both tools to report the dry-run image unsigned. Raw diagnostics now match exactly,
including signed-input replacement notices. `TestDMGAccessTime` now
requires all 80 byte comparisons, including the 20 formerly divergent dry runs.
Four Mac permission cases distinguish file-write denial from parent-directory
creation denial. Portable unit tests cover unsigned-container bounds, cancellation,
failed construction, certificate rejection and the unchanged `SignBytes` contract.

Linux and Windows each export 70 `dryrun-dmg-*.dmg` artifacts. The downstream
`TestVerifyImportedDMGDryRuns` requires all 140, compares each complete image with
independent native output and checks that native verification/display reject it
as unsigned. These outputs are separate from the 606 valid signed imports and
88 removal comparisons; unsigned output is the expected native dry-run result.

The [signing-notice matrix](signing-diagnostics.md) adds 92 portable cases and
eight Mac-only failure/continuation cases. It compares exact raw diagnostics for
91 successful/supported-rejection profiles, records the malformed-signature
repair/rejection difference, and checks notice ordering separately from the
remaining OS-error wording. Linux/Windows results are checked against the same
expected strings; Mac independently compares native output and complete bytes.

### Certificate extraction

`TestCertificateExtraction` adds 96 cases: six formats × four identities × four
prefix/display modes. DER bytes must match both independent PEM certificates and
native extraction, including a three-certificate chain with its root. Display
stdout/stderr/status are retained without normalization; source trees remain
unchanged. Temporary input roots are resolved physically before creating fixtures.
Certificate verbose display has two explicit native date profiles at the fixed
fixture time: local `24 Sep 2026 at 12:00:00` and hosted
`Sep 24, 2026 at 12:00:00\u202fPM` (U+202F before PM). Go retains its documented
fixed English UTC form. The hosted profile requires the complete expected output
with exactly that date line; every other character must match. Its eighteen
certificate/verbose records retain both raw outputs, mark `exact_display: false`
and record `remaining_date_profile_difference: true`. They establish extraction
and the other display fields, not localized-date parity. Any other drift fails.

Eight output-lifecycle cases cover in-place truncation/mode preservation, stale
indices, missing parents, first/later directory failures, symlink/hard-link writes
and repeated prefixes. Three multiple-target cases compare overwrite and
stop/continue behavior. Five signature-state cases cover unsigned inputs, changed
pages, damaged CMS and explicit universal-slice selection. Three cases prove the
option is ignored for signing, verification and removal. These 115 cases run on
all producers, recording certificate/output hashes for artifact comparison.

Two Mac cases independently exercise read-only output failure and bundle-parent
alias extraction. The latter now requires identical physical display paths and
DER after the shared directory resolver fix. CLI units cover optional-value
parsing, distinct-slice selection, JSON omission and unknown OS errors. Existing
output identity is captured through `File.Stat` before fixture renames; Windows
path-based `Stat` otherwise loads identity lazily after the path changes. Library
tests compare four certificate algorithms to independent PEM fixtures and prove
returned DER ownership. Extraction does not imply page validity or CA trust.

### Bundle directory-parent aliases

`TestBundleParentAliases` adds 108 cases: nine layouts × three architectures ×
four operands (physical, relative parent alias, chained parent alias, `link/..`).
Each tool operates on a reset fixture at exactly the same pathname, so its five
display levels and sign/verify/dry-run/remove stdout/stderr/status require raw
equality. Complete signed/removed trees, dry-run preservation, unchanged alias
text and untouched lexical-neighbour trees are checked. The Mac also strictly
verifies Go's output; other producers retain signing/removal hashes for comparison
to native-compared Mac records. Six new app/extension regressions fail against
the merged baseline before the resolver change.

Library tests retain direct framework selection/Current safety, final root-alias
rejection (including suffixes), relative directory inputs, missing parents and
volume roots. Older comparisons using different temporary input names now resolve
both fixture prefixes symmetrically; their only substitution remains the exact
fixture prefix. The new same-path matrix performs no substitution.

### Recorded certificate DMG dry-run failures

The opt-in `TestRecordDMGCertificateDryRunFailure` records four native RSA/P-256
memory-fault cases in [a pinned record](../spec/apple-dmg-dryrun-certificate.json).
It uses only public test identities in disposable keychains. Ordinary CI validates
the record's driver/baseline provenance and the Go unsupported-error behavior;
it does not repeatedly trigger those native crashes. To reproduce that research:

```sh
MACOSCODESIGN_RECORD_DMG_DRYRUN=1 go test ./acceptance \
  -run '^TestRecordDMGCertificateDryRunFailure$' -count=1
```

The `xcode-27` hosted runner is selected because its documented image uses macOS
27. Every run records the actual host and `codesign` hash; that rolling preview
image is not assumed identical to the local baseline. Output drift fails the
comparison and must be investigated without silently normalizing it away.

## CI

The test workflow runs the coverage gate on Ubuntu, Windows, and macOS 27. Linux
and Windows jobs upload the actual Mach-O files, app bundles and DMGs they signed,
including hidden resources. A downstream Mac
job downloads both sets and requires Apple's strict verification to succeed for
all 522 imported artifacts (three ad-hoc, twelve PEM, eight PKCS#12, three chain,
one timestamp replay, forty-five app bundles, 63 layout archives, nine multi-version
framework trees, nine direct-path framework trees, nine executable-path trees,
84 bundle-writer archives and fifteen DMGs per OS). Twelve of
each OS's apps use binary metadata: two encodings, three architectures and two
identities. Nine more apps per OS contain two nested helpers and a dylib, covering
three architectures and ad-hoc/RSA/P-256 identities. Another eighteen per OS
contain recursive app trees under XML/mixed-metadata profiles. Both nested groups
require native `--deep`. The 63 tar archives per OS add 54 standalone layouts
(six formats, three architectures and three identities) and nine mixed trees.
Tar retains symbolic links through artifact transport; the Mac safely extracts
each archive and verifies its outer bundle with native `--strict --deep`.
The nine framework-version archives per producer cover three identities and
three architectures; Apple verifies both the parent and explicit A/B selections.
The nine direct-path archives add signing through physical A and Current inputs;
Apple checks their parents, root selections and all three directory input paths.
The nine executable-path archives per OS contain seven bundles signed through
their executable paths; Apple checks the parent and nine executable/alias inputs.
Every native fixture test and producer exercises real filesystem symlinks,
including on Windows; these cases are required rather than silently skipped.
The downstream
job also requires `hdiutil verify` for every imported DMG. Each producer additionally
exports 44 removed Mach-O files. The Mac independently performs native removal of
the same inputs and checks all 88 foreign outputs byte for byte.
Every algorithm/architecture combination must be present from both OS jobs.
These are native OS jobs; cross-compilation alone
does not replace them.

Separate jobs run the Go race detector and ten bounded fuzz targets:
`FuzzInspect`, `FuzzIdentity`, `FuzzCMS`, `FuzzPKCS12`, `FuzzTimestamp` and
`FuzzTimestampHTTP`, `FuzzBundleResources`, `FuzzDMG`, `FuzzRequirementText`
and `FuzzEntitlementMetadata`.
Each CI fuzz target runs for 60 seconds. GoReleaser creates
snapshots with SPDX SBOMs and checksums for all six OS/architecture pairs; PR
snapshots explicitly skip Cosign signing. The race detector's compiler dependency is
confined to test binaries. Every distributed binary uses `CGO_ENABLED=0`.

Timestamp acceptance replays an Apple-issued token into a freshly signed RSA
arm64 file and requires complete native-fixture byte equality. The Mac checks
strict verification and tampering with `codesign`, and independently verifies
TSA CMS integrity and the path at the recorded time with OpenSSL. Every OS
checks explicit TSA trust and historical validity.

`TestCLITimestampHTTP` runs an independent local HTTP TSA on all three OSes. The
compiled CLI signs all Mach-O forms, validates nonce/imprint/signature/trust and
handles chunked replies. The test checks unchanged input after HTTP failure,
deadline expiry, bad tokens and a failed second architecture; dry runs acquire
tokens without writing. Unit tests cover cancellation, header/body limits and
malformed framing. Routine CI contacts only this loopback TSA, not a public one.

On macOS, `TestAppleTimestampOptionParity` compares native and Go ad-hoc results
and exit codes for bare, disabled, custom-HTTP, empty and HTTPS timestamp options.
The online live check explicitly contacts Apple's TSA and is opt-in:

```sh
MACOSCODESIGN_LIVE_TIMESTAMP=1 MACOSCODESIGN_REQUIRE_APPLE=1 \
  MACOSCODESIGN_EVIDENCE_DIR="$PWD/artifacts/live-timestamps" \
  CGO_ENABLED=0 go test ./acceptance -run '^TestCLILiveAppleTimestamp$' -count=1 -v
```

It uses the production CLI transport and native strict verification on arm64,
x86_64 and universal outputs. The JSON attestations retain timestamps, output
hashes and native results. Network/service availability affects this check; it
does not replace deterministic CI. See [timestamp policy and transport limits](timestamps.md).

`go-lint.yml` runs golangci-lint only and fails on reported issues. SuperLinter
is removed. Lint failures are not suppressed or automatically fixed in CI.

## Release automation and full-parity audit

`make release-check` currently fails because the full-parity inventory contains
unresolved requirements. This remains an explicit audit for a full-equivalence
claim; it no longer blocks versioned releases of the documented subset.
[Release Please](releases.md) owns tags, changelog and GitHub releases. The tagged
GoReleaser workflow attaches archives, SBOMs and signed checksums to that release.
It follows the reference project's App-token/PAT and append-release pattern.

Local `actionlint`, `goreleaser check` and snapshot packaging validate configuration
and builds. They do not establish publishing or keyless-signing success. Remote
workflow success must be reported from an actual GitHub Actions run.

## Signature file lists

[File-list behavior](file-lists.md) is tested by 96 portable records:

- `TestFileList`: 76 representation cases, each exercising signing, display,
  replacement and signed dry run; full input trees, raw stdout/stderr, append
  contents and framework dot spelling are checked against native at the same path.
- `TestFileListOutputLifecycle`: 17 cases cover creation/append, preserved output
  mode/inode, symlink/hard-link destinations, last-value selection, output-open
  failures, multiple operands, continuation, preceding certificate extraction,
  unsigned input and ignored verification.
- `TestFileListExternalComponents`: three report-API comparisons establish
  existing-file ordering and embedded-component exclusion. CLI inspection's
  rejection of extra signature files remains explicit.

Mac adds one permission case and six explicit native-crash differences. The
latter are attested as remaining differences, never successful parity. DMG dry
runs compare their actual unsigned bytes and use the pre-signing report for the
list. Known-error fixtures retain exact raw output; no diagnostic normalization
is used. Foreign artifact comparison replaces only the fixture root and path
separator in the already independently checked path records, and compares
signing/replacement/dry-run tree hashes unchanged.

The six-function, two-target AST driver is `scripts/extract-file-list.go`, run by
`make research-paths`; its output is `spec/apple-file-list.json`. Unit tests also
cover byte-only reports, absent/unsigned architecture selection, JSON companion
files, invalid destinations and writer failures. Current-commit coverage, CI and
artifact audit results belong to the implementation PR, not the previous merge.

## Entitlement extraction

`TestEntitlementExtraction`, `TestEntitlementOutputLifecycle`,
`TestEntitlementSignatureState` and `TestEntitlementArchitectureSelection` add 91
portable records: 44 value/representation cases, 26 destination/interaction cases,
18 component mutations and three architecture selections. Mac requires 90 raw
native comparisons; the remaining JSON interaction is an explicit extension.
Inputs are preserved, actual link inode/mode retention is checked, and outputs,
exits and deterministic input/output hashes are attested. Absolute file-list
payloads retain raw native comparison; foreign comparisons must use checked paths
rather than equating OS-specific path bytes.

The [contract](entitlement-extraction.md) distinguishes hash failures, malformed
bound DER, mixed primitive arrays, append mode and the consumed colon prefix.
`FuzzEntitlementMetadata` directly exercises untrusted DER independently of slot
hash checks; CI now runs ten fuzz targets. The six-function two-target
[Clang record](../spec/apple-entitlement-extraction.json) documents source and
private-interface limits. Coverage, native acceptance and downloaded artifact
checks apply to each final commit, not merely the preceding merged milestone.
