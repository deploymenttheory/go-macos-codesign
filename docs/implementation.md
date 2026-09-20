# Implementation stages

The implementation remains incomplete against the full original objective.
The stages below retain all requirements rather than declaring a smaller scope
to be complete.

The [detailed implementation plan](implementation_plan.md) expands this overview
into a complete post-PR #25 backlog, with all 55 inventory entries mapped to
24 work packages, dependencies, native acceptance criteria and proposed PR slices.
Work has resumed through the first D04 writer slice. The expanded D01 inventory
now retains 88 obligations; [native inventory](native-inventory.md) and
[file writes](file-writes.md) describe the evidence and remaining differences.

The certificate-chain/Team ID/PKCS#12 phase and RFC 3161 core are merged. Online
HTTP timestamp acquisition is merged in [PR #10](https://github.com/deploymenttheory/go-macos-codesign/pull/10).
The first [app-bundle phase](bundles.md) adds deterministic resource envelopes
and native acceptance for a bounded Contents-based layout.
The [DMG phase](dmg-integration.md) now directly imports go-apfs-v2 for its UDIF
model and adds signing, verification and inspection around that implementation.
Binary bundle metadata now extends the app profile with bounded object-graph
decoding and independent native comparisons for two binary encodings.
Nested Mach-O helpers/dylibs and Contents-based APPL .app trees add designated-
requirement seals, staged recursive signing, shared limits and shallow/deep
verification. Contents-based BNDL/XPC! layouts, unversioned and multiple-version
frameworks, and bounded relative resource symlinks now extend that profile.
Explicit version selection, alternate-version requirement validation and direct
physical/Current version-directory inputs are implemented. Supported main-executable
paths now select their bundles. Standalone file aliases select the physical target
for signing/removal, default identifiers and display; Mach-O replacement reuses
go-apfs-v2's metadata API. Bundle executable replacement now preserves external
hard-link neighbours while keeping resource envelopes in place. Wider discovery and bundle symlink/xattr policy remain next.
See [progress](progress.md) for the tested commit, native evidence and coverage.

| Stage | Current result | Outstanding work |
| --- | --- | --- |
| Repository and research | Go module; Cobra/Viper CLI; local and GitHub references; Clang SDK, C/C++ and Objective-C excerpts for formats, allocation, requirements, Team IDs and timestamps | Wider source/control-flow coverage and full private translation units where reproducible |
| Binary formats | Bounded Mach-O/fat parsing, SuperBlob, versioned CodeDirectory, hashes, requirement subset, XML/DER entitlements | All historical/new slots, scatter/pre-encrypt data, full requirements and constraints |
| Ad-hoc writer | Thin/fat signatures, replacement/removal, version and executable metadata, exact signing fixtures; native removal padding, virtual-size and alignment comparisons | Header expansion, legacy digest selection, detached formats, wider removal/preservation/error semantics |
| Certificate signing | PEM/PKCS#12 keys; RSA/ECDSA CMS; native allocation/BER; RSA byte parity; organization/Developer ID requirements, Team IDs and certificate metadata | Encrypted PEM, full Apple policy and requirement synthesis, native localized display, end-to-end Developer ID signing evidence and hybrid algorithms |
| Timestamps | RFC 3161 verification/providers, nonce-bound SHA-256 exchanges, direct HTTP CLI acquisition, pinned Apple roots, deadlines and cancellation; live native verification on three Mach-O forms | Broader TSA/Apple policy, revocation, proxy/redirect behavior and additional CMS/BER forms |
| Bundles and resources | Contents-based APPL/BNDL/XPC! and unversioned/multiple-version FMWK discovery; main-executable inputs, explicit selection and direct version-directory inputs; XML/binary metadata; deterministic v1/v2 CodeResources; nested and alternate-version requirements; relative symlink seals; staged recursive signing, shared budgets and deep verification; native byte/mutation comparisons | Wider discovery and symlink/xattr policy, requirement/digest variants, full strict verification |
| Other representations | Single-segment UDIF v4 signing/verification/inspection via go-apfs-v2, native trailer binding, identifiers and byte comparisons | Large-image streaming, encrypted/segmented images, detached/generic/xattr files and certificate interchange |
| Verification and policy | Page/special-slot checks, supported requirements, CMS integrity, explicit leaf pins and CA roots, bounded chain validation, purpose/validity and Team ID checks; RFC 3161 signature/imprint/ESS binding and separate TSA roots | General CMS/BER forms, full PKIX and Apple timestamp policy, revocation, notarization and constraints |
| Host-state features | Blockers recorded | A provable portable equivalent for hosting/PIDs, native keychain/database state, and non-exportable hardware identities; none is currently available |
| Proof and distribution | >95% package coverage gate; host differential tests; three-OS CI; Apple verification of 522 signed artifacts and 88 removal byte comparisons configured for Linux/Windows; six-target GoReleaser builds, SBOMs/checksums and App-based Release Please; successful v0.1.0 release workflow; golangci-lint, race and nine fuzz targets | Validate each changed commit and authorized tagged release, extend acceptance to every feature/input class, clear every full-parity blocker |

## Next implementation sequence

1. **Extend bundle compatibility:** retain the tested resource, nested Mach-O
   and recursive bundle/framework profiles while extending executable discovery,
   broader symlink/xattr policy and full strict
   verification. Expand the pinned source/Clang record and independent host
   comparisons for each added case.
2. **Extend representations:** retain go-apfs-v2 as the DMG format dependency,
   add bounded streaming for large images and broader image/policy cases, then
   detached and generic-file representations. Keep image codecs and filesystem
   handling in the APFS project; see the [integration boundary](dmg-integration.md).
3. **Wider signature and policy compatibility:** add remaining requirement
   predicates, CodeDirectory/digest variants, preservation semantics, certificate
   and timestamp policy, and diagnostic parity with independent acceptance cases.

These are proposed implementation stages, not delivered capabilities. Host-state
features retain the portability blockers described below.

## Requirements for every phase

Each new capability needs source/AST evidence, malformed-input handling, meaningful
unit tests, a standalone Linux/Windows execution path, and independent host
acceptance. Deterministic signatures require exact bytes; randomized signatures
and timestamps require independently checked cryptographic/content invariants
with every permitted difference declared in the case definition.

Certificate and network work must preserve the no-native-framework boundary.
The standard `crypto/x509` package currently brings a macOS trust bridge into
Darwin binaries, including indirectly through `net/http`. Certificate decoding now
uses portable ASN.1, explicit leaf pins and caller-supplied roots. Future network work must
continue to audit the entire linked dependency graph. Disabling CGO alone is not
sufficient evidence.

The local Afero dependency copy removes only its unused HTTP adapter and retains
hashes and attribution for every included upstream file. Dependency upgrades
must preserve that audit and pass `scripts/guards.py` on all target platforms.

Full parity is not attainable for live macOS state on an independent non-macOS
host without access to that state. Those entries remain blockers; a saved snapshot
or an unsupported response is not an equivalent implementation.
