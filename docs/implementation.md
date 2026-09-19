# Implementation stages

The implementation remains incomplete against the full original objective.
The stages below retain all requirements rather than declaring a smaller scope
to be complete.

| Stage | Current result | Outstanding work |
| --- | --- | --- |
| Repository and research | Go module; Cobra/Viper CLI; reviewed both local references and other-language projects; Clang SDK AST/layout capture | Reproducible Apple C++ source translation units and a wider source/behavior inventory |
| Binary formats | Bounded Mach-O/fat parsing, SuperBlob, versioned CodeDirectory, hashes, requirement subset, XML/DER entitlements | All historical/new slots, scatter/pre-encrypt data, full requirements and constraints |
| Ad-hoc writer | Thin/fat signatures, replacement/removal, version and executable metadata, exact fixture comparisons | Header expansion, legacy digest selection, detached formats, full preservation/error semantics |
| Certificate signing | Portable ASN.1 identity parsing; PEM PKCS#1/SEC1/PKCS#8; RSA and P-256/P-384/P-521 CMS; Apple hash-agility attributes; leaf-hash requirements; native acceptance | PKCS#12/encrypted keys, complete X.509/Apple chain policy, native allocation/default requirements, hybrid algorithms, RFC 3161 |
| Bundles and resources | External Info.plist/resource hash inputs available in library | Bundle discovery, deterministic resource envelopes, nested signing, symlink/xattr policy, strict verification |
| Other representations | Format boundaries identified | UDIF/DMG signing using reviewed APFS fields, generic/xattr files, detached signatures and certificate interchange |
| Verification and policy | Page/special-slot checks, supported requirements, CMS integrity, explicit leaf pins and certificate purpose/validity checks | General CMS/BER forms, chain building and Apple policy, timestamps/revocation, notarization and constraints |
| Host-state features | Blockers recorded | A provable portable equivalent for hosting/PIDs, native keychain/database state, and non-exportable hardware identities; none is currently available |
| Proof and distribution | >95% package coverage gate; host differential tests; three-OS CI; cross-platform artifact verification; GoReleaser | Execute remote CI, extend acceptance to every feature/input class, clear every full-parity blocker |

Each new capability needs source/AST evidence, malformed-input handling, meaningful
unit tests, a standalone Linux/Windows execution path, and independent host
acceptance. Deterministic signatures require exact bytes; randomized signatures
and timestamps require independently checked cryptographic/content invariants
with every permitted difference declared in the case definition.

Certificate and network work must preserve the no-native-framework boundary.
The standard `crypto/x509` package currently brings a macOS trust bridge into
Darwin binaries, including indirectly through `net/http`. Certificate decoding now
uses portable ASN.1 and explicit leaf pins. Future chain and network work must
continue to audit the entire linked dependency graph. Disabling CGO alone is not
sufficient evidence.

The local Afero dependency copy removes only its unused HTTP adapter and retains
hashes and attribution for every included upstream file. Dependency upgrades
must preserve that audit and pass `scripts/guards.py` on all target platforms.

Full parity is not attainable for live macOS state on an independent non-macOS
host without access to that state. Those entries remain blockers; a saved snapshot
or an unsupported response is not an equivalent implementation.
