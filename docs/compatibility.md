# Compatibility status

The baseline is Apple `codesign` on macOS 27.0, build 26A428, arm64. The executable
and manual hashes are recorded in `spec/compatibility.json`; fixture provenance
is recorded in `testdata/macho/manifest.json`. A different macOS build must be
tested independently. Native display output and defaults can change by OS version.

The implementation is partial. No broad native feature is marked fully verified
merely because a representative case passes. Coverage describes exercised Go
statements, not the percentage of Apple's functionality implemented.

| Area | Implemented and tested | Remaining requirements |
| --- | --- | --- |
| Mach-O parsing | Thin 32/64-bit, both byte orders; fat 32/64-bit; bounds and overlap checks | Host acceptance for legacy architectures and unusual load-command layouts |
| Ad-hoc signing | SHA-256 CodeDirectory, signature allocation, all slices, replacement, identifiers, page size, selected flags, runtime version | Header expansion, alternate digests, scatter/pre-encrypt forms, full metadata preservation |
| Certificate signing | RSA and ECDSA P-256/P-384/P-521 CMS, PEM identities, Apple hash-agility attributes; host verifies thin/fat output | Native allocation and requirement synthesis, PKCS#12/encrypted keys, timestamps, hybrid signatures |
| Entitlements | XML and DER encoding, executable flags, extraction; typed plist values | Full malformed-input/error parity, constraints, macOS 27 hybrid signing interactions |
| Requirements | Identifier, CDHash, leaf certificate hash, boolean operations, standalone binary requirements and designated sets | Other certificate/anchor predicates, Info.plist predicates, complete native grammar and diagnostic output |
| Verification | Code pages, special slots, supported requirements, CMS integrity, explicit leaf pins, certificate validity/purpose | General CMS/BER forms, chain/Apple policies, timestamps, revocation, platform strictness, notarization |
| CLI | Cobra dispatch; native grouped short options; explicit Viper config; sign/verify/display/remove subset | Every native option and combination, complete diagnostics/exit behavior, detached signatures |
| Formats | Embedded Mach-O signatures | App/framework/plugin bundles, resource envelopes, UDIF/DMG, generic-file/xattr representations |
| Host state | Explicit unsupported errors | Hosting/PID verification, system detached database, keychain selection and non-exportable keys |

## Exact comparisons currently exercised

The live macOS suite signs the same unsigned files using Apple and the compiled
Go CLI. For arm64, x86_64, and universal files, it compares every output byte for:

- Default ad-hoc signing with an explicit identifier.
- XML/DER entitlements.
- Entitlement-derived executable flags.
- Hardened-runtime metadata.
- An explicit designated identifier requirement.
- An explicit 4096-byte signing page size.
- The hard, kill, and library-validation flags.

Apple also verifies each Go output with `--verify --strict --verbose=4`.
The suite compares stdout, stderr, and exit codes for five verbosity levels on
the arm64 ad-hoc fixture, compares rejection of binary-plist entitlement files,
rejects a modified code page, and executes the host-architecture Go-signed fixture.
These cases do not establish compatibility for other inputs or feature combinations.

## Library extensions and limits

`EncodeEntitlements` can convert a binary plist to XML/DER. Apple's CLI rejects
binary-plist entitlement input on the pinned baseline, and this CLI reproduces
that rejection. Library conversion is an extension, not a native CLI parity claim.

`Identity` accepts an exportable RSA/ECDSA signing key and leaf-first raw DER
certificates. `LoadIdentityPEM` loads supported unencrypted PEM forms. Certificate
verification requires an explicit leaf pin in `VerifyOptions.TrustedCertificates`;
page hashes alone never prove certificate-backed validity. These portable trust
inputs and the `-s FILE --key FILE` CLI convention are extensions, not native
keychain behavior. See [certificate signing](certificates.md) for exact limits.

Twelve certificate cases are accepted by Apple and independently verified by
OpenSSL, with code/CMS tampering rejected by both Apple and Go. Their allocation
and default designated requirements are not yet exact matches for Apple's.

The file writer constructs all slices before writing and preserves the target's
inode, permissions, ownership, and attributes through in-place writes. It rejects
non-regular write targets. A write, sync, or truncation failure can leave partial
data; concurrent modification is not a supported transactional operation.

Parsing recognizes more legacy forms than signing has been proven to reproduce.
Large files, a signature located before the end of a slice, and insufficient
load-command space can return explicit unsupported errors.

## Full-parity gate

`spec/compatibility.json` inventories the native manual options plus format and
host-state requirements. The statuses `partial`, `not-implemented`, and `blocked`
all prevent release. `python3 scripts/guards.py --require-complete` deliberately
fails while any remain. An unsupported error is not a successful implementation.

Clang can expose declarations and source-level structure. It cannot reconstruct
the current contents of another machine's kernel, retrieve a non-exportable key,
or supply unpublished behavior simply by parsing headers. Those constraints
remain visible in the inventory rather than being replaced by a native bridge.
