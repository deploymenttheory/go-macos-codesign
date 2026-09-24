# Compatibility status

The baseline is Apple `codesign` on macOS 27.0, build 26A428, arm64. The executable
and manual hashes are recorded in `spec/compatibility.json`; fixture provenance
is recorded in `testdata/macho/manifest.json`. A different macOS build must be
tested independently. Native display output and defaults can change by OS version.

The implementation is partial. No broad native feature is marked fully verified
merely because a representative case passes. Coverage describes exercised Go
statements, not the percentage of Apple's functionality implemented.
The [progress report](progress.md) identifies the exact tested revision and CI run.

| Area | Implemented and tested | Remaining requirements |
| --- | --- | --- |
| Mach-O parsing | Thin 32/64-bit, both byte orders; fat 32/64-bit; bounds and overlap checks | Host acceptance for legacy architectures and unusual load-command layouts |
| Ad-hoc signing | SHA-256 CodeDirectory, signature allocation, all slices, replacement, identifiers, page size, selected flags, runtime version | Header expansion, alternate digests, scatter/pre-encrypt forms, full metadata preservation |
| Certificate signing | RSA and ECDSA P-256/P-384/P-521 CMS, PEM/PKCS#12 identities, native allocation and hash agility, organization/Developer ID requirements, Team IDs, RFC 3161 provider callbacks and online HTTP timestamps | Broader identity formats, Apple-proper requirements, encrypted PEM, broader TSA transport policy, hybrid signatures |
| Timestamps | RFC 3161 signature/imprint/ESS/nonce validation, historical validity, explicit TSA roots, Apple/custom HTTP acquisition, deadlines and cancellation | Complete Apple TSA policy, revocation, proxy/redirect/compression behavior, broader CMS/BER forms and localized dates |
| Entitlements | XML and DER encoding, executable flags, extraction; typed plist values | Full malformed-input/error parity, constraints, macOS 27 hybrid signing interactions |
| Requirements | Identifier, CDHash, certificate index/root hash, subject CN/O/OU, extension existence, generic Apple anchor, boolean expressions | Remaining predicates, Info.plist predicates, complete native grammar and diagnostic output |
| Verification | Code pages, special slots, supported requirements, CMS integrity, explicit leaf pins and CA roots, bounded chain policy, Team ID consistency, RFC 3161 binding and separate TSA trust | Full PKIX/Apple policies, general CMS/BER forms, complete timestamp policy, revocation, platform strictness, notarization |
| CLI | Cobra dispatch; native grouped short options; explicit Viper config; sign/verify/display/remove subset | Every native option and combination, complete diagnostics/exit behavior, detached signatures |
| Certificate extraction | Supported CMS chains as leaf-first DER, default/empty/custom prefixes, architecture selection, native overwrite/partial-write and continuation behavior | Wider CMS/chains, host augmentation, signature slots, combined entitlement diagnostics and bundle-parent alias display |
| Formats | Embedded Mach-O signatures; bounded APPL/BNDL/XPC! Contents layouts and unversioned/multiple-version FMWK frameworks; main-executable inputs, explicit selection, direct version directories and alternate-version requirement checks; recursive bundle/Mach-O seals and relative resource symlinks; single-segment UDIF DMGs via go-apfs-v2 | Wider discovery and symlink/xattr policy, wider replacement metadata, encrypted/segmented images, streaming large images, detached and generic files |
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

The app-bundle matrix additionally compares the complete executable and resource
envelope bytes for three ad-hoc apps, five display levels per architecture, and
eleven resource/metadata/code mutations. Public-test RSA and ad-hoc app outputs
pass native strict verification. The supported layout and conservative limits
are listed in [app bundles](bundles.md); full bundle policy remains incomplete.

Forty DMG option/profile cases compare complete native image bytes and five
display levels each. Fifteen ad-hoc/RSA/P-256 cases pass native signature and
image-checksum verification. Five committed Apple images include exact RSA
reconstruction at a matched signing time. Native DMG removal is unsupported;
both implementations preserve the input and reject it. See [DMG support](dmg-integration.md).

Timestamp replay reconstructs a recorded native RSA arm64 file byte for byte.
Five native timestamp-option cases compare exit codes and ad-hoc file bytes.
Fresh online timestamps are inherently different signing events: the opt-in live
test checks authenticated timestamps and native strict verification on all three
Mach-O forms, without claiming byte equality between independent TSA responses.

## Library extensions and limits

`EncodeEntitlements` can convert a binary plist to XML/DER. Apple's CLI rejects
binary-plist entitlement input on the pinned baseline, and this CLI reproduces
that rejection. Library conversion is an extension, not a native CLI parity claim.

`Identity` accepts an exportable RSA/ECDSA signing key and leaf-first raw DER
certificates. `LoadIdentityPEM` loads supported unencrypted PEM forms and
`LoadIdentityPKCS12` imports authenticated PFX archives. Certificate verification
requires an explicit leaf pin in `VerifyOptions.TrustedCertificates` or a valid
path to `VerifyOptions.TrustedRoots`;
page hashes alone never prove certificate-backed validity. These portable trust
inputs and the `-s FILE --key FILE` CLI convention are extensions, not native
keychain behavior. See [certificate signing](certificates.md) for exact limits.

Twelve certificate cases are accepted by Apple and independently verified by
OpenSSL, with code/CMS tampering rejected by both Apple and Go. Their allocation
and default designated requirements now have the additional native comparisons
described in [certificate signing](certificates.md), including 64 layout cases,
three organization-based chain cases, and 24 PKCS#12 signing cases. Display
authority and Team ID lines match the tested native cases. Supported timestamps
produce descriptive metadata and `Timestamp=` display; dates use fixed English
UTC formatting. Localized dates and metadata for unsupported CMS remain incomplete.

Timestamp trust is separate from code-signer trust. Verification requires
`--timestamp-root CA.pem` or the explicit bundled-root selector `apple`.
Online signing defaults to bundled Apple TSA roots, with a custom CA file as an
override. Transport and policy limits are listed in [timestamps](timestamps.md).

Standalone and bundle Mach-O writes use go-apfs-v2's metadata-preserving staged
replacement, detaching the selected hard-link name. DMGs and existing bundle
resource envelopes retain in-place writes. Bundle commits can leave partial
output on I/O failure. Standalone file aliases select
their physical target for identifiers, display and all path operations, preserving
the aliases and resolving `link/..` before lexical cleanup. Other non-regular
standalone targets are rejected. Re-signing retains existing bytes after the new
SuperBlob within its allocation. [Writer limits](file-writes.md) cover filesystem support, metadata
and concurrency; this is not a crash-durable transaction.

Parsing recognizes more legacy forms than signing has been proven to reproduce.
Large files, a signature with more than seven following bytes, and insufficient
load-command space can return explicit unsupported errors.
Removal now follows the tested native symbol-table padding, virtual-size and
universal-alignment rules. [Removal evidence](removal.md) describes its exact
comparisons and the remaining legacy/malformed-layout limits.

## Full-parity gate

`spec/compatibility.json` retains the original 55 obligations and adds 32 native
parser-recognized switches and the allocator environment hook: 88 entries, with
no status upgrades from recognition alone. The [native inventory](native-inventory.md)
records operation probes and unavailable contexts. The statuses `partial`, `not-implemented`, and `blocked`
all prevent a full-parity declaration. `python3 scripts/guards.py --require-complete`
deliberately fails while any remain. Versioned releases of the documented subset
use [Release Please and GoReleaser](releases.md) independently of this audit.
An unsupported error is not a successful implementation.

Clang can expose declarations and source-level structure. It cannot reconstruct
the current contents of another machine's kernel, retrieve a non-exportable key,
or supply unpublished behavior simply by parsing headers. Those constraints
remain visible in the inventory rather than being replaced by a native bridge.
