# Portable certificate signing

The library and CLI sign thin and universal Mach-O binaries using RSA PKCS#1 v1.5
or ECDSA P-256/P-384/P-521 with SHA-256 CMS. Signing includes the leaf-first input
certificate set and both Apple hash-agility attributes, binding the complete
primary and alternate CodeDirectories. The Mach-O writer currently emits one
SHA-256 CodeDirectory per architecture.

## Identity input

The signing examples below are alternatives for an unsigned file. Add `-f` to
replace an existing signature.

```sh
macoscodesign -s certificate.pem --key private-key.pem --timestamp=none ./hello
macoscodesign --verify --trust certificate.pem ./hello

# Alternatively, use a PEM bundle containing the leaf certificate,
# supporting certificates, and private key:
macoscodesign -s identity.pem --timestamp=none ./hello

# Authenticated PKCS#12 and explicit CA trust:
macoscodesign -s identity.p12 --password-file password.txt ./hello
macoscodesign --verify --trust-root root-ca.pem ./hello

# Add an online Apple timestamp; TSA trust is separate from code trust:
macoscodesign -s identity.p12 --password-file password.txt --timestamp ./hello
macoscodesign --verify --trust-root root-ca.pem --timestamp-root apple ./hello
```

PEM private keys may use PKCS#1 RSA, SEC1 EC, or unencrypted PKCS#8. RSA keys must
be 2048–8192 bits. Certificate bundles must put the leaf first and contain no
duplicate certificates. Signing checks that the supplied certificates form one
leaf-first path and satisfy certificate purpose and CA constraints. Include the
complete chain needed for requirement and Team ID synthesis; no issuers are
downloaded. Encrypted PEM, native keychain selection, RSA-PSS, and hybrid
algorithms are not implemented.

`LoadIdentityPKCS12(data, password)` requires a valid password MAC before decoding
encrypted contents. It supports PBES2/PBKDF2 with AES-128/192/256-CBC, legacy
PKCS#12 SHA-1/3DES and RC2-40, and SHA-1/256/384/512 MACs. Unencrypted key bags
inside authenticated archives also work. Exactly one private key and its matching
certificate chain are required; unrelated certificates, ambiguous leaf matches,
missing MACs, unknown bags, and public-key integrity mode are rejected. Input is
bounded to 16 MiB, password to 1,024 UTF-8 bytes, salt to 1–1,024 bytes, and each
KDF to one million iterations, with a two-million-block-iteration archive budget.
Empty and UTF-16 password representations are handled explicitly. The password
file is UTF-8; the CLI removes one trailing LF/CRLF. Omit it for an empty password.

```go
identity, err := codesign.LoadIdentityPEM(certificatePEM, privateKeyPEM)
if err != nil {
    return err
}
err = codesign.Sign(ctx, path, codesign.SignOptions{
    Identifier: "org.example.hello",
    Identity: identity,
})
if err != nil {
    return err
}
report, err := codesign.Verify(ctx, path, codesign.VerifyOptions{
    TrustedCertificates: [][]byte{identity.Certificates[0]},
})
```

Certificate parsing uses `encoding/asn1`; signing and signature verification use
Go's RSA/ECDSA primitives. Production code does not import `crypto/x509`, execute
external programs, or call Apple frameworks. The dependency guard checks the
Darwin graph as well as Linux and Windows. Standard `crypto/x509` is used only
in tests and the test-fixture generator as an independent implementation.

## Verification boundary

`VerifyCMS` checks detached CMS integrity, the message digest, signed content
type, and both Apple hash-agility bindings. It checks DER attribute ordering and
rejects duplicate attributes, ambiguous signer certificates, and unsupported
algorithms. It does not evaluate certificate trust.

`VerifyBytes` and `Verify` additionally require the embedded signer certificate
to match a caller-supplied complete DER leaf pin, or a valid path to a certificate
in `VerifyOptions.TrustedRoots`. Leaf pinning and CA trust are separate options;
`--trust` remains an exact leaf pin. Both check certificate validity
at `CurrentTime` (default: now), or at an explicitly trusted RFC 3161 timestamp,
and check digital-signature key usage and code-signing
extended key usage when present, and reject unhandled critical extensions.
Without an explicit pin or roots they return `ErrUntrusted` and never report
`Valid`. `VerifyCertificateChain` also exposes the portable CA policy directly.
It checks RSA/ECDSA SHA-256/384/512 link signatures, CA basic constraints,
non-self-issued intermediate path length, certificate-sign key usage, and
code-signing EKU throughout the path. Pools are limited to 64 certificates,
paths to 32 certificates, and path search to 256 visits. Issuer names must match
subject names in DER; broader PKIX name normalization is not implemented.
Name constraints, policy mappings/constraints, inhibit-any-policy and unhandled
critical extensions fail closed. This deliberately conservative subset does not
reproduce every RFC 5280 policy, Apple's expiration tolerances or keychain trust.
There is no system trust store, issuer fetching, OCSP or CRL processing.

`SignOptions.SigningTime` permits reproducible RSA output with a fixed time.
The authenticated signing-time attribute is a signer's claim, not trusted proof
of time. Expiration is checked against verification time, never bypassed by that
claim. [RFC 3161 tokens](timestamps.md) require separate explicit TSA roots and
are authenticated before their time is used. CRLs and other unsigned CMS
attributes remain unsupported; no revocation check is implied. CMS parsing accepts
DER and Apple's indefinite-length BER outer containers. Size, nesting, and
element-count limits bound parsing. Certificates, signer records, and signed
attributes retain their original bytes and must decode as DER; envelope conversion
does not repair authenticated data. This is not a general BER codec.

Default non-Apple requirements select the last certificate sharing the leaf's
Organization, using Apple's root slot when that reaches the anchor. CN-only
identities keep the leaf hash. SHA-1 here identifies a certificate in Apple's
requirement format; CMS and code-page signatures use SHA-256. Requirements also
support certificate indices, root hashes, subject CN/O/OU equality, extension
existence, and generic Apple anchors. Unsupported predicates fail explicitly.

Team IDs derive from the leaf OU only after cryptographic chain linkage to a
pinned Apple root and recognized developer markers. Caller-provided CA trust
cannot make a fake Apple root eligible. Verification rejects a present Team ID
that disagrees with a recognized Apple developer certificate. Developer ID and
WWDR designated requirement synthesis is implemented for three-certificate paths;
Apple-proper requirement synthesis remains unsupported. Missing intermediates
are not fetched, and arbitrary OU fields never become Team IDs.

Inspection includes `Signature.CertificateMetadata` when the supported CMS
binding can be checked. It contains ordered authorities, CN/O/OU, serial number,
SHA-256 fingerprint, validity dates, signing time and supported timestamp metadata;
it is not a trust verdict. Verbose display prints `Authority`, `TeamIdentifier`,
and `Timestamp` when a supported token is present, otherwise `Signed Time`. Time
display uses a fixed English UTC format, so localized native date output is not yet
reproduced. Unsupported or damaged CMS displays `Authority=(unavailable)`.

## Certificate extraction

```sh
# Writes codesign0, codesign1, ... in the working directory:
macoscodesign -d --extract-certificates ./hello

# Writes chain-0, chain-1, ... in an existing directory:
macoscodesign -d --extract-certificates=export/chain- ./Example.app

# An empty attached prefix writes 0, 1, ...:
macoscodesign -d --extract-certificates= ./Example.dmg
```

The optional prefix must be attached with `=`. A separate word is another input
operand. Repeated options use the last prefix; a final bare option resets it to
`codesign`. Extraction applies to display and is ignored for signing, verification
and removal, matching the measured native behavior. Ordinary display output is
retained. `--architecture` selects the same slice as display; the current portable
default prefers arm64, then the first slice. Native defaults on other host
architectures remain unproven.

Files contain exact DER certificates, numbered from zero in leaf-first chain
order, including an embedded root when present. No root or missing issuer is
downloaded or supplied from a system keychain. The source is the existing
`Signature.CertificateMetadata.Certificates` field, whose byte slices are owned
copies in the same order as `Authorities`. JSON reports omit DER bytes;
`-d --json --extract-certificates=PREFIX` still writes the files as a portable
extension.

Extraction is descriptive, not a code-integrity or trust verdict. Modified code
pages still permit extraction. Ad-hoc signatures produce no files. Unsupported
or corrupted CMS for which inspection cannot supply metadata also produces no
files; normal display can still succeed. Unsigned inputs fail display. Existing
explicit-trust verification APIs retain their separate checks.

Outputs are written sequentially with ordinary file writes. Existing files are
truncated in place, retaining their inode/mode and following symlinks or hard links.
New files request mode 0644 subject to the host's permissions/umask. Parent
directories are not created. Stale higher-numbered files remain. A write failure
retains earlier writes; the next operand is reached only with `--continue`.
Multiple operands use the same prefix, so later certificates overwrite earlier
indices. There is no atomic rollback or automatic cleanup of exported files.

The native matrix covers arm64/x86_64/universal Mach-O, a Contents app, a versioned
framework and a compressed DMG with ad-hoc/RSA/P-256/three-certificate identities.
It compares DER to independent PEM fixtures and Apple's extraction, plus raw
stdout/stderr/exit status. Verbose certificate display retains an explicit date
profile difference on the hosted Mac: its month-first 12-hour format differs from
Go's fixed day-first 24-hour format. Both raw outputs are recorded, with the entire
expected string checked for each of the two observed profiles; date parity is not
claimed. Additional cases cover existing files, links, permission
and partial-write failures, multiple operands and CMS/page mutations.

Remaining differences include unsupported CMS algorithms/representations,
incomplete/ambiguous chains, native host-chain augmentation, detached signatures,
additional signature slots, broader filesystem errors and output paths aliasing
inputs. Bundle inputs reached through a symlinked parent now use the physical
parent in `Executable=`; the Mac regression requires identical output and DER.
Combined extraction now retains normal display and colon warnings. Certificates
are written before [entitlements](entitlement-extraction.md); file lists follow
entitlements. Broader slot, CMS, locale and output interactions remain open.

## Evidence and remaining parity work

The host acceptance test signs RSA/P-256/P-384/P-521 cases for arm64, x86_64, and
universal files. Apple `codesign --verify --strict` accepts all 12 combinations;
OpenSSL independently verifies each architecture's CMS. Apple and Go both reject
modified code pages and CMS signatures. This evidence uses public self-signed
test identities, not Developer ID credentials or notarized distribution.
Two leaf-certificate requirement expressions additionally match Apple's `csreq`
compiler output byte for byte.

The native certificate matrix adds 64 comparisons across the four key types,
three Mach-O forms, runtime flags, entitlements, explicit requirements, and
sixteen identifier lengths. The writer reproduces Apple's 18,000-byte CMS blob
budget and single alignment pass. It also reproduces Apple's BER containers,
SHA-256 algorithm parameters, and hash-agility XML formatting.

The 28 RSA cases compare complete Mach-O slice bytes, including CMS and padding,
using the same signing-time claim as Apple. The 36 ECDSA cases compare layout and
non-CMS signature components and verify both signatures independently. Committed
native fixtures additionally compare authenticated attributes and algorithm
identifiers on every OS. Randomized ECDSA signature bytes are not asserted equal.
Fat slices can have different native signing times; each slice is compared at
its own recorded time. The 21 ad-hoc byte comparisons remain unchanged.

The chain phase adds three native organization-based anchor comparisons, with
equal CodeDirectory/requirement bytes and authority/Team ID display, plus a
Developer ID expression compared against `csreq`. A real public Microsoft
Developer ID chain independently validates to Team ID `UBF8T346G9` at the fixed
test time. This establishes certificate policy and requirement behavior, not an
end-to-end Developer ID signing test: no Developer ID private key is present.
Twelve PKCS#12 fixtures were exported by LibreSSL/OpenSSL, and 24 signatures made
from imported identities pass native strict verification across all three Mach-O
forms. Wrong-password, missing-MAC, fake-Apple, invalid-CA and tampering tests
exercise rejection paths. Full PKIX/Apple trust equivalence remains unfinished.

The three-OS CI runs portable certificate signing and verification on each OS.
Linux and Windows each export 27 signed Mach-O files, including eight PKCS#12,
three chain cases and one timestamp replay, for a downstream Mac to verify
(54 Mach-O files in total). The bundle phase additionally exports six apps per
OS, bringing the required native verification count to 66 artifacts.
The DMG phase adds another fifteen images per OS, for 96 artifacts overall.
The CLI also verifies the twelve committed Apple-created signatures on every OS.
The [progress report](progress.md) links the actual three-OS workflow and its
54-file native verification result. Future commits require their own checks.
