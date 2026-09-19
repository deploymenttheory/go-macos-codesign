# Portable certificate signing

The library and CLI sign thin and universal Mach-O binaries using RSA PKCS#1 v1.5
or ECDSA P-256/P-384/P-521 with SHA-256 CMS. Signing includes the leaf-first input
certificate set and both Apple hash-agility attributes, binding the complete
primary and alternate CodeDirectories. The Mach-O writer currently emits one
SHA-256 CodeDirectory per architecture.

## Identity input

```sh
macoscodesign -s certificate.pem --key private-key.pem --timestamp=none ./hello
macoscodesign --verify --trust certificate.pem ./hello

# Alternatively, use a PEM bundle containing the leaf certificate,
# supporting certificates, and private key:
macoscodesign -s identity.pem --timestamp=none ./hello

# Authenticated PKCS#12 and explicit CA trust:
macoscodesign -s identity.p12 --password-file password.txt ./hello
macoscodesign --verify --trust-root root-ca.pem ./hello
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
at `CurrentTime` (default: now), digital-signature key usage and code-signing
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
claim. RFC 3161 tokens, revocation, CRLs, and other unsigned CMS attributes are
currently rejected rather than silently treated as verified. CMS parsing accepts
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
SHA-256 fingerprint, validity dates and signing time; it is not a trust verdict.
Verbose display prints `Authority`, `Signed Time`, and `TeamIdentifier`. Signing
time uses a fixed English UTC format, so localized native date output is not yet
reproduced. Unsupported or damaged CMS displays `Authority=(unavailable)`.

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
Linux and Windows export their signed Mach-O files for a downstream Mac to verify.
The CLI also verifies the twelve committed Apple-created signatures on every OS.
Configured CI is not evidence of a remote run; inspect its actual artifacts and
logs before making a cross-platform execution claim.
