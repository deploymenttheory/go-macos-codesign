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
```

PEM private keys may use PKCS#1 RSA, SEC1 EC, or unencrypted PKCS#8. RSA keys must
be 2048–8192 bits. Certificate bundles must put the leaf first and contain no
duplicate certificates. Additional certificates are embedded but are not
path-validated or automatically trusted. Encrypted PEM, PKCS#12, native keychain
selection, RSA-PSS, and hybrid algorithms are not implemented.

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
to match a caller-supplied complete DER leaf pin. They check certificate validity
at `CurrentTime` (default: now), digital-signature key usage and code-signing
extended key usage when present, and reject unhandled critical extensions.
Without a matching pin they return `ErrUntrusted` and do not report `Valid`.
This explicit policy does not reproduce Apple's keychain or PKIX chain policy.

`SignOptions.SigningTime` permits reproducible RSA output with a fixed time.
The authenticated signing-time attribute is a signer's claim, not trusted proof
of time. Expiration is checked against verification time, never bypassed by that
claim. RFC 3161 tokens, revocation, CRLs, and other unsigned CMS attributes are
currently rejected rather than silently treated as verified. CMS parsing accepts
DER; BER indefinite-length support remains unfinished.

The default designated requirement binds the identifier and SHA-1 hash of the
leaf certificate. SHA-1 here is Apple's requirement-format certificate identifier;
the CMS and code-page signatures use SHA-256. CA-anchor, Apple certificate-marker,
and full native designated-requirement synthesis are unfinished.

## Evidence and remaining parity work

The host acceptance test signs RSA/P-256/P-384/P-521 cases for arm64, x86_64, and
universal files. Apple `codesign --verify --strict` accepts all 12 combinations;
OpenSSL independently verifies each architecture's CMS. Apple and Go both reject
modified code pages and CMS signatures. This evidence uses public self-signed
test identities, not Developer ID credentials or notarized distribution.
Two leaf-certificate requirement expressions additionally match Apple's `csreq`
compiler output byte for byte.

The existing 21 exact ad-hoc signing comparisons remain separate. Certificate
signatures currently reserve a conservative amount of Mach-O signature space,
and the generated designated requirement differs from Apple's default synthesis.
ECDSA signatures also contain randomness. These certificate cases establish
native acceptance and cryptographic integrity, not complete byte-for-byte parity.

The three-OS CI runs portable certificate signing and verification on each OS.
Linux and Windows export their signed Mach-O files for a downstream Mac to verify.
Configured CI is not evidence of a remote run; inspect its actual artifacts and
logs before making a cross-platform execution claim.
