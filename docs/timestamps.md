# RFC 3161 timestamps

The library verifies and attaches RFC 3161 timestamp tokens without platform
certificate services or a network dependency. The CLI verifies timestamped
Mach-O files and displays `Timestamp`. Online CLI acquisition through
`--timestamp` or `--timestamp=URL` remains unsupported; `--timestamp=none` retains
its existing behavior. This is a bounded interoperability phase, not complete
timestamp or Apple trust-policy parity.

## Verification

```sh
macoscodesign --verify --trust signer.pem --timestamp-root tsa-root.pem ./hello
# A code-signing CA path can replace the exact signer pin:
macoscodesign --verify --trust-root code-root.pem --timestamp-root tsa-root.pem ./hello
macoscodesign -dvv ./hello
```

`VerifyOptions.TimestampRoots` supplies DER TSA roots independently of
`TrustedCertificates` and `TrustedRoots`. An embedded certificate or a pinned
code-signing leaf never grants TSA trust. A present timestamp must validate;
the verifier does not fall back to current-time verification after a bad or
untrusted token.

The verifier checks the CMS signature, TSTInfo content digest, imprint over the
**code signer's signature octets**, ESSCertID/ESSCertIDv2 certificate binding,
critical and exclusive timeStamping EKU, certificate path constraints and
validity at authenticated `genTime`. The timestamp must not be later than
`CurrentTime` (default: now; no clock-skew allowance). Only then does `genTime`
replace current time for code-signing certificate validity. A CMS `signingTime`
claim alone cannot bypass expiration. Apple-anchored code additionally requires
an Apple-anchored timestamp, using the project's existing public root pins.

Inspection verifies the cryptographic binding but does not establish trust.
`Signature.CertificateMetadata.Timestamp` includes time, policy, serial and
descriptive TSA information; `Report.Valid` stays false. Verbose display uses
fixed English UTC dates. Verification can return descriptive metadata with an
error; callers must check the error and `Valid` before treating it as trusted.

## Signing and transport

`SignOptions.Timestamp` accepts a `TimestampOptions` provider. The provider
receives signature octets for each architecture and returns a ContentInfo token.
The library authenticates the token against explicit TSA roots before embedding
it as the sole unsigned CMS attribute. Failed acquisition or validation returns
no signed output and leaves the input file unchanged. A dry run constructs the
complete signature, including calling the provider.

```go
opts.Timestamp = &codesign.TimestampOptions{
    TrustedRoots: tsaRoots, // [][]byte, DER CA anchors
    Provider: func(ctx context.Context, signature []byte) ([]byte, error) {
        return codesign.AcquireTimestamp(ctx, signature, exchange, tsaRoots, time.Time{})
    },
}
err := codesign.Sign(ctx, path, opts)
```

`exchange` is a caller-supplied `TimestampExchange`: it receives a DER
TimeStampReq and returns a TimeStampResp. It owns transport, deadlines, response
limits and context cancellation. `AcquireTimestamp` requests SHA-256, certificates
and a positive nonce with 128 random bits. It authenticates the response and
requires the exact nonce and requested imprint algorithm. Granted and
granted-with-modifications statuses are supported; failures are errors.

`TimestampCMS` also works directly on an existing detached code-signing CMS.
`VerifyTimestampToken` validates a standalone token against signature octets and
explicit roots. Providers may replay a token already bound to the identical
signature. Such replay is useful for offline reproducibility, not proof of a new
signing event. A token already embedded in CMS is not silently replaced.

No `net/http`, `crypto/tls`, `crypto/x509`, native API or subprocess is introduced
into the production dependency graph. Choosing a portable CLI network transport
and its URL/proxy/TLS behavior remains a separate implementation task.

## Supported profile and limits

- One issuer/serial CMS signer, SignedData version 3, encapsulated DER TSTInfo
  version 1, RSA PKCS#1 v1.5 or ECDSA, SHA-1/256/384/512 digests.
- SHA-1 is accepted for legacy timestamp verification: the recorded Apple TSA
  response uses SHA-1 CMS and an RSA signature. New requests use SHA-256 imprints;
  code-signing CMS remains SHA-256, and certificate links remain SHA-2 only.
- ESS v1 or v2, including an optional matching issuer/serial. If both attributes
  are present, both must validate. Exactly one ESS certificate identifier is
  supported, without ESS policies.
- UTC GeneralizedTime, optional accuracy/ordering/nonce, and an optional TSA
  directoryName that exactly matches the signer subject. Other TSA name forms,
  extensions, nested unsigned attributes, CRLs and multiple signers are rejected.
- Tokens/responses are limited to 1 MiB; signature inputs to 8 KiB; serials and
  nonces to 160 bits. Existing CMS element/depth and CA path-search limits apply.

Revocation, TSA policy-OID allowlists, complete PKIX/Apple policy, general BER,
RSA-PSS, online CLI acquisition and localized native display remain open. TSA
root trust is explicit and deliberately does not imply notarization acceptance.

## Evidence

`spec/apple-timestamps.json` records two-target Clang AST extraction from pinned
Apple timestamp declarations and the complete `verifyTSTInfo` body with named
type/function/macro shims. Run `make research-timestamps` after fetching the two
source files listed in that manifest. This is source research, not execution of
Apple's full private translation unit.

`testdata/timestamps` contains an Apple-created timestamped arm64 Mach-O using
the public RSA test identity. The portable signer reproduces its complete bytes
at the same signing time with the recorded token. Native acceptance runs
`codesign --verify --strict`, checks tamper rejection, and independently checks
TSA CMS integrity and the certificate path at `genTime` with OpenSSL. Routine
tests perform no TSA requests. Synthetic RSA/ECDSA cases exercise SHA-1/256/384/512,
ESS versions, three Mach-O forms, expiry, nonce replay and malformed input.

Linux and Windows each export a freshly reconstructed timestamped signature;
the downstream Mac requires native verification alongside all other exported
signatures. Check the actual workflow run before claiming remote execution.

An additional live test exercises the Go request/nonce implementation against
Apple's published HTTP TSA and asks native `codesign` to verify the new result:

```sh
MACOSCODESIGN_LIVE_TIMESTAMP=1 CGO_ENABLED=0 go test ./acceptance \
  -run '^TestAcquireAppleTimestamp$' -count=1 -v
```

Its HTTP client is test-only. The response is saved under ignored `artifacts/`
for diagnostics. Apple returns an RFC 3161 UTF8String status message even when
the text is ASCII; the regression test preserves that tag during strict parsing.
