# RFC 3161 timestamps

The library verifies and attaches RFC 3161 timestamp tokens using Go, without
platform certificate services. The CLI signs with Apple's HTTP TSA using
`--timestamp`, or a custom HTTP TSA using `--timestamp=http://URL`, and verifies
and displays timestamps. This is a bounded interoperability profile; complete
timestamp and Apple trust-policy parity remain open.

## Verification

```sh
macoscodesign --verify --trust signer.pem --timestamp-root tsa-root.pem ./hello
# Explicitly select the bundled public Apple PKI roots:
macoscodesign --verify --trust signer.pem --timestamp-root apple ./hello
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

```sh
macoscodesign -s identity.pem --timestamp ./hello
macoscodesign -s identity.pem --timestamp=http://tsa.example/timestamp \
  --timestamp-root private-tsa-root.pem --timestamp-timeout 10s ./hello
```

Timestamped certificate signing defaults to the three bundled Apple PKI roots.
An explicit `--timestamp-root` CA file replaces those roots. Verification always
requires its own explicit TSA trust choice. `AppleTimestampRoots()` returns
independent copies of these public certificates; provenance and SHA-256 pins
are in `pkg/codesign/trust/manifest.json`. No system trust store is consulted.
`--timestamp=none` disables acquisition. Ad-hoc signing ignores a valid timestamp
option, matching the tested native tool. Invalid timestamp URLs fail before any
file is changed, including with ad-hoc signing.

`SignOptions.Timestamp` accepts a `TimestampOptions` provider. The provider
receives signature octets for each architecture and returns a ContentInfo token.
The library authenticates the token against explicit TSA roots before embedding
it as the sole unsigned CMS attribute. Failed acquisition or validation returns
no signed output and leaves the input file unchanged. A Mach-O/bundle dry run
constructs the complete signature, including calling the provider. Certificate
DMG path dry runs are explicitly unsupported and do not call the provider; see
[DMG dry-run behavior](dmg-integration.md). `SignBytes` still constructs complete
signatures regardless of the path-only dry-run option.

```go
exchange, err := codesign.NewHTTPTimestampExchange(codesign.AppleTimestampURL, 0)
if err != nil {
    return err
}
tsaRoots := codesign.AppleTimestampRoots()
opts.Timestamp = &codesign.TimestampOptions{
    TrustedRoots: tsaRoots, // [][]byte, DER CA anchors
    Provider: func(ctx context.Context, signature []byte) ([]byte, error) {
        return codesign.AcquireTimestamp(ctx, signature, exchange, tsaRoots, time.Time{})
    },
}
err = codesign.Sign(ctx, path, opts)
```

`TimestampExchange` receives a DER TimeStampReq and returns a TimeStampResp.
Callers may supply their own exchange or use `NewHTTPTimestampExchange`.
The supplied transport sends a direct HTTP/1.x POST using Go's DNS resolver,
with a 15-second default deadline covering DNS, connection, write and response.
Caller cancellation closes the connection. It supports Content-Length, chunked
and close-delimited responses; it bounds bodies to 1 MiB, header and chunk framing
to 32 KiB each, individual lines to 8 KiB, and headers/trailers to 128 lines.
It validates the response media type and rejects ambiguous framing.

HTTPS, URL credentials/fragments, redirects, proxy environment variables,
compression, chunk extensions, retries and HTTP/2 are unsupported. Native macOS
27 rejects HTTPS timestamp URLs too; other transport limits are this project's
explicit profile, not claims about every native networking behavior. HTTP does
not encrypt request metadata. Token signatures, imprint and nonce checks provide
the response authentication; the HTTP status alone does not establish trust.

`AcquireTimestamp` requests SHA-256, certificates
and a positive nonce with 128 random bits. It authenticates the response and
requires the exact nonce and requested imprint algorithm. Granted and
granted-with-modifications statuses are supported; failures are errors.

`TimestampCMS` also works directly on an existing detached code-signing CMS.
`VerifyTimestampToken` validates a standalone token against signature octets and
explicit roots. Providers may replay a token already bound to the identical
signature. Such replay is useful for offline reproducibility, not proof of a new
signing event. A token already embedded in CMS is not silently replaced.

No `net/http`, `crypto/tls`, `crypto/x509`, native API or subprocess is introduced
into the production dependency graph. Dependency guards check all three target
operating systems; `net/http` and `crypto/x509` are used only in independent tests.

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
RSA-PSS and localized native display remain open. TSA
root trust is explicit and deliberately does not imply notarization acceptance.

## Evidence

`spec/apple-timestamps.json` records two-target Clang AST extraction from pinned
Apple timestamp declarations and the complete `verifyTSTInfo` body with named
type/function/macro shims. Run `make research-timestamps` after fetching the
source files listed in both timestamp manifests. The same target runs an Objective-C AST
extraction of verbatim `initWithURLString:` and `post:` methods, with Foundation
SDK types and a minimal class interface. `spec/apple-timestamp-http.json` records
the HTTP method, content type and 15-second timeout, and the default endpoint
from Apple's pinned preferences file. These facts are checked in Go tests.
This is source research, not execution of Apple's full private translation unit.

`testdata/timestamps` contains an Apple-created timestamped arm64 Mach-O using
the public RSA test identity. The portable signer reproduces its complete bytes
at the same signing time with the recorded token. Native acceptance runs
`codesign --verify --strict`, checks tamper rejection, and independently checks
TSA CMS integrity and the certificate path at `genTime` with OpenSSL. Routine
tests perform no public TSA requests. Local HTTP authority acceptance tests issue
fresh nonce-bound tokens for all three Mach-O forms and check unchanged inputs
after bad status, nonce, imprint, signature or trust. Unit tests cover transport
timeouts, cancellation and malformed responses; HTTP response parsing is fuzzed.
Synthetic RSA/ECDSA cases exercise SHA-1/256/384/512,
ESS versions, three Mach-O forms, expiry, nonce replay and malformed input.

Linux and Windows each export a freshly reconstructed timestamped signature;
the downstream Mac requires native verification alongside all other exported
signatures. Check the actual workflow run before claiming remote execution.

An additional live test exercises the Go request/nonce implementation against
Apple's published HTTP TSA and asks native `codesign` to verify the new result:

```sh
MACOSCODESIGN_LIVE_TIMESTAMP=1 CGO_ENABLED=0 go test ./acceptance \
  -run '^TestCLILiveAppleTimestamp$' -count=1 -v
```

This runs the compiled production CLI on arm64, x86_64 and universal files.
Set `MACOSCODESIGN_EVIDENCE_DIR` to an absolute directory to retain attestations
with timestamps, output hashes and native verification results.
Apple returns an RFC 3161 UTF8String status message even when
the text is ASCII; the regression test preserves that tag during strict parsing.
