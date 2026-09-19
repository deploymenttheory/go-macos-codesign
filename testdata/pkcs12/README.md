# Public PKCS#12 interoperability fixtures

These archives contain only the existing public test identities. Their passwords
are recorded in `manifest.json`; they are not credentials for any real system.

Legacy exports use `/usr/bin/openssl` (LibreSSL 3.3.6): RC2-40 certificate bags,
3DES key bags, and SHA-1 MAC. Modern exports use OpenSSL 3.6.4: AES-256-CBC,
PBKDF2/HMAC-SHA256 and SHA-256 MAC. The AES-128 and AES-192 fixtures additionally
exercise SHA-384 and SHA-512 MAC derivation. Empty and Unicode password fixtures
exercise password encoding independently of the Go implementation.

Generation command, substituting the implementation and algorithm:

```sh
openssl pkcs12 -export -in testdata/identities/rsa-cert.pem -inkey testdata/identities/rsa-key.pem -out identity.p12 -passout pass:public-codesign-test-only
```

AES variants add `-keypbe AES-128-CBC -certpbe AES-128-CBC -macalg sha384`, or
`-keypbe AES-192-CBC -certpbe AES-192-CBC -macalg sha512`. The password variants
set `-passout pass:` or `-passout 'pass:café🔑'`. Salts and encryption randomness
mean regeneration changes hashes; update provenance and run acceptance together.
