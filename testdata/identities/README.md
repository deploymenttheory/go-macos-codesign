# Public test identities

These self-signed RSA and ECDSA certificates and private keys are intentionally
published test data. They have no distribution identity or trust authority.
Never use them to sign distributed software or install them into a trust store.

`generate.go` uses Go's standard certificate implementation to produce independent
fixtures valid from 2020 to 2100, with digital-signature and code-signing usages.
Regenerate explicitly from the repository root with:

```sh
go run testdata/identities/generate.go
```

Generation replaces the random test keys and certificates. Normal tests do not
regenerate them. The generator and its `crypto/x509` dependency are excluded from
production builds; GoReleaser remains the binary build and packaging tool.
