# RC2 import primitive

Unmodified `pkcs12/internal/rc2` source and tests from `golang.org/x/crypto v0.50.0`,
with the upstream license. `UPSTREAM.json` pins every retained source file.
Only `go.mod` was added to package the subset without the upstream PKCS#12
package's platform trust dependencies. No RC2 export API is exposed by codesign.

This dependency's upstream tests run separately (`go test ./...` in this folder).
As with module dependencies generally, its source is outside the first-party
coverage denominator. All PKCS#12 parsing, KDF, bounds and cipher selection code
is first-party and included in the coverage gate.
