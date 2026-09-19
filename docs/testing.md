# Testing and release evidence

## Local commands

```sh
make verify
make lint
goreleaser check
make snapshot
```

GoReleaser is the build/packaging tool. Python is used for development-only AST
extraction, fixture provenance, dependency audits, and coverage aggregation.
The acceptance harness builds an instrumented CLI using Go's native coverage
support; it does not invoke an installed copy of the implementation.

`scripts/verify.py` creates fresh coverage directories on every invocation. It
combines atomic statement profiles from unit tests and subprocess CLI tests,
counts each statement once, and requires more than 95% in every package under
`pkg/`, `internal/`, and `cmd/`. Tests and upstream dependency code are not included
in the production statement denominator. New production packages enter the gate
automatically through `go list`.

The resulting files under `artifacts/` include:

| File | Evidence |
| --- | --- |
| `coverage.out`, `coverage.json`, `coverage.html` | Exact statement counts and source-level coverage |
| `unit.jsonl` | Raw `go test -json` unit-test transcript, retained even when tests fail |
| `acceptance.jsonl` | Raw `go test -json` subprocess acceptance transcript |
| `acceptance.json` | Current-run byte comparisons, hashes, and execution attestations |
| `provenance.json` | Host/tool versions, Apple executable hash on Mac, source and fixture hashes, and `.gitattributes` hash |

On failure, the verification script prints the failed tests' output and package
diagnostics in the CI job log. Full transcripts and provenance remain available
in the `evidence-<runner>` artifact uploaded even if a test fails. Apple fixture
comparisons report both file lengths and SHA-256 hashes, the first differing
offset, and nearby bytes. Entitlement cases also record the input XML hash and
line-ending counts. The XML fixture is pinned to LF in `.gitattributes` because
its bytes are embedded verbatim in the signature; automatic CRLF conversion
would change the comparison input on Windows.

The committed fixtures are small executables compiled from this repository's
`testdata/src/hello.c`. `scripts/gen-fixtures.py` regenerates them on a development
Mac and records Apple signing, display, verification, and hashes in the manifest.
Fixture generation is explicit: normal tests never rewrite expected results.

## Host acceptance

Set `MACOSCODESIGN_REQUIRE_APPLE=1` to make absence of a Mac reference host a test
failure. On non-Mac hosts, Apple-only tests explicitly skip while portable fixture
comparisons and CLI tests still run. Skipped Apple checks are not evidence of
native parity.

The matrix currently contains 21 exact signing comparisons, five exact display
comparisons, binary-entitlement rejection, tamper rejection, and successful native
execution of an ad-hoc file signed by the Go CLI. The local baseline is macOS
27.0 build 26A428. A passing case is evidence for that case and baseline only.

Certificate acceptance adds 12 combinations: RSA and ECDSA P-256/P-384/P-521,
each signing arm64, x86_64, and universal files. Apple verifies each output,
OpenSSL independently checks every architecture's detached CMS, and Apple/Go
reject modifications to both code and CMS data. Certificate cases establish
cryptographic integrity and native acceptance, not byte equality with Apple.
Published self-signed identities under `testdata/identities` are test data only.
Two certificate-hash requirement expressions are also compiled by Apple's
`csreq` and compared byte for byte with the Go compiler output.

`TestAppleNativeCertificateLayout` adds 64 native signing comparisons using
temporary keychains containing public test identities: 28 RSA cases require
complete slice byte equality at matched signing times, and 36 ECDSA cases require
matching layout and non-CMS bytes with independent verification. Twelve native
fixtures under `testdata/certificate-layout` are verified by the library and CLI
on all three operating systems. Their provenance and hashes are committed;
authenticated CMS attributes and algorithm encodings are also compared. See the
fixture README for explicit regeneration instructions.

The `xcode-27` hosted runner is selected because its documented image uses macOS
27. Every run records the actual host and `codesign` hash; that rolling preview
image is not assumed identical to the local baseline. Output drift fails the
comparison and must be investigated without silently normalizing it away.

## CI

The test workflow runs the coverage gate on Ubuntu, Windows, and macOS 27. Linux
and Windows jobs upload the actual Mach-O files they signed. A downstream Mac
job downloads both sets and requires Apple's strict verification to succeed for
all 30 imported files (three ad-hoc and twelve certificate cases per OS).
Every algorithm/architecture combination must be present from both OS jobs.
These are native OS jobs; cross-compilation alone
does not replace them.

Separate jobs run the Go race detector, bounded Mach-O/identity/CMS fuzzing, and GoReleaser snapshots
for all six OS/architecture pairs. The race detector's compiler dependency is
confined to test binaries. Every distributed binary uses `CGO_ENABLED=0`.

`go-lint.yml` pins the linter and fails on reported issues. It does not suppress
failures with an exit-code override or automatically modify source files.

## Release gate

`make release-check` currently fails by design because the full-parity inventory
contains unresolved requirements. Both Release Please and the tagged GoReleaser
workflow enforce that gate. The tagged workflow also reruns the validation
workflow before creating a draft release. No release has been published by the
implementation work.

GoReleaser snapshots remain available for development. They are not labeled as
a fully compatible release. Remote workflow success must be reported from an
actual GitHub Actions run, not inferred from local tests or workflow validation.
