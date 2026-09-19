# go-macos-codesign

A pure Go library and Cobra/Viper CLI for Apple code signatures. The implementation
currently signs, inspects, verifies, and removes **ad-hoc and RSA/ECDSA
certificate-backed Mach-O signatures**. Certificate verification uses explicit
leaf-certificate pins or caller-supplied CA roots. It is **not yet a complete replacement for Apple
`codesign`**. Full certificate policy, bundle sealing, disk images, and other requirements remain open in the
[compatibility inventory](spec/compatibility.json). Full-parity releases are blocked.

The CLI runs on Linux, macOS, and Windows without Apple frameworks, subprocess
helpers, CGO, an Apple SDK, or Clang. Clang and Apple tools are used only for
development research and independent macOS acceptance testing.

## Build

Use Go 1.27.1 or newer and GoReleaser 2.18.1. From a checkout:

```sh
goreleaser check
goreleaser build --snapshot --clean --parallelism 2
```

`make build` runs the same command. It builds `macoscodesign` for Linux, Darwin,
and Windows on amd64 and arm64 with `CGO_ENABLED=0`. Outputs are under `dist/`.
For archives and SHA-256 checksums:

```sh
goreleaser release --snapshot --clean --parallelism 2
```

`make snapshot` runs that command. Snapshot mode creates local artifacts without
publishing. The [GoReleaser configuration](.goreleaser.yml) is shared by local builds
and CI. Windows packages are ZIP files; the other targets use tar.gz.

Build from a checkout: the module uses a local dependency replacement described
in [NOTICE](NOTICE), so `go install ...@version` is not supported for the CLI.

## CLI examples

With the built `macoscodesign` binary on your path:

```sh
macoscodesign -s - -i org.example.hello --timestamp=none ./hello
macoscodesign -vv ./hello
macoscodesign -dvvvv ./hello
macoscodesign -fs - -i org.example.hello --entitlements entitlements.plist ./hello
macoscodesign -v '-R=identifier "org.example.hello"' ./hello
macoscodesign --remove-signature ./hello

# Portable certificate identity and trust inputs (unencrypted PEM):
macoscodesign -s certificate.pem --key private-key.pem --timestamp=none ./hello
macoscodesign --verify --trust certificate.pem ./hello
```

Signing accepts the ad-hoc identity `-`, a PEM file, or a PKCS#12 file. A combined certificate
and private-key PEM file can be passed directly to `-s`; separate files use
`--key`. These are portable extensions, not native keychain-name lookup.
`--trust-root` enables portable CA chain verification. PKCS#12 identities use
`-s identity.p12 --password-file password.txt`. `--trust` pins the complete leaf
certificate; it does not accept CA anchors or
claim Apple trust-policy equivalence. See [certificate signing](docs/certificates.md)
for supported formats and limits. Timestamped files additionally require
`--timestamp-root tsa-root.pem` or `--timestamp-root apple` for bundled Apple
roots. [RFC 3161 support](docs/timestamps.md) includes online signing with
`--timestamp` (Apple TSA) or `--timestamp=http://URL`, portable verification and
library callbacks. The CLI supports grouped short
options and Apple's overloaded `-v`. `-h` means native process hosting and reports
unsupported; use `--help` for the portable help extension. Unsupported features
return errors and are not counted as implemented.

`--json` provides a structured inspection/verification report. `--config FILE`,
or `MACOSCODESIGN_CONFIG`, loads an explicitly selected Viper configuration.
Currently only the portable `json` presentation option is configurable; native
signature defaults do not depend on ambient configuration.

## Library

```go
err := codesign.Sign(ctx, path, codesign.SignOptions{
    Identifier: "org.example.hello",
})
if err != nil {
    return err
}
report, err := codesign.Verify(ctx, path, codesign.VerifyOptions{})
```

Import `github.com/deploymenttheory/go-macos-codesign/pkg/codesign`.
`SignBytes`, `InspectBytes`, `VerifyBytes`, and `RemoveSignatureBytes` support
in-memory use. Input bytes are not modified by signing or signature removal.
File writes preserve the existing inode and are not atomic; sign a copy when
rollback is required. File operations currently have a 1 GiB input/output limit.

## Verification

```sh
make verify
make lint
```

Verification runs unit tests and the compiled CLI as a subprocess, merges their
statement coverage, and requires **more than 95% in every production package**.
It writes coverage, raw acceptance transcripts, fixture hashes, and source
provenance under `artifacts/`. The current implementation has been checked against
Apple `codesign` on macOS 27.0, build 26A428. See
[the validation procedure](docs/testing.md) for the exact evidence boundary.

CI runs tests on Linux, macOS 27, and Windows; builds all six targets with
GoReleaser; checks race behavior and fuzzes parsers; and sends files signed on
Linux/Windows to macOS for Apple verification. CI configuration is not evidence
that a remote run has passed.

## Research and remaining work

- [Clang AST research and source references](docs/research.md)
- [Certificate signing and explicit trust](docs/certificates.md)
- [Implemented behavior and compatibility gaps](docs/compatibility.md)
- [Implementation stages and outstanding work](docs/implementation.md)
- [Testing and release gates](docs/testing.md)

This project retains the full-parity objective. Operations that depend on live
macOS process state, system keychains, or non-exportable hardware keys cannot be
reported equivalent without access to that state. They remain explicit blockers
under the requirement that the implementation have no macOS dependency.
