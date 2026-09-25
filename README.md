# go-macos-codesign

A pure Go library and Cobra/Viper CLI for Apple code signatures. The implementation
currently signs, inspects, verifies, and removes **ad-hoc and RSA/ECDSA
certificate-backed Mach-O signatures**, including a bounded macOS app-bundle
profile with XML/binary metadata, resource sealing, nested Mach-O helpers/dylibs,
apps, plug-ins, XPC services/extensions and unversioned or multiple-version frameworks.
It also signs, inspects and verifies UDIF DMGs using
[`go-apfs-v2`](docs/dmg-integration.md) directly. Certificate verification uses explicit
leaf-certificate pins or caller-supplied CA roots. It is **not yet a complete replacement for Apple
`codesign`**. Full certificate policy, broader bundle discovery and symlink/xattr policy,
additional disk-image forms, and other requirements remain open in the
[compatibility inventory](spec/compatibility.json). Versioned releases document
that supported subset; the full-parity audit remains incomplete.

The CLI runs on Linux, macOS, and Windows without Apple frameworks, subprocess
helpers, CGO, an Apple SDK, or Clang. Clang and Apple tools are used only for
development research and independent macOS acceptance testing.

The current implementation includes portable certificate chains and Team IDs,
authenticated PKCS#12 import, and online RFC 3161 timestamps. The
[progress report](docs/progress.md) records delivered milestones, the tested
commit and actual CI evidence. [App bundles](docs/bundles.md) now bind Info.plist
and deterministic CodeResources, including child designated requirements and
`--deep` signing/verification. UDIF signing reuses the APFS project's footer
model; wider format and policy coverage remains open. Supported bundle resources
include relative symlinks, sealed by their target text.
`--bundle-version` selects a framework version for signing, display, verification
or removal. Parent verification checks every physical framework version against
the parent's sealed requirement; `--deep` adds their pages and resources.
Direct directory paths such as `Fixture.framework/Versions/A` and
`Fixture.framework/Versions/Current` operate on that version as a standalone bundle.
Main-executable paths such as `Example.app/Contents/MacOS/hello` select the
enclosing bundle, including its resource seal. Framework executable aliases
select the resolved physical version. Helpers remain standalone files.

Display and signing support [`--file-list PATH`](docs/file-lists.md), appending
absolute signature-file paths or writing them to stdout with `-`. The list
describes the selected outer representation; deep signing does not enumerate
all nested writes. Output failures retain preceding signing/extraction effects.

## Build

Use Go 1.27.1 or newer and GoReleaser 2.18.1. From a checkout:

```sh
goreleaser check
goreleaser build --snapshot --clean --parallelism 2
```

`make build` runs the same command. It builds `macoscodesign` for Linux, Darwin,
and Windows on amd64 and arm64 with `CGO_ENABLED=0`. Outputs are under `dist/`.
For archives, SPDX SBOMs and SHA-256 checksums, install Syft and run:

```sh
goreleaser release --snapshot --clean --parallelism 2 --skip=sign
```

`make snapshot` runs that command. Snapshot mode creates local artifacts without
publishing. The [GoReleaser configuration](.goreleaser.yml) is shared by local builds
and CI. Windows packages are ZIP files; the other targets use tar.gz.
Tagged releases add keyless Cosign signatures to the checksum file. Release
Please owns version tags and release notes; [release setup](docs/releases.md)
documents the App/PAT credentials and artifact verification.

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

# A supported Contents-based app bundle:
macoscodesign -s - --timestamp=none ./Example.app
macoscodesign --verify ./Example.app
macoscodesign -dvvvv ./Example.app

# A supported app containing helpers, apps, plug-ins, XPC services or frameworks:
macoscodesign -s - --deep --timestamp=none ./Example.app
macoscodesign --verify --deep ./Example.app

# A single-segment UDIF disk image:
macoscodesign -s - -i org.example.image --timestamp=none ./Example.dmg
macoscodesign --verify ./Example.dmg

# Portable certificate identity and trust inputs (unencrypted PEM):
macoscodesign -s certificate.pem --key private-key.pem --timestamp=none ./hello
macoscodesign --verify --trust certificate.pem ./hello

# Extract the embedded chain as certificate-0, certificate-1, ... (DER):
macoscodesign -d --extract-certificates=certificate- ./hello

# PKCS#12 identity with an Apple timestamp and explicit verification trust:
macoscodesign -fs identity.p12 --password-file password.txt --timestamp ./hello
macoscodesign --verify --trust-root code-root.pem --timestamp-root apple ./hello
```

For DMGs, native-compatible ad-hoc `--dryrun` changes the image in place and
leaves it unsigned, including when replacing an existing signature with `--force`.
Use the construction-only `SignBytes` API for a preview without path writes.
Certificate DMG path dry runs are unsupported; see [DMG behavior](docs/dmg-integration.md).

Forced replacement prints `<operand>: replacing existing signature` to stderr,
including during dry runs and before later failures. This notice does not indicate
success; see [signing diagnostics](docs/signing-diagnostics.md) for the tested scope
and optional path-only `SignOptions.OnReplace` library callback.

Certificate extraction uses the default prefix `codesign` when no `=PREFIX` is
given. Existing outputs are overwritten; a later failure retains earlier writes.
Extraction does not establish trust. See the [extraction contract](docs/certificates.md#certificate-extraction)
for chain ordering, supported inputs and remaining limits.

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
Standalone file aliases resolve to their physical target for signing, removal,
identifiers and display; the symlink remains intact. `Report.Path` is the absolute
resolved standalone path. Mach-O writes stage a replacement through go-apfs-v2,
preserving other hard-link names for standalone and bundle executables. DMGs and
existing bundle resource envelopes retain their in-place behavior. Bundle commits
can leave partial output on I/O failure. See [writer behavior and limits](docs/file-writes.md).
File operations currently have a 1 GiB input/output limit.
The path APIs also accept supported app bundles; byte APIs accept Mach-O and UDIF.
See [bundle layouts and limits](docs/bundles.md).

## Verification

```sh
make verify
make lint
```

Verification runs unit tests and the compiled CLI as a subprocess, merges their
statement coverage, and requires **more than 95% in every production package**.
It writes coverage, raw acceptance transcripts, fixture hashes, and source
provenance under `artifacts/`. The merged recursive-app phase measures
96.20–96.44% library coverage, 98.10–99.53% CLI coverage and 100% entry-point coverage
across the three CI operating systems; see the [commit-specific results](docs/progress.md#recorded-validation).
The current implementation has been checked against
Apple `codesign` on macOS 27.0, build 26A428. See
[the validation procedure](docs/testing.md) for the exact evidence boundary.

CI runs tests on Linux, macOS 27, and Windows; builds all six targets with
GoReleaser; checks race behavior and fuzzes parsers; and sends files signed on
Linux/Windows to macOS for Apple verification. The merged recursive-app phase
passed all 174 artifacts, including 36 recursive app trees. Bundle layouts expand
the required matrix to 300, adding 126 tar archives that retain framework and
resource symlinks for native strict deep verification. See the
progress page for completed runs. Go code linting uses golangci-lint only.

## Research and remaining work

- [Project progress and validation evidence](docs/progress.md)
- [Documentation index](docs/README.md)
- [Clang AST research and source references](docs/research.md)
- [Certificate signing and explicit trust](docs/certificates.md)
- [Online timestamps and TSA trust](docs/timestamps.md)
- [App bundles and resource sealing](docs/bundles.md)
- [DMG signing using go-apfs-v2](docs/dmg-integration.md)
- [Implemented behavior and compatibility gaps](docs/compatibility.md)
- [Implementation stages and outstanding work](docs/implementation.md)
- [Testing and native evidence](docs/testing.md)
- [Release automation](docs/releases.md)

This project retains the full-parity objective. Operations that depend on live
macOS process state, system keychains, or non-exportable hardware keys cannot be
reported equivalent without access to that state. They remain explicit blockers
under the requirement that the implementation have no macOS dependency.

## Related Projects

- [go-apfs-v2](https://github.com/deploymenttheory/go-apfs-v2) — Pure Go toolkit for reading, creating, and repacking Apple disk images with APFS and HFS+ support.
- [go-macos-pkg](https://github.com/deploymenttheory/go-macos-pkg) — Cross-platform Go toolkit for inspecting, building, signing, notarizing, and stapling macOS installer packages.
