# Release automation

The workflows follow the `go-macos-pkg-1` release pattern. Release Please owns
version tags, `CHANGELOG.md`, release pull requests and GitHub releases.
GoReleaser builds and attaches the binaries after a `v*` tag is pushed.

## Credentials

Configure these repository or inherited organization settings:

| Setting | Purpose |
| --- | --- |
| `RP_APP_ID` variable | GitHub App ID; the App must be installed on this repository |
| `RP_APP_PRIVATE_KEY` secret | App private key used to mint a short-lived installation token |
| `RELEASE_PLEASE_PAT` secret | Fallback when App configuration is unavailable |

The App or PAT needs access to create release PRs, tags and releases (repository
contents and pull requests). The workflow reports which credential it selected
without printing credentials. It fails with a setup message if neither is
available. The default `GITHUB_TOKEN` is deliberately not a fallback: tags it
creates do not trigger the separate release workflow.

The tagged build uses its job's `GITHUB_TOKEN` with `contents: write` to attach
artifacts and `id-token: write` for Cosign's keyless identity. No signing key is
stored for artifact signing. Credential provisioning is separate from committing
the workflows; local syntax checks cannot establish that the App is installed
or that organization secrets are accessible to this repository.

## Workflow

1. A push to `main` runs `.github/workflows/release-please.yml`. Conventional
   commits update the release PR. Its `terraform-module` strategy matches the
   reference project's tag-only versioning: there is no source version file or
   module import path to rewrite.
2. Merging the release PR lets Release Please create the tag and GitHub release.
3. The tag triggers `.github/workflows/release.yml`. It fetches full Git history,
   installs Go from `go.mod`, Cosign and Syft, then runs GoReleaser v2.
4. GoReleaser cross-compiles six pure-Go binaries (Linux/macOS/Windows on
   amd64/arm64), creates tar.gz/ZIP archives and SPDX SBOMs, calculates checksums,
   and signs the checksum file with Cosign. Release notes remain owned by Release
   Please; GoReleaser appends artifact-verification instructions.

The PR/main test workflow continues to require coverage above 95% per package,
native acceptance, three operating systems, golangci-lint, race and fuzz checks.
Its GoReleaser snapshot job also exercises archive/SBOM/checksum creation. It
skips signing explicitly because PR builds have no release OIDC identity.

The previous unconditional full-parity gate was removed from both release
workflows: it prevented every release while features remained incomplete.
`make release-check` still audits whether **full Apple codesign equivalence** can
be claimed. Versioned releases may deliver the documented subset; a passing
release build is not a declaration of full compatibility.

## Local validation and downloads

```sh
actionlint .github/workflows/release-please.yml .github/workflows/release.yml .github/workflows/test.yml
goreleaser check
# Requires Syft; does not publish or obtain a signing identity.
make snapshot
```

The checksum file is `macoscodesign_<version>_checksums.txt`. The accompanying
`.sigstore.json` bundle authenticates it; archive and SBOM hashes are in that
file. Each release footer supplies the exact `cosign verify-blob` command,
including this repository's `release.yml` identity at the release tag, followed
by `shasum -a 256 -c ... --ignore-missing` for the downloaded artifacts.

Publishing and keyless signing can only be verified by an authorized tagged run.
Snapshot packaging and YAML checks exercise the build path without creating a
tag or publishing a release.

References: [GoReleaser release configuration](https://goreleaser.com/customization/publish/scm/),
[checksum signing](https://goreleaser.com/customization/sign/sign/),
[SBOM generation](https://goreleaser.com/customization/sbom/).
