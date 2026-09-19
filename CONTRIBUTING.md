# Contributing

Start with the [project status](docs/progress.md), [roadmap](docs/implementation.md)
and [compatibility matrix](docs/compatibility.md). Bug reports and feature requests
belong in [this repository's issues](https://github.com/deploymenttheory/go-macos-codesign/issues).
Follow the [Code of Conduct](CODE_OF_CONDUCT.md) when participating.

## Development workflow

Use the Go version in [go.mod](go.mod) and the pinned GoReleaser/golangci-lint
versions in the [CI workflows](.github/workflows). Build from a checkout because
this repository includes local dependency replacements.

```sh
make verify
make lint
goreleaser check
make snapshot
```

GoReleaser handles distributable builds and packaging. Development-only Python
scripts audit dependencies/fixtures and aggregate Go coverage; Go and Python
research drivers invoke Clang. None is a production runtime dependency.
The [testing guide](docs/testing.md) explains native acceptance, evidence artifacts
and optional live TSA checks.

## Implementation requirements

- Keep production pure Go and portable across Linux, macOS and Windows. Audit
  transitive dependencies as well as direct imports; disabling CGO alone does not
  remove Darwin's certificate trust bridge.
- Tie behavior to pinned source/Clang AST facts and independent native acceptance.
  Compare complete bytes where deterministic; document randomized fields and
  validate their cryptographic invariants independently.
- Include malformed-input and failure cases where behavior changes. Every
  production package must retain more than 95% statement coverage.
- Use public test identities only. Preserve fixture provenance and intentional
  line endings; do not silently regenerate expected data after a failing test.
- Update the relevant capability docs, [progress](docs/progress.md),
  [roadmap](docs/implementation.md), [changelog](CHANGELOG.md) and
  [compatibility inventory](spec/compatibility.json) with each phase.

## Pull requests

Use a conventional title such as `feat: add ...`, `fix: ...` or `docs: ...`.
Explain the concrete behavior change, evidence, validation and remaining limits.
Link the actual CI run before claiming cross-platform or native verification.
A passing example does not establish full compatibility for a native option.
For dependent PRs, state their merge order and keep each diff reviewable.

`make release-check` deliberately fails until every full-parity requirement is
verified. Development snapshots remain available; do not bypass that release gate.
For vulnerabilities, follow the [security policy](SECURITY.md).
