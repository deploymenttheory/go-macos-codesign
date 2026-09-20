# Native bundle-layout fixtures

Deterministic tar archives preserve the symlink target text and signed bytes of
Contents-based BNDL plug-ins, XPC services/extensions, unversioned frameworks and
single-version frameworks. Each layout has arm64, x86_64 and universal fixtures
with binary Info.plist metadata. Plug-ins use real MH_BUNDLE files; frameworks use
the previously pinned dylib fixtures and contain an additional nested executable.

All archives were signed by Apple and checked with `--verify --strict --deep`.
The manifest pins every archive, the unsigned MH_BUNDLE inputs, compiler, source,
host and signing tool. Go reproduces the complete archives on every CI OS.
Tar is a test/CI transport; the production API operates on filesystem bundles.

To deliberately regenerate, move generated files and manifest.json to an ignored
backup, leaving this README, then run:

```sh
MACOSCODESIGN_RECORD_LAYOUTS=1 MACOSCODESIGN_REQUIRE_APPLE=1 CGO_ENABLED=0 \
  go test ./acceptance -run '^TestRecordAppleLayoutFixtures$' -count=1 -v
```

The recorder refuses overwrites. Review the manifest and run `make verify`.
The fixture directory must be force-added when staging: archives and executable
extensions can match generic ignore rules. No native tools are used in production.
