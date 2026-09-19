# Native app-bundle fixtures

These three Contents-based apps contain the repository's unsigned arm64,
x86_64 and universal test executables, XML metadata and plain public resources.
Apple `codesign -s - --timestamp=none` signed them; native strict verification
passed before recording. The manifest records host/tool provenance, arguments
and the SHA-256 of every file. No private identity is needed.

`TestNativeBundleFixtures` verifies these fixtures and compares freshly Go-signed
executables and CodeResources byte for byte on Linux, macOS and Windows.
`TestAppleAppBundleParity` independently repeats the native comparison on a Mac.

Deliberate regeneration requires an empty destination for each app. Move the
existing three `.app` directories into an ignored backup under `artifacts/`,
then run on a development Mac:

```sh
MACOSCODESIGN_RECORD_BUNDLES=1 MACOSCODESIGN_REQUIRE_APPLE=1 CGO_ENABLED=0 \
  go test ./acceptance -run '^TestRecordAppleBundleFixtures$' -count=1 -v
```

The recorder refuses to overwrite existing files. Review all fixture/manifest
changes and run `make verify`. `.gitattributes` preserves their exact bytes.
The three Resources/.DS_Store files are intentional public text fixtures: they
exercise the difference between legacy and modern omission rules and must
remain tracked despite any global `.DS_Store` ignore rule.
