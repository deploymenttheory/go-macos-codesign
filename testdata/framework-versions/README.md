# Native framework-version fixtures

These deterministic tar files preserve complete Apple-signed app trees, including
framework versions A and B with different resources and `Current -> B`. Both
versions use the explicit designated requirement `identifier "org.example.layout"`.
The parent seals that requirement; each physical version must satisfy it.

`manifest.json` records the native host/tool, source inputs, commands and hashes.
The executable and dylib fixtures come from the existing independently compiled
Mach-O and nested-code fixture sets. No private identity is used here.

Record on macOS with:

```sh
MACOSCODESIGN_RECORD_FRAMEWORK_VERSIONS=1 CGO_ENABLED=0 go test ./acceptance -run '^TestRecordAppleFrameworkVersions$' -count=1
```

Ordinary acceptance verifies these signatures and compares complete Go-signed
trees against their bytes on Linux, macOS and Windows. Recording is opt-in and
never runs in normal CI.
