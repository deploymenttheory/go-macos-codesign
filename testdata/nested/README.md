# Nested Mach-O fixtures

Clang compiles `library.c` into unsigned arm64/x86_64 dylibs; lipo combines them.
The native recorder builds three apps with two executable helpers and one real
dylib, signs them with Apple's `codesign --deep`, and verifies each using
`--verify --strict --deep`. The manifest pins file hashes, tools, host and commands.

`TestNativeNestedFixtures` verifies these committed native signatures and
reproduces their bytes on every supported OS. Native tools are only used for
research/recording and macOS acceptance; production remains pure Go.

To deliberately regenerate, move generated files/apps to an ignored backup under
artifacts, leaving only this README and library.c, then run:

```sh
MACOSCODESIGN_RECORD_NESTED=1 MACOSCODESIGN_REQUIRE_APPLE=1 CGO_ENABLED=0 \
  go test ./acceptance -run '^TestRecordAppleNestedFixtures$' -count=1 -v
```

The recorder refuses overwrites. Review regenerated hashes and run `make verify`.
The three Resources/.DS_Store files are public text fixtures and must be tracked
despite global ignore rules. `.gitattributes` preserves their bytes on Windows.
