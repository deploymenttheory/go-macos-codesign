# Recursive native app fixtures

Each fixture contains an outer APPL app, a login-item APPL child and a worker
APPL grandchild. The grandchild also contains two executable helpers and a real
dylib from the existing native fixtures. Parent/grandchild metadata is XML;
the child's binary Info.plist is encoded by the pinned howett.net/plist library.

Apple `codesign -s - --deep --timestamp=none` signs each tree, followed by native
`--verify --strict --deep`. The manifest pins every file, host, tool and command.
`TestNativeNestedAppFixtures` verifies and reproduces the complete signatures and
resource envelopes on Linux, macOS and Windows. Native tools are test/research
dependencies only.

To deliberately regenerate, move generated apps and manifest.json to an ignored
backup under artifacts, leaving only this README, then run:

```sh
MACOSCODESIGN_RECORD_NESTED_APPS=1 MACOSCODESIGN_REQUIRE_APPLE=1 CGO_ENABLED=0 \
  go test ./acceptance -run '^TestRecordAppleNestedAppFixtures$' -count=1 -v
```

The recorder refuses overwrites. Review hashes and run `make verify`. The hidden
Resources/.DS_Store files are public text test resources; these and the dylibs
must remain tracked despite generic ignore rules. `.gitattributes` preserves
native fixture bytes on Windows.
