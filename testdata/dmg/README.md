# DMG fixtures

`apfs.dmg` and `hfs-lzma.dmg` are exact copies of `testdata/cli/basic.dmg` and
`testdata/cli/hfs-basic-lzma.dmg` from
[`go-apfs-v2` revision a4b437d9dd8e62e3781004edc44be462793c883e](https://github.com/deploymenttheory/go-apfs-v2/tree/a4b437d9dd8e62e3781004edc44be462793c883e/testdata/cli).
They contain public test data. Original content manifests and the MIT license
are retained. Both pass native `hdiutil verify`.

The five `native-*.dmg` fixtures use `disk.EncodeUDIF`, followed by Apple signing
and strict verification: raw/zlib/LZFSE ad-hoc images and zlib RSA/P-256 images.
Only public test credentials from `testdata/identities` were used. The manifest
records hashes, source revision, arguments and host/tool provenance.

Normal tests never rewrite fixtures. To re-record deliberately, move the five
native files into an ignored backup under `artifacts/`, then run on a Mac:

```sh
MACOSCODESIGN_RECORD_DMG=1 MACOSCODESIGN_REQUIRE_APPLE=1 CGO_ENABLED=0 \
  go test ./acceptance -run '^TestRecordNativeDMGFixtures$' -count=1 -v
```

The recorder refuses to overwrite native files. Review changes and run
`make verify`. Native RSA is compared byte for byte at its recorded signing
time. ECDSA compares CodeDirectories and verifies randomized signatures.

The native LZMA fixture is used because a small image from the pinned encoder
fails `hdiutil` before signing. See [the observation and reproducer](../../docs/dmg-integration.md).
