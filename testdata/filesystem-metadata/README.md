# Native filesystem metadata seeds

These AppleDouble inputs let the ordinary CLI tests exercise metadata on real
FAT32 and exFAT volumes. The CLI receives only native codesign arguments. The
filesystem determines how attributes are stored.

`seed.c` assigns metadata through macOS `setxattr`, then exports it with
`copyfile(COPYFILE_PACK | COPYFILE_ALL)`. The eleven seeds cover clean, ordinary,
FinderInfo, resource-fork, combined, stripping, signature removal, generic
clean/populated/empty signature namespaces and bundle executable discovery.
Host-created attributes are retained. In particular, a hand-built compact input
without native provenance can change differently when macOS later touches it;
such an input is not interchangeable with these native-produced seeds.

`native-seeds.json` records the actual host, SDK, compiler, producer binary hash,
input bytes and hashes of the producer, module files and both SDK ASTs. The ASTs
are compressed without removing declarations. This retained capture comes from
the host recorded in the report; it does not claim execution on other versions
or on Intel. CI also captures fresh inputs on its macOS profile runners.

From the repository root on macOS:

```sh
go run scripts/probe-filesystem-metadata-seeds.go
MACOSCODESIGN_RECORD_FILESYSTEM_REMOVAL=testdata/filesystem-metadata/native-removal.json \
MACOSCODESIGN_RECORD_FILESYSTEM_DISCOVERY=testdata/filesystem-metadata/native-discovery.json \
go test ./acceptance -run '^TestFilesystemMetadata(Removal|Discovery)$' -count=1
go test ./acceptance -run '^Test(FilesystemMetadata|StandaloneSideband|NativeFilesystemIgnores)' -count=1
```

`TestFilesystemMetadataEvidence` rejects stale or incomplete source bindings.
`TestFilesystemMetadataCLI` records raw inputs, operation results and resulting
carriers, checks preservation of unrelated attributes and verifies stripped,
re-signed output. macOS compares directly with its installed `codesign`.
`native-removal.json` retains 54 exact generic-removal outcomes and
`native-discovery.json` retains 80 bundle-selection outcomes from real FAT32/exFAT
volumes. Both bind their source helpers, seeds and dependencies. Capture mode is
macOS-only, requires a complete oracle inventory, and still compares the Go CLI
against the native results. Normal execution validates those bindings before
using the corpus; macOS also runs a fresh native comparison.
Linux/Windows execution and native readback of their produced artifacts remain
required before declaring portable signing complete.
