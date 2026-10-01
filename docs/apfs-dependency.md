# APFS v0.15.0 integration

Codesign pins the published
[APFS v0.15.0 module](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.15.0).
There is no local APFS replacement or workspace override. Existing replacement,
directory metadata and timestamp operations use `pkg/hostdata`; read/access-time
operations use `pkg/hostdata/accesstime`.

The release removes `purego` from the dependency graph. Missing x/sys signatures
use the approved finite typed Darwin extension, following x/sys's static import
and runtime-call pattern. It retains macOS metadata, ACL, quarantine, identity
and sandbox operations while portable codecs and policy remain Go. The boundary
still calls platform libraries for native host observations; it does not claim
that a foreign host can observe a live Darwin process. See the versioned
[wrapper boundary and qualification](https://github.com/deploymenttheory/go-apfs-v2/blob/v0.15.0/docs/darwin-wrappers.md).

## Qualification

The upstream correction passed all 64 applicable checks in
[APFS PR184](https://github.com/deploymenttheory/go-apfs-v2/pull/184), including
Linux/macOS/Windows suites, native comparisons, fuzz, commercial images and real
large-fork transfers/readbacks. The macOS wrapper gate measured 81/82 statements
(98.8%) with 2,193 passing test records. This upstream evidence does not replace
codesign's downstream qualification.

The unchanged dependency guard, native acceptance, per-package coverage above
95%, three-OS CI, Apple verification of foreign signatures and GoReleaser artifact
checks must pass against this published pin. Module checksums have been verified;
full downstream qualification is in progress. Keep PR70 draft until its final
revision is qualified. Candidate checks using temporary modfiles do not count as
release qualification.

Reproduce the local guard and full native suite on macOS:

```sh
go mod verify
MACOSCODESIGN_REQUIRE_APPLE=1 make verify
make lint
make check
```

Package PR72 is being updated to the same published release. Its own wrapper,
build/extract, native package and three-OS checks remain required. The maintainer
merges both PRs; no release or merge is performed by this adoption work.

## Next implementation phase

After downstream qualification and merge, cut the next codesign phase from main:
implement sideband/plain/all verification policy and signing-time stripping using
the shared APFS metadata APIs. Do not duplicate filesystem code in codesign.
No CLI capability or compatibility-inventory status changes merely because the
SDK dependency is upgraded.
