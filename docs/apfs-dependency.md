# APFS integration

During Phase 02, codesign pins merged APFS main commit
[`674c2a3a815b`](https://github.com/deploymenttheory/go-apfs-v2/commit/674c2a3a815b05fc6ce34d9931291ff6a86bd62f)
as `v0.17.3-0.20261007070340-674c2a3a815b`. This includes PR198's compressed-source
replacement fix, PR208's shared lifecycle work and PR209's Windows staging error
classification. Upstream releases are batched under the
[phase dependency policy](implementation_plan.md); development and CI use the
same reproducible module version until the batch release is available.
There is no local APFS replacement or workspace override. Existing replacement,
directory metadata and timestamp operations use `pkg/hostdata`; read/access-time
operations use `pkg/hostdata/accesstime`.

Resource traversal and hashing use `hostdata.OpenContentFileRead`, replacing the
Unix and Windows resource-opening implementations formerly in codesign. This
regular-file reader confines paths and avoids unrelated ACL/EA access rights.
Bundle replacement sources use `hostdata.OpenMetadataFileRead`: restoring source
ACLs requires metadata rights, even though resource hashing does not. Sideband
queries remain independent operations against the same held identity.

Windows integration tests enforce real ACL/EA denials, successful content-only
signing with valid seals, and refusal of actual data-read denial without an
executable commit. Existing strict sideband, replacement, native acceptance and
foreign-import tests remain required. Platform-plist selection is still a
separate [discovery policy increment](removal-platform-metadata.md).

Bundle removal uses `hostdata.StatMetadata` for executable discovery. This rooted,
no-follow query does not request file-data or extended-attribute access. On
Windows it uses the SDK's held-parent metadata opener instead of Go's
`Root.Lstat`, whose generic-read request can confuse data denial with missing
metadata. Selected-file read failures remain fatal. The SDK also uses this query
before acquiring metadata handles. See the versioned
[query contract](https://github.com/deploymenttheory/go-apfs-v2/blob/v0.16.0/docs/rooted-metadata-stat.md)
and [bundle-removal acceptance](bundle-removal-discovery.md).

PR186 and release PR187 fix denied-write source ACL staging. The SDK delays source
ACL restoration until the temporary file has been opened and written. Codesign
now delays that restoration until after the final explicit access-time write,
preventing a restored deny-writeattr ACL from blocking a permitted replacement.
The source handle stays open for SDK restoration and closes before rename on
every platform. Six portable CLI cases
exercise real write denials; the broader Mac ACL matrix compares native behavior.
See [permission qualification and remaining ACL policy](signing-permissions.md).

Bundle replacement retains the SDK's writable staging handle until access time
has been copied and metadata synced, then closes it before rename. This is
required by the SDK's implemented Windows access-time operation: a read-only
reopen cannot update file times or flush the file, and restored read-only
attributes can prohibit reopening for writing. Path identity checks remain in
place. Windows regression tests cover writable and read-only files, exact access
time, unrelated metadata preservation, handle closure and staging cleanup.

The earlier v0.15.0 release removes `purego` from the dependency graph. Missing x/sys signatures
use the approved finite typed Darwin extension, following x/sys's static import
and runtime-call pattern. It retains macOS metadata, ACL, quarantine, identity
and sandbox operations while portable codecs and policy remain Go. The boundary
still calls platform libraries for native host observations; it does not claim
that a foreign host can observe a live Darwin process. See the versioned
[wrapper boundary and qualification](https://github.com/deploymenttheory/go-apfs-v2/blob/v0.15.0/docs/darwin-wrappers.md).

## Qualification

The metadata-query correction passed all applicable checks in
[APFS PR188](https://github.com/deploymenttheory/go-apfs-v2/pull/188),
[run 36977991355](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/36977991355).
The new query files had 100% statement coverage on Linux, macOS and Windows.
Its live Windows tests distinguish denied data, denied extended attributes, and
effective metadata denial. Codesign must independently pass its unchanged
three-platform and native-import gates against the published v0.16.0 module.

The upstream correction passed all 64 applicable checks in
[APFS PR184](https://github.com/deploymenttheory/go-apfs-v2/pull/184), including
Linux/macOS/Windows suites, native comparisons, fuzz, commercial images and real
large-fork transfers/readbacks. The macOS wrapper gate measured 81/82 statements
(98.8%) with 2,193 passing test records. This upstream evidence does not replace
codesign's downstream qualification.

The unchanged dependency guard, native acceptance, per-package coverage above
95%, three-OS CI, Apple verification of foreign signatures and GoReleaser artifact
checks passed against the earlier v0.15.0 pin in merged
[PR70](https://github.com/deploymenttheory/go-macos-codesign/pull/70),
[run 36827217728](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/36827217728).
Codesign coverage was 95.39% on Linux, 95.31% on Windows and 95.55% on macOS;
CLI coverage was 98.44%, 98.44% and 99.06%, respectively, with command coverage
100%. Qualification included six archives and SBOMs plus Apple's verification
of 606 foreign-produced signed artifacts. Candidate checks using temporary
modfiles do not count as release qualification.

Native chain acceptance keeps its disposable keychain unlocked for the bounded
suite: its 30-minute fixture timeout exceeds the 20-minute suite budget. macOS's
default five-minute lock otherwise expires before later requirement tests reuse
the chain. This changes only the test-created keychain, which is deleted at suite
exit; user keychain settings, trust policy, command deadlines and assertions are
unchanged.

Reproduce the local guard and full native suite on macOS:

```sh
go mod verify
MACOSCODESIGN_REQUIRE_APPLE=1 make verify
make lint
make check
```

Package PR72 merged on v0.15.0. Its macOS 27 relocation-default gap
was resolved in merged [PR73](https://github.com/deploymenttheory/go-macos-pkg/pull/73),
with macOS 27's default used on every host and older relocation behavior available
explicitly. Its [qualification run](https://github.com/deploymenttheory/go-macos-pkg/actions/runs/36840133037)
passed the required native and portable checks. Both downstream publication
prerequisites are satisfied.

## Next implementation phase

The read-only [sideband metadata adapter](sideband-policy.md), object/carrier
binding and signing-time stripping are implemented within their documented
profiles. [Shallow removal](signature-removal.md) now avoids unrelated resource
and child reads. [Bundle discovery](bundle-removal-discovery.md) adds valid-plist
fallback under executable metadata denial in supported layouts. Next obligations
include destination ACL inheritance, broader discovery, directory-entry enumeration under
metadata denial, and denied-delete allocation/cleanup artifacts; see
[signing permissions](signing-permissions.md). Shared filesystem primitives belong
in APFS. Continue using the shared APFS
metadata APIs; do not duplicate filesystem code in codesign.
No CLI capability or compatibility-inventory status changes merely because the
SDK dependency is upgraded.
