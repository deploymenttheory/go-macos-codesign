# Signing permissions

Signing a readable executable does not require permission to overwrite its
existing data in place. Codesign writes a private replacement and commits it
after preparing its content and metadata. Published
[APFS v0.15.1](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.15.1)
fixes this staging prerequisite: a source deny-write ACL no longer prevents the
SDK from opening its temporary copy. Codesign uses this release directly, with
no local module replacement.

## Operational behavior

- Bundle executable construction precedes the replacement notice. A denied
  attribute read fails before that notice, even with `--no-strict`. The early
  `com.apple.root.installed` query checks accessibility; it does not grant Apple
  platform-signing privileges.
- Permission errors retain their original cause for `errors.Is`, while the CLI
  reports `Permission denied` or `Operation not permitted`. Executable discovery
  failures identify the executable; failures inside nested bundles identify the
  immediate subcomponent with an absolute path.
- Ordinary resource traversal uses held root-relative descriptors when readable
  resource data has a denied pathname attribute lookup. It retains regular-file,
  no-follow, identity, hard-link and size checks. An unreadable resource is never
  silently dropped from the envelope.
- Attribute stripping remains ordered and nontransactional. A successful fork
  removal survives a later FinderInfo permission failure or cancellation.
  Disappearance between a positive size query and removal is successful, matching
  Apple's options-zero removal. Unrelated metadata is retained.
- Final replacement metadata permissions are checked during preparation, before
  an envelope is committed. Later access-time refresh and commit ordering remain
  separate operations. Dry runs do not commit code bytes, but can strip metadata.

The same signing policy and explicit AppleDouble protocol run on Linux, macOS
and Windows. Host ACL namespaces differ; Linux attributes named `user.com.apple.*`
are not silently renamed, and neighboring AppleDouble files are not auto-discovered.
Content-handle acquisition uses typed `x/sys` wrappers with no-follow semantics
under a held directory; codecs and metadata operations remain in the shared SDK.

## Evidence

[`signing_permissions_darwin_test.go`](../acceptance/signing_permissions_darwin_test.go)
contains 400 native differential cases: thin/universal Mach-O, application roots,
main executables and resources, framework executables/resources, and nested main
executables. Each tests real read-attribute, read-EA, write-EA or write-data denials
under default, stripping, dry-run and no-strict policies. Directory resource forks
are not constructible on Darwin, so application-root cases use FinderInfo.

Both implementations receive fresh identical inputs at the same path. Assertions
compare status, both output streams, bytes, all target attributes and replacement
identity. A single evidence record retains both observations. Resource failure
checks use an independently successful Apple signing control: only an entirely
unchanged or entirely completed independent child is permitted; failed ancestors
and unrelated members must remain unchanged. Completed manifests are retained in
the evidence. Arbitrary partial child bytes never pass.

[`signing_permissions_test.go`](../acceptance/signing_permissions_test.go) exercises
six actual CLI write-denial cases on **every** producer using Darwin ACLs, Windows
DACLs or Linux modes, verifies that the denial is effective, and compares the
complete result with unrestricted signing. Portable API tests cover permission
errors, cancellation, permanent partial carrier removal and control-value retention.
The existing 1,664 signing-sideband cases and replacement-notice tests remain.

[`apple-sideband.json`](../spec/apple-sideband.json) contains fifteen complete
pinned Apple bodies compiled with Clang against both host SDK targets. Added
bodies cover `appleInternalForcePlatform`, `isPlainFile` and `checkPlainFile`.
The [BundleDiskRep constructor and setup](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/bundlediskrep.cpp)
are source-reviewed for construction order. Native observations qualify the
current host behavior; this is not a reconstruction of Apple's private CLI.

CI retains all three producer jobs, native comparison, foreign-artifact verification,
race/fuzz, lint and coverage **above 95% in every production package**, combining
unit and real CLI coverage. A draft remains unqualified until those gates pass.

## Outstanding qualification

This bounded permission matrix does not complete filesystem or codesign parity.
Native executable ACL inheritance differs from the SDK's deliberate source-ACL
preservation contract. Deny-write staging is fixed; the separate ACL policy,
inherited ACE ordering and write-attribute/security/delete/append rights still
require native qualification and implementation. This matrix does not claim to
compare resulting ACL records.

Additional work includes alternate filesystems, sandbox/authorization contexts,
concurrent path/content/ACL mutation, custom resource rules, generic/xattr-backed
code, detached signatures and large streamed executable signing. These remain in
the [full implementation plan](implementation_plan.md); no feature is promoted to
fully verified by this increment.
