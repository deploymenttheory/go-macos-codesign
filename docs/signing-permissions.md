# Signing permissions

Signing a readable executable does not require permission to overwrite its
existing data in place. Codesign writes a private replacement and commits it
after preparing its content and metadata. Published
[APFS v0.15.1](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.15.1)
fixes this staging prerequisite: a source deny-write ACL no longer prevents the
SDK from opening its temporary copy. Codesign retains this fix in v0.16.0, with
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
- Executable preparation retains a private writable replacement and the source
  handle. After preceding envelopes and child cleanup succeed, the writer copies
  source access time, restores final metadata, syncs and closes both handles,
  then rechecks identity and renames. Restoring a deny-writeattr ACL before the
  timestamp write incorrectly rejected replacements that native codesign permits.
  Dry runs allocate without final restoration or code commits; they can strip
  metadata. Cancellation or restoration failure never publishes staged bytes.

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

[`signing_security_darwin_test.go`](../acceptance/signing_security_darwin_test.go)
adds 72 exact native comparisons across eight standalone, application, framework
and nested shapes, three ACL rights (`writeattr`, `writesecurity`, `append`) and
signing, dry-run and removal. These compare complete code bytes, output streams,
status, replacement identity, all target xattrs and the actual source/final ACL
records. Source entries survive successful replacement. The shared restoration
sequence runs on every platform; portable lifecycle tests verify source/writer
closure, cancellation, failed restoration, unchanged source bytes and cleanup.
Windows additionally verifies private writable staging, final read-only flags,
source creation/access times and retained staged modification time.

The existing [`apple-writer.json`](../spec/apple-writer.json) was regenerated
unchanged with Clang for both architectures. Its complete `MachOEditor::commit`
body copies security/metadata through the held writer after allocation, then
renames. Native tests establish the observable behavior of the current OS.

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
Native executable ACL copying retains **explicit** source entries and combines
them with entries inherited from the destination parent. It does not simply
discard source ACLs. The SDK already supplies `appledouble.InheritACL` and
`appledouble.CopyACL`; allocation-level integration must retain the correct
destination inheritance before restoration. Current replacement preserves the
source ACL, so parent inheritance and inherited-entry ordering remain open.

Broader exploratory probes found additional gaps outside the 72-case restoration
profile: deny-readsecurity can make native bundle removal select Info.plist without
replacing its executable. This bounded fallback is now implemented in PR79;
broader authorization contexts remain open. Deny-delete
can leave native `.cstemp` files while SDK private staging has different paths
and cleanup. These require separate discovery/removal and allocation/cleanup
work, including exact failure artifacts and nested completion boundaries.
They are not qualified by this increment. Reproduce the observations with
[`probe-signing-security.go`](../scripts/probe-signing-security.go).

The subsequent [shallow-removal phase](signature-removal.md) removes the
unnecessary resource/child traversal and corrects removal's CLI permission
diagnostics. [Subsequent discovery work](bundle-removal-discovery.md) adds the
selected-executable fallback. Signature-directory metadata denial remains open.

Additional work includes alternate filesystems, sandbox/authorization contexts,
concurrent path/content/ACL mutation, custom resource rules, generic/xattr-backed
code, detached signatures and large streamed executable signing. These remain in
the [full implementation plan](implementation_plan.md); no feature is promoted to
fully verified by this increment.
