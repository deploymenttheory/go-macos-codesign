# Signing permission qualification

This phase starts from merged PR74 (`96b06a8`) on
`feat/signing-permission-qualification`. It is **not ready for merge**.

The real Darwin ACL matrix in
[`signing_permissions_darwin_test.go`](../acceptance/signing_permissions_darwin_test.go)
compares native and Go signing at identical fresh operand paths. It retains
command arguments, status, both output streams, complete operand byte digests,
all target attributes before/after, and object replacement. Assertions compare
the actual bytes and attribute values, not just exit status. Read-attribute,
read-extended-attribute, write-extended-attribute and write-data denials cover
thin/universal code, application roots/executables/resources, frameworks and
nested code, with ordinary, stripping, dry-run and no-strict signing.

The expanded matrix currently fails against released APFS v0.15.0. In particular,
the SDK clones source deny-write ACL entries before opening the private copy for
writing. Native codesign can sign that readable source, whereas the SDK staging
open fails. [APFS PR186](https://github.com/deploymenttheory/go-apfs-v2/pull/186)
fixes the SDK's staging contract, with source ACL restoration after content writes.
Wait for that PR's full CI, maintainer merge and published release before updating
codesign. No local dependency replacement or reduced acceptance assertion is used.

Additional exposed differences still need resolution after the dependency update:

- Replacement-notice ordering when main-executable metadata cannot be read.
- Nested discovery error context when ACLs deny main-executable attributes.
- Exact independent-child commit outcomes after resource permission failures;
  reuse the established complete-member scheduling oracle rather than accepting
  arbitrary partial bytes.
- Native executable ACL inheritance versus the SDK's deliberate source-ACL
  preservation contract. Fixing writable SDK staging does not resolve this policy
  difference.

The branch also records two corrections for subsequent qualification: preserve
underlying permission errors while rendering native signing diagnostics, and
accept disappearance between attribute presence-query and removal. Apple's pinned
`FileDesc::removeAttr` body uses options zero and tolerates ENOATTR; its complete
body is already included in the two-target Clang evidence in
[`apple-sideband.json`](../spec/apple-sideband.json). This narrow race outcome is
not a guarantee against arbitrary concurrent path or content mutation.

Linux and Windows keep their full signing implementations. APFS PR186 adds real
write-denial tests for both SDK replacement APIs on all three hosts. Codesign's
additional portable permission and partial-failure coverage remains part of this
unfinished phase. No feature is promoted to fully verified by this checkpoint.
