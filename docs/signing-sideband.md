# Signing attached metadata

Signing checks for nonempty `com.apple.ResourceFork` and `com.apple.FinderInfo`
on supported Mach-O code and included bundle resources. This is a signing
preflight default; it does not require `--strict`. Linux, macOS and Windows use
the same policy and the released APFS SDK's native metadata operations.

```sh
macoscodesign -s - --strip-disallowed-xattrs Example.app
macoscodesign -fs - --deep --strip-disallowed-xattrs Example.app
```

The option removes only nonempty prohibited attributes. ResourceFork is queried
and removed before FinderInfo. Empty attributes and unrelated values are retained.
Presence-query EPERM has Apple's Darwin-specific absence treatment; removal EPERM
is an error. Successful removals remain after a later query, write or cancellation
failure. No attribute rollback is implied.

**A dry run can remove metadata.** `--dryrun` suppresses Mach-O signature commits,
but it does not suppress this earlier stripping. UDIF uses Apple's separate
representation override: it neither rejects nor strips these attributes. Its
existing ad-hoc dry-run component writes still apply.

| Object or option | Signing behavior |
| --- | --- |
| Signed outer input without `--force` | Reject before stripping |
| Bundle canonical root, then main executable | Strip if requested, then reject remaining prohibited data |
| Versioned framework | Check selected version root and executable; keep outer framework metadata |
| Included ordinary resource | Strip if requested, then apply signing preflight before hashing |
| Resource symlink | Seal link text; this stripping branch does not visit its target |
| Omitted Info.plist/signature files and ordinary directories | No resource stripping; framework Resources/Info.plist is included |
| Nested code | Process when `--deep` selects it for signing; preserve existing signed children unless forced |
| `--no-strict` | Suppress code-object checks and stripping; explicit ordinary-resource stripping still runs |
| Verification, display or signature removal with strip | Accept the flag without adding metadata mutation |

An independent child can finish signing before another resource worker fails.
The Go signer commits successful independent work, preserves the failed code and
its ancestors, and returns the failure. Apple's exception-aware dispatcher may
leave independent children unstarted. Acceptance checks complete before/after
member manifests and independently verifies fully completed results; it does not
accept arbitrary partial bytes or changes to failed ancestors.

## Filesystem metadata and library snapshots

The shared APFS view selects native attributes or FAT/exFAT dot-underscore
storage. It performs stripping on that selected storage. Linux native
`user.com.apple.*` names remain distinct and are not remapped.

Explicit AppleDouble snapshots are an additional library input. Filesystem
removals happen first, followed by snapshot removals in ResourceFork/FinderInfo
order. A mutable snapshot's implementation owns its commit, identity and failure
contract. The shared rewrite helper produces canonical snapshot encoding;
filesystem-selected removal instead preserves the VFS carrier layout.

Library callers use `SignOptions.NoStrict`, `StripDisallowedXattrs`, `AppleDouble`
and `AppleDoubleFiles`. A carrier requiring removal must implement
`MutableAppleDouble.RemoveAttribute`; read-only carriers remain valid for rejection
checks or clean inputs. The caller owns each carrier's lifetime and mutation
contract. `SignBytes` rejects carrier inputs because it has no filesystem object.

## Evidence and remaining qualification

[`signing_sideband_test.go`](../acceptance/signing_sideband_test.go) adds 1,664
portable cases across thin/universal Mach-O, UDIF, applications, flat/versioned
frameworks and recursive bundles. The macOS runner additionally compares Apple's
CLI, exact failure diagnostics, output bytes, native attributes and object
replacement. Evidence is retained by the existing acceptance harness. Protocol
tests exercise query/removal errors, partial removal, cancellation, carrier
validation and unrelated-value retention on every producer.
Three additional portable cases compare absolute nested failure paths when the
CLI operand is relative. Windows runs the existing replacement, certificate and
dry-run regressions with the preflight handle released before replacement.

The [permission matrix](signing-permissions.md) adds 400 native ACL comparisons
and six portable write-denial CLI cases using published APFS v0.15.1. It covers
executable preflight, diagnostic ordering, readable-resource traversal and partial
metadata removal without weakening byte, metadata or failure assertions.

[`apple-sideband.json`](../spec/apple-sideband.json) records fifteen complete pinned
Apple bodies compiled with Clang for both architectures, including strict
representation checks and resource hashing. The source-reviewed
[`Signer::prepare` and `buildResources`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/signer.cpp)
connect default preflight, resource stripping and nested dispatch. These larger
signer bodies are not claimed as compiled AST evidence.

Remaining native ACL inheritance/security/write-attribute rights, concurrent path/attribute changes,
alternate filesystems, custom resource rules, generic/xattr-backed code, detached
signatures, signing selector combinations and large streamed executable signing
remain roadmap work. The compatibility inventory therefore records this feature
as partial. The production coverage threshold, native failure handling, race/fuzz,
foreign-signature verification and six GoReleaser builds remain mandatory.
