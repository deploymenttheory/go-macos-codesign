# Signing attached metadata

Signing checks for nonempty `com.apple.ResourceFork` and `com.apple.FinderInfo`
on supported Mach-O code and included bundle resources. This is a signing
preflight default; it does not require `--strict`. Linux, macOS and Windows use
the same policy and the released APFS SDK's native metadata operations.

```sh
macoscodesign -s - --strip-disallowed-xattrs Example.app
macoscodesign -fs - --deep --strip-disallowed-xattrs Example.app
macoscodesign -s - --appledouble metadata.ad --strip-disallowed-xattrs executable
macoscodesign -fs - --appledouble-map metadata.json --strip-disallowed-xattrs Example.app
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

## Explicit portable metadata

`--appledouble` and `--appledouble-map` have the same explicit object-binding rules
as [verification](sideband-policy.md). Native metadata is additional input; a
carrier cannot conceal it. Neither operation discovers neighboring `._` files or
restores foreign attributes onto the host. Linux `user.com.apple.*` attributes
remain distinct native names, rather than an implicit Darwin-name remapping.

Stripping an explicit carrier authorizes changes to that carrier, including on a
dry run. Native removals happen first; carrier removals follow in ResourceFork,
FinderInfo order. Each carrier removal uses APFS's streaming decoder/encoder,
retains unrelated decoded attribute values and produces a canonical snapshot.
Padding, record placement and ignored nonsemantic wire data are not a preservation
contract. Each removal is staged before writing through the original held carrier,
preserving its object identity, hard links, mode and native metadata. Commit errors
can leave partial bytes. Cancellation is checked during streaming and between
commit reads. Shared references to one carrier observe its updated contents.

Keep metadata carriers outside signed resource trees unless their changed bytes
are deliberately part of the resources being signed. Keep operands and metadata
stable for the duration of the operation; hostile concurrent mutation is not yet
a qualified profile.

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

[`apple-sideband.json`](../spec/apple-sideband.json) records twelve complete pinned
Apple bodies compiled with Clang for both architectures, including strict
representation checks and resource hashing. The source-reviewed
[`Signer::prepare` and `buildResources`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/signer.cpp)
connect default preflight, resource stripping and nested dispatch. These larger
signer bodies are not claimed as compiled AST evidence.

Broader native ACL/read-only denial matrices, concurrent path/attribute changes,
alternate filesystems, custom resource rules, generic/xattr-backed code, detached
signatures, signing selector combinations and large streamed executable signing
remain roadmap work. The compatibility inventory therefore records this feature
as partial. The production coverage threshold, native failure handling, race/fuzz,
foreign-signature verification and six GoReleaser builds remain mandatory.
