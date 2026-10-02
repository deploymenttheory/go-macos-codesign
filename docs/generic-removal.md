# Generic signature removal

Apple stores signatures for scripts and ordinary files in `com.apple.cs.*`
extended attributes. `--remove-signature` now removes those signatures in place
on Linux, macOS and Windows. The data fork, inode, hard links and unrelated
metadata remain intact. Generic executables selected by the existing app and
framework layouts also have their bundle signature envelope removed.

This is removal support. Generic signing, verification and display are still
outstanding. Bundle discovery still requires the existing explicit executable
metadata; CoreFoundation's fallback to signing an Info.plist is not yet integrated.

## Use

```sh
macoscodesign --remove-signature ./script
macoscodesign --remove-signature --appledouble ./script.metadata ./script
macoscodesign --remove-signature --appledouble-map ./metadata-map.json ./Example.app
```

The map has the same object-path-to-carrier-path format as signing and strict
verification. Inputs are explicit: neighboring sidecars are never discovered
implicitly. Native metadata is always processed first. Library callers can use
`codesign.Remove(ctx, path, codesign.RemoveOptions{AppleDouble: carrier})`, or
`AppleDoubleFiles` for bundles. A carrier containing signature attributes must
implement `codesign.MutableAppleDouble`. Existing `RemoveSignature` and
`RemoveSignatureWithOptions` calls remain compatible.

Linux cannot store unnamespaced `com.apple.*` attributes. A native inventory
establishes their absence; `user.com.apple.cs.*` remains a distinct, untouched
namespace. Explicit AppleDouble carriers provide the full Apple namespace,
including present-empty and case-sensitive values, on every host. Windows uses
APFS's real NTFS EA operations; that native namespace is case-insensitive and
cannot retain present-empty EA values. Explicit carriers retain those distinctions.
No native attribute error is silently treated as absence.

## Operation and failure order

1. Resolve the operand and classify its representation with bounded header reads.
   Short files and Mach-O object files are generic. A recognized loadable Mach-O
   with malformed commands stays on the Mach-O validation path.
2. Open the generic writer read/write and verify it still identifies the object
   that was classified. Apple requires this access even when no signature exists.
3. Remove the twelve canonical signature names in slot order, including empty
   values; a genuinely absent attribute is success.
4. List attributes and remove the remaining names in the `com.apple.cs.` namespace,
   including alternate directories and unknown signature attributes.
5. Process an explicitly supplied carrier with the same removal protocol. The
   shared APFS streaming codec preserves unrelated decoded metadata values.
6. For a bundle, purge its signature directory after the generic writer succeeds.

Completed removals survive later failures or cancellation. In particular, a
standalone macOS read-EA denial occurs at the listing stage, after the canonical
names have been removed. Bundle platform-metadata queries can fail earlier.
Write/data-access denial prevents mutation. Cancellation is checked between
operations; it cannot interrupt a syscall already in flight. Carrier writes
retain the existing in-place commit contract: a failed write can leave a partial
carrier and is not rolled back.

Mach-O removal still replaces the executable and preserves attached attributes.
UDIF removal remains unsupported as in native codesign. Encrypted disk images and
dyld caches do not fall through to generic mutation. FAT64 stays on the existing
Mach-O parser path; complete dispatch compatibility for those specialized and
legacy formats remains outstanding. `--dryrun` does not suppress native generic
removal, and removal does not recurse into child bundles.

## Evidence and acceptance

- [`extract-generic-removal.go`](../scripts/extract-generic-removal.go) compiles
  eight complete, verbatim Apple methods on both SDK architectures and retains
  their ASTs and source hashes in [`apple-generic-removal.json`](../spec/apple-generic-removal.json).
- [`probe-generic-removal.go`](../scripts/probe-generic-removal.go) retains forty
  native dispatch/permission observations in
  [`native.json`](../testdata/generic-removal/native.json). Driver, input and native
  binary hashes identify the evidence. Portable unit tests replay successful and
  malformed dispatch cases using explicit carriers on every host.
- The published source's `flush` compares thirteen bytes with a twelve-byte
  prefix. Current macOS removes arbitrary names under `com.apple.cs.*`; the
  implementation follows the measured native behavior. This source discrepancy
  is recorded rather than silently changing the extracted C++ body.
- The acceptance suite includes 102 native/carrier cases across seventeen shapes and
  three attribute states, six effective write denials, four alias cases, four
  dry-run controls and a sparse data fork above 1 GiB. Native ACL acceptance adds
  48 comparisons, plus removal of a script signed by Apple's ad-hoc signer.
- Foreign producers each export 51 generic-removal records. The existing native
  artifact job requires all 102 and compares data hashes, metadata, diagnostics and
  inode-preservation results with independent Apple removals. Earlier artifact
  requirements remain mandatory.
- Unit tests cover protocol ordering, list/removal failures, cancellation, readonly
  or malformed carriers, namespace boundaries, bounded probing and changed writer
  identity. Every production package must still exceed 95% combined coverage;
  race, fuzz, lint, six GoReleaser targets and all three runtime suites remain gates.

Reproduce research with `go run scripts/extract-generic-removal.go` and
`go run scripts/probe-generic-removal.go` on macOS. Native acceptance uses ad-hoc
identities only and does not require a login-keychain password.

## Next work

[Info.plist fallback](bundle-removal-discovery.md) now preserves the generic writer's
contract when candidates are absent or their discovery stat is permission-denied
in supported bundle layouts. Broader property/authorization discovery remains open.
Signature-directory enumeration under
metadata denial, destination ACL inheritance and denied-delete staging cleanup
still require the shared APFS work tracked in the
[implementation plan](implementation_plan.md). Generic signing, verification,
display, detached signatures, wider authorization contexts and concurrent mutation
remain separate parity obligations.
