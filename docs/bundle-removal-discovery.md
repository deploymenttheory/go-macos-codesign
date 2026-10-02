# Bundle discovery during signature removal

`--remove-signature` can use a supported bundle's `Info.plist` as its nominal
executable when no executable candidate is discoverable. This matters for resource-only
bundles, an app whose declared executable has been removed, and installer-style
metadata in an existing Contents layout, or metadata-attribute/security denial on
the executable. Apple stores this representation's
signature in extended attributes on the plist. Removing it preserves the plist's
data fork and inode, then removes the selected bundle's signature envelope.

The same implementation runs on Linux, macOS and Windows. Native metadata uses
APFS v0.16.0; foreign Apple metadata can be supplied through the existing explicit
`--appledouble-map`. There is no implicit sidecar discovery or Linux xattr renaming.
Signing, display and verification retain their existing metadata requirements.

## Selection and mutation

For directory operands in supported Contents, flat-framework and versioned-framework
layouts, removal reads bounded metadata and:

1. Uses a nonempty string `CFBundleExecutable`. If the key is absent, tries the
   historical `NSExecutable` key. An empty or non-string value falls back to the
   bundle directory's stem; a present invalid modern key does not select the old key.
   [Missing or empty metadata](removal-empty-metadata.md) supplies no keys.
   Versioned framework arbitration does not use a framework-stem fallback.
2. Searches the selected base's `MacOS` directory, then the base itself. Contents
   bundles also search their wrapper root. A found candidate proceeds through the
   existing Mach-O or generic remover. Read failure or malformed Mach-O after
   selection does not authorize fallback.
3. Queries candidates with APFS `hostdata.StatMetadata`. If they are missing or
   metadata discovery is permission-denied, selects Info.plist and uses the ordered
   generic writer. The native corpus distinguishes readattr/readsecurity denial
   from read/readextattr denial, which leaves selection intact. The SDK query
   requests neither file data nor extended attributes on Windows, where Go's
   `Root.Lstat` requests data access. Later data/attribute-read failures remain fatal.
   `CFBundleIdentifier` and `CFBundlePackageType` are not removal prerequisites.
   `IFMajorVersion` does not prevent this fallback.
   If no real plist exists either, removal returns the native bad-bundle diagnostic
   without mutating files or the signature envelope.
4. Requires writable access to the selected generic file, removes canonical
   signature attributes before the remaining signature namespace, and preserves
   earlier changes if a later operation fails. Only successful attribute removal
   proceeds to envelope cleanup. `--dryrun` retains native removal behavior.

Unselected executable bytes, resource forks, FinderInfo, unrelated attributes and
hard-link identity retain the [generic removal contract](generic-removal.md).
The existing rooted containment and regular-file checks remain enforced. Resource
scanning and recursive removal are not introduced.

## Evidence and tests

[CoreFoundation source](https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBundle.c)
establishes the modern-key, old-key and bundle-stem selection order.
[BundleDiskRep::setup](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/bundlediskrep.cpp)
selects FileDiskRep on a real Info.plist when executable discovery fails.
The existing bundle-layout AST also records the setup body. Three additional
complete executable-name/existence functions plus three metadata-dictionary/URL
functions are compiled through Clang against the host SDK
for arm64 and x86_64; private types/helpers are explicit declaration shims.

The historical source searches alternate platform folders. Current macOS 27
probes do not select an executable placed only in `Contents/Mac OS X`; the current
native result governs this profile. Source analysis alone is not a parity claim.

- `go run scripts/extract-removal-discovery.go` regenerates
  [Clang evidence](../spec/apple-removal-discovery.json).
- `go run scripts/probe-bundle-removal.go` captures twenty native cases in
  [the discovery corpus](../testdata/bundle-removal/native.json), including
  permission outcomes and the remaining malformed-plist prerequisite. It also
  records the independent Go rooted-stat authorization result before removal.
- Thirteen supported native corpus cases replay through the portable API with
  input/output hashes, plist inode identity, signature-carrier selection and
  envelope results. Evidence tests verify driver and fixture hashes.
- Eight additional fixture shapes join the existing generic acceptance matrix:
  three bundle layouts, installer metadata, missing/empty/non-string executable
  keys, and the historical-directory control. All three hosts run native and
  explicit-carrier tests; macOS compares against `/usr/bin/codesign`.
- Each foreign producer now exports 51 generic-removal records. Apple's import
  job requires both producers for all 51, including all 24 new fallback records
  per producer. It compares complete tree hashes and metadata against independent
  native removals. Earlier required archives and records remain mandatory.
- Fallback apps and frameworks also have effective write-denial and dry-run
  acceptance. Twelve native ACL comparisons cover readattr, readsecurity, read and
  readextattr across all three layouts, preserving bytes, inode identity, ACLs and
  unselected signature attributes. An additional explicit-carrier test requires
  an effective metadata-discovery denial on every host (Darwin readattr, NTFS
  file READ_ATTRIBUTES plus parent directory-list denial, Linux parent search),
  without claiming identical ACL models. NTFS otherwise permits child-attribute
  discovery through directory listing; the fixture denies both sources of access
  and restores the parent before the child. It checks the same SDK query used by
  discovery before invoking the CLI. Existing unreadable-executable tests require
  data denial to remain fatal and preserve the original signature.
  Unit tests cover failed loader ownership, unsupported metadata,
  path containment and malformed selected executables. The new discovery module
  has complete local unit statement coverage.
- The [missing/empty metadata corpus](removal-empty-metadata.md) adds 27 portable
  API/CLI cases and 54 mandatory foreign observations, with native comparisons
  of signature selection, complete tree hashes, data and inode preservation.

Native probes use temporary fixtures and no private signing identity or keychain.
Existing CI requirements remain unchanged: every production package above 95%,
three runtime platforms, native import comparisons, race/fuzz, lint and six
GoReleaser build targets. Passing local tests do not replace those gates.

## Remaining discovery work

This closes absent-executable and the tested metadata-permission fallback profiles
for valid, missing or zero-byte metadata in the documented supported layouts.
It does not close the following native behaviors:

- Broader CoreFoundation property queries, filesystem errors and authorization
  contexts. The released SDK metadata-only query supplies the retained profile
  on all three hosts; additional filesystem primitives belong in APFS.
- Nonempty invalid and platform-specific Info.plist, broader shallow/legacy layouts, widgets and
  `.dist` discovery, specialized resource-root policies and executable-path
  discovery outside the currently recognized directories.
- Symlink/alias and dynamic-loader environment selection beyond existing supported
  layouts; concurrent changes during discovery.
- Signature-directory enumeration under metadata denial, parent ACL inheritance,
  and denied-delete staging cleanup, as tracked in the
  [implementation plan](implementation_plan.md).

Generic signing, verification and display remain separate open obligations. The
compatibility inventory remains partial; this does not claim complete parity.
