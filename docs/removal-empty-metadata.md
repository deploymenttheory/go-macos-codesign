# Removal with missing or empty bundle metadata

Signature removal does not need an Info.plist dictionary to construct a new
signature. For supported directory operands, a missing or zero-byte Info.plist
now supplies no executable-name keys. This lets resource-only bundles and apps
with incomplete metadata use the representation that native `codesign` selects.
The policy is the same on Linux, macOS and Windows and uses published APFS v0.16.0.

## Selection

| Layout | No executable-name key | No discoverable executable |
| --- | --- | --- |
| Contents app | Search for the bundle stem using the existing directory order | Select the real Info.plist, including a zero-byte file |
| Flat framework | Search for the framework stem | Select the real Resources/Info.plist |
| Versioned framework | Native version arbitration does not select the framework-stem executable | Select the selected version's real Resources/Info.plist |

If neither an executable nor an Info.plist exists, removal reports
`bundle format unrecognized, invalid, or unsuitable` and leaves every file and
the signature envelope untouched. It does not create missing metadata. An
unnamed executable left at its old declared name is not selected merely because
it exists. A selected Mach-O uses the existing replacement writer; a selected
generic file uses in-place attribute removal. Unselected signatures, data and
file identities remain unchanged.

An empty dictionary has the same name-selection behavior as empty metadata.
This also corrects the framework-stem fallback for versioned frameworks whose
valid dictionary contains no usable executable-name key. Explicit executable
names continue to use the existing discovery path.

Signing, display and verification retain their metadata requirements. The
removal loader still enforces bounded reads, rooted containment and regular-file
checks. File-read errors are not converted into absence. Parsing errors in
nonempty metadata remain rejected; Apple accepts some such files, so this is
still an explicit compatibility gap, not evidence of full discovery parity.

## Evidence and acceptance

The retained [native corpus](../testdata/bundle-removal/empty-info.json) contains
27 cases: three layouts, missing/zero-byte/empty-dictionary metadata, and an old
declared-name executable, a bundle-stem executable or no executable. The
[Go capture script](../scripts/probe-removal-empty-info.go) records the host and
native binary hash, CLI status and output, both files' signature state, data
hashes, inode preservation and envelope state. It uses disposable fixtures and
does not access signing keys.

All 27 cases replay through the library on each host. CLI acceptance repeats
them with explicit AppleDouble mappings on every producer, checks unrelated
metadata, and compares both the mapped and native-metadata paths with Apple's
binary on macOS. Each foreign producer exports 27 observations; the existing
Mac import job requires both copies of every case and independently compares
complete tree hashes and file/metadata outcomes. These 54 observations are
additional to the existing 102 generic-removal records and all earlier artifacts.
Three portable Mach-O architecture cases qualify dispatch with a missing plist.

The [Clang record](../spec/apple-removal-discovery.json) contains six complete
bundle-discovery functions and two dictionary operations compiled for arm64 and
x86_64 against the host SDK. The
CoreFoundation functions synthesize empty dictionaries and retain real/raw plist
URLs. Private bundle fields, locks, directory iteration, logging and key symbols
are declaration shims; the function bodies are verbatim. Current native probes
qualify version arbitration independently of historical source.

All existing CI gates remain required: coverage above 95% per production
package, Linux/macOS/Windows execution, native and foreign-artifact comparisons,
race/fuzz, golangci-lint and six GoReleaser targets.

## Remaining work

- Broader encodings/grammar and property/authorization queries. Bounded
  [plist interpretation](removal-plist-interpretation.md) and
  [platform selection](removal-platform-metadata.md) now have their own native
  and mandatory portable acceptance profiles.
- Legacy/shallow layouts outside the supported profile, widgets, `.dist`
  discovery and executable-path aliases.
- Signature-directory metadata denial, ACL inheritance and exact denied-delete
  staging artifacts. Generic signing, display and verification also remain open.

The ACL audit found a shared-SDK prerequisite: replacement restoration currently
installs the complete source ACL. Codesign needs allocation-time destination
inheritance combined with explicit source entries using APFS `InheritACL` and
`CopyACL`, followed by a single final security restoration. Applying a second ACL
after restoration can itself be blocked by a restored deny-write-security entry.
The SDK must expose that lifecycle without changing existing callers' default
preservation policy, and qualify native host ACLs and transported Apple ACL
policy on all three hosts before codesign adopts it.
