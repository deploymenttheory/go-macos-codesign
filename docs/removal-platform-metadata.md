# Platform-specific removal metadata: research and SDK integration

Native macOS `codesign --remove-signature` can select `Info-macos.plist` instead
of `Info.plist`. This policy must ultimately be the same on Linux, macOS and
Windows. It is **not implemented yet**. The current removal loader still selects
ordinary metadata. APFS v0.16.0 is now adopted for shared content acquisition;
the selection-policy gap remains open.

## Measured native behavior

The [capture script](../scripts/probe-removal-platform-info.go) exercises fourteen
disposable Contents apps with attached generic signature attributes. It needs
no private keys or keychain access. The [retained results](../testdata/bundle-removal/platform-info-research.json)
identify the macOS build, native binary hash, script hash, status, diagnostic,
selected object, before/after content hashes, file identity and envelope
effect. Every case asserts the expected selection and unchanged bytes/identity.
Test ACLs are removed before reading attributes so an attribute-read denial
cannot be mistaken for a removed signature.

| Input | Native removal target |
| --- | --- |
| Both ordinary and macOS-specific metadata | Executable named by `Info-macos.plist` |
| Only macOS-specific metadata | Executable named by `Info-macos.plist` |
| `Info-macosx.plist` beside ordinary metadata | Executable named by ordinary metadata |
| Empty macOS-specific metadata | `Info-macos.plist` itself |
| macOS-specific metadata names a missing executable | `Info-macos.plist` itself |
| `CFBundleExecutable-macos` alongside the ordinary key | macOS-specific key's executable |
| `CFBundleExecutable-windows` alongside the ordinary key | Ordinary key's executable, even for the future Windows implementation |
| Platform plist is a directory, or denies data reads | Executable named by ordinary metadata |
| Platform plist denies `readsecurity`, `readextattr`, `write` or `writeextattr` | Platform executable |
| Platform plist denies `readattr` | Status 1, ambiguous app/framework diagnostic; no signature mutation |

These are bounded removal observations on the recorded host. They do not yet
qualify other layouts, malformed property lists, aliases, other override keys,
signing, display or verification.

## Source and live behavior

The existing [Clang extraction](../scripts/extract-removal-discovery.go) and
[AST evidence](../spec/apple-removal-discovery.json) include the complete
`_CFBundleCopyInfoDictionaryInDirectoryWithVersion` body from Apple's pinned
CoreFoundation source. Its platform-file read precedes the ordinary-file read;
failed acquisition can fall back, while an acquired empty dictionary retains
the platform plist URL. Preserve that distinction in the Go loader.

CoreFoundation revision `dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3` also has a
`_isBlacklistedKey` implementation that lists `CFBundleExecutable`. The current
native executable-key override probe contradicts that historical restriction.
The old body must not be treated as current-host evidence. Extend the source/AST
qualification and native cases together before implementing key normalization.

## Shared filesystem prerequisite

Reading plist data must not require reading its ACL or extended attributes.
The former codesign Windows resource opener requested `FILE_GENERIC_READ`,
including `READ_CONTROL` and `FILE_READ_EA`. That also prevented content-only
resource signing under unrelated metadata denials. A preliminary metadata stat
can likewise impose rights absent from native content acquisition.

[APFS v0.16.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.16.0)
provides `hostdata.OpenContentFileRead` on all three supported hosts. It keeps contained
parent resolution, rejects final links/nonregular objects and verifies held
identity without an extra pathname stat. Real data denial remains an error.
The APFS gate covers twelve live/retained C cases on macOS, effective Windows
rights denials and portable containment/lifetime tests, with over 95% required
per tracked implementation file. Parent-directory authorization remains the
host's responsibility.

Codesign's resource traversal and hashing now use this published reader. The
duplicated Unix `Openat` and Windows `NtCreateFile` implementations have been
removed. Sideband queries still use APFS's held-identity attribute operations;
content success does not waive a required metadata query. Replacement staging
uses `OpenMetadataFileRead`, because restoring owner/group, ACLs and EAs requires
metadata access that a content-only Windows handle deliberately lacks. Existing
replacement and sideband acceptance remain required on all three hosts.

The Windows integration tests apply effective ACL-read, EA-read and data-read
denials. Content-only signing must succeed for the unrelated metadata denials,
produce a valid resource seal and preserve resource bytes. Data denial must
fail without committing a replacement executable. OWNER RIGHTS makes the ACL
denial effective for the fixture's owner; restoration uses a previously held
security handle.

The macOS `readattr` case above is a separate **discovery policy** failure, not
evidence that the held content reader should fail. Do not conflate those stages.

## Remaining integration

1. The released reader is adopted. Keep discovery authorization separate from
   content acquisition: the captured `readattr` ambiguity and `readsecurity`
   success must both be reproduced before enabling platform-plist selection.
   Keep the module free of local APFS replacements and duplicate OS primitives.
2. Extend the loader with distinct metadata selection, content acquisition and
   dictionary interpretation stages. Retain the selected raw plist URL even
   when its dictionary supplies no executable name.
3. Qualify Contents, flat and versioned frameworks, permission discovery/read
   boundaries, filename variants, key overrides, empty and malformed input.
   Preserve existing unsupported cases until their native behavior is understood.
4. Add API/CLI and native/explicit-carrier tests on Linux, macOS and Windows.
   Import foreign-produced results on macOS and compare with native `codesign`.
   Require identical selection, effects, errors and unchanged unrelated objects.
5. Retain all existing coverage, native image, race, fuzz and release-build gates;
   reconcile the public contract only after implementation and acceptance pass.
