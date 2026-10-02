# Platform-specific removal metadata

`--remove-signature` selects `Info-macos.plist` before `Info.plist` in supported
Contents apps, flat frameworks and selected versioned frameworks. Selection uses
the macOS policy on **Linux, macOS and Windows**. A Windows host does not select
`Info-windows.plist` or substitute a Windows executable key.

This is removal discovery. Signing, display and verification retain their
existing metadata policies; this increment does not declare full CoreFoundation
or native codesign parity.

## Selection and authorization

| Input | Removal target or result |
| --- | --- |
| Both ordinary and macOS-specific metadata | Executable named by `Info-macos.plist` |
| Only macOS-specific metadata | Executable named by `Info-macos.plist` |
| `Info-macosx.plist` beside ordinary metadata | Executable named by ordinary metadata |
| Empty or empty-dictionary macOS-specific metadata, with no usable stem executable | `Info-macos.plist` itself |
| MacOS-specific metadata names a missing executable | `Info-macos.plist` itself |
| `CFBundleExecutable-macos` alongside the ordinary key | MacOS-specific key's value takes precedence |
| Empty or non-string macOS executable override | Ordinary key is replaced; existing stem/raw-plist fallback applies |
| `CFBundleExecutable-windows` alongside the ordinary key | Ordinary key's executable |
| Platform plist is a directory, or acquisition denies data reads | Fall back to ordinary metadata |
| Platform plist denies ACL reads, EA reads, data writes or EA writes | Platform executable remains selected |
| Platform plist denies basic attribute discovery | Status 1, ambiguous app/framework diagnostic; no signature mutation |

Discovery, content acquisition and dictionary interpretation are separate steps.
An acquired empty platform plist retains its raw URL. It does not cause an
ordinary-plist retry. Existing app/flat-framework stem fallback and the distinct
versioned-framework name arbitration still apply. Selected executable failures
remain failures; they do not authorize retrying an ordinary executable.

The selected generic file retains its bytes and inode while signature attributes
are removed. Other files and their attributes remain untouched; successful
removal then purges the selected signature envelope. Native attributes and
explicit mutable AppleDouble bindings use the same selection policy. There is
no automatic discovery of neighbouring AppleDouble files.

## Shared APFS operations

The implementation pins published [APFS v0.17.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.17.0),
which contains merged [PR192](https://github.com/deploymenttheory/go-apfs-v2/pull/192).
All 63 applicable upstream checks passed in its
[final workflow](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/37027802219).
No local SDK replacement or duplicate OS primitive is introduced.

`hostdata.ReadEntryType(root, name)` performs rooted basic-attribute discovery.
On macOS the approved typed wrapper requests only `ATTR_CMN_OBJTYPE` through
`getattrlistat`, without following the final link. Windows uses the SDK's typed
NT opener with basic-attribute rights; Linux uses rooted Lstat. Actual host
parent/basic-attribute authorization still applies. This query does not simulate
foreign ACLs or hold the discovered object open.

`hostdata.OpenContentFileRead` then acquires a contained regular file without
requesting its ACL or extended attributes. Discovery denial produces the native
ambiguity error, while content-read denial permits ordinary-plist fallback.
The shared SDK also preserves physical parent `link/..` resolution on Windows.

Explicit AppleDouble bindings still check missing paths and reject duplicate
object identities. If ordinary stat is denied only because it requests ACL
visibility, the adapter can obtain regular-file identity through the shared
content reader. Effective combined ACL/data denial remains an error. Existing
replacement staging continues to use the metadata reader because restoring
owner/group, ACLs and EAs requires that access.

## Native evidence and portable acceptance

The original [fourteen-case research capture](../testdata/bundle-removal/platform-info-research.json)
remains required. The new [capture driver](../scripts/probe-removal-platform-selection.go)
and [33-case corpus](../testdata/bundle-removal/platform-selection.json) cover
eleven selection states across all three layouts. They record exact input bytes,
layout links, selected object, status/output, content hashes, inode preservation
and signature/envelope effects, with native binary and capture-source hashes.
They use disposable generic signature attributes, with no private key or keychain.

The API replays every retained case. CLI acceptance runs every case with explicit
AppleDouble bindings on all three producers and with native attributes on macOS.
The existing foreign-import job requires **66 additional records**: each of the
33 cases from both Linux and Windows, compared with fresh Apple observations.
Another **18 native permission comparisons** cover six rights across the three
layouts, checking Apple, Go native metadata and Go explicit bindings. They also
check that the operation leaves the ACL unchanged.

Effective discovery denials run on all three hosts; Windows additionally tests
ACL-read, EA-read and data-read boundaries, and non-root Linux tests a real
data-read denial. Denial fixtures must first demonstrate that access is actually
blocked. Darwin tests retain hard-link duplicate detection under ACL denial and
reject combined ACL/data denial. No permission case is replaced with a skip.

The [Clang extraction](../scripts/extract-removal-discovery.go) and
[AST evidence](../spec/apple-removal-discovery.json) contain six complete Apple
bundle-discovery bodies plus two dictionary operations for both Mac architectures. The pinned
`_CFBundleCopyInfoDictionaryInDirectoryWithVersion` body establishes platform
read precedence, acquired-empty dictionaries and retained raw URLs. Current
authorization and executable overrides are established independently by the
native captures. Apple's historical CF revision
`dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3` blacklists
`CFBundleExecutable` in `_isBlacklistedKey`; that restriction contradicts the
current host's measured override and is not presented as its implementation.

See [progress](progress.md) for the tested revision and actual CI results. All
existing coverage above 95% per production package, native/foreign acceptance,
race, fuzz, provenance and six-target GoReleaser gates remain mandatory.

## Outstanding work

1. **Property-list parsing:** the [bounded removal interpreter](removal-plist-interpretation.md)
   now qualifies XML/OpenStep/binary interpretation, captured syntax failures,
   non-dictionary roots and duplicate-key order. Other text encodings and broader
   grammar/object types remain open. Unsupported formats and resource limits must
   never be converted silently to empty metadata.
2. **Aliases and discovery:** final plist symlinks, wider root aliases,
   alternate layouts, filename case/Unicode, concurrent replacement and broader
   parent authorization contexts need qualification. Final platform links and
   nonregular files currently return unsupported; containment remains enforced.
3. **Dictionary normalization:** other platform/product-qualified keys, legacy
   combinations and precedence outside the captured executable-key profile
   remain open. Extend source/AST evidence and native captures together.
4. **Other operations:** apply independently qualified platform metadata policy
   to signing, verification and display, including resource seals, raw plist
   binding and operation-specific failure order.
5. **Wider filesystem work:** signature-directory enumeration under metadata
   denial, replacement ACL inheritance, temporary-artifact cleanup and sandbox/
   process contexts retain their separate roadmap obligations.
