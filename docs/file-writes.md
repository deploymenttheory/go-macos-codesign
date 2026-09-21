# File replacement and metadata

Standalone and bundle Mach-O signing, re-signing and signature removal prepare a new file,
restore its metadata, sync and close it, and rename it over the selected name.
Other hard-link names retain the original inode and bytes. Removing a signature
from an unsigned Mach-O also replaces the inode. Dry runs preserve all names.

The filesystem implementation belongs to
[`go-apfs-v2/pkg/hostmeta` in v0.5.0](https://github.com/deploymenttheory/go-apfs-v2/tree/v0.5.0/pkg/hostmeta).
Standalone writes call its `PrepareReplacement` and `RestoreMetadata` APIs.
Bundle writes use the root-relative `PrepareReplacementAt` API delivered in
[APFS PR #102](https://github.com/deploymenttheory/go-apfs-v2/pull/102) and released
in v0.5.0, which this module pins. Codesign owns the signing-specific decision
to rename. It has no copied platform metadata writer.
The existing `go-apfs-v2/pkg/disk` dependency continues to own the UDIF model.

The directory-stat follow-up on this development branch additionally requires
`CopyDirectoryStat` from [APFS PR #104](https://github.com/deploymenttheory/go-apfs-v2/pull/104).
It is tested locally with an external Go workspace. The dependency must be
released and pinned before this branch can build without that workspace or merge;
`go.mod` still records the released v0.5.0 replacement baseline.

On macOS the new replacement path uses the supported x/sys libSystem wrappers
`Fclonefileat`, `Setattrlist` and `Fchflags`, with CGO disabled. Its private staging
directory has inherited ACLs cleared before cloning so destination inheritance
cannot add permissions to the source ACL. Ownership, mode, xattrs, ACLs, birth
time and supported BSD flags are preserved. It requires filesystem clone support:
HFS+ and other non-cloning filesystems fail before replacement. Protected and
compressed source files are also unsupported by this path.

Linux restores ownership, mode and readable xattrs, including POSIX ACLs, with
8 MiB bounds for attribute names and values. Linux inode flags and creation time
are outside the current preservation contract. Windows copies alternate streams
and attributes, then restores owner/group and DACL; SACL preservation is not
claimed. The root-relative Windows API limits extended attributes/streams to
8 MiB and rejects compressed, encrypted, sparse and reparse files. A Windows
read-only destination may reject the final rename.

The shared library's older compression-aware attribute reader retains its
existing raw-syscall/fallback implementation. The new replacement API does not
call it. Codesign's own production-source guard rejects direct syscalls.

DMGs retain Apple's in-place write behavior: both hard-link names observe the
new signature. Existing bundle CodeResources files also update in place on
sign/re-sign and are unlinked on removal; their external links retain the
updated or removed file's bytes respectively. New envelopes are created beneath
the opened bundle root. Internal hard links to writable bundle files remain
rejected by the structural scan.

Bundle signing stages every executable replacement before any bundle write.
Preparation and cancellation failures before commit preserve the original tree
and clean staging directories. Commits proceed descendant-first, with each
resource envelope preceding its main executable. Each executable rename checks
the original file identity again. A later I/O or cancellation failure can leave
earlier commits in place; this is not whole-tree rollback. Removal replaces only
the selected main executable and empties its signature directory, retaining the
directory itself. Descendant signatures remain unchanged during outer removal.

For supported regular files in `_CodeSignature`, signing excludes old sidecars
from resource seals and purges them after committing that bundle's main executable.
Only the newly written `CodeResources` remains. Removal purges all regular files,
including unknown names, even for an unsigned executable. Unlinking preserves
external hard-link neighbours' bytes and inode. Dry runs preserve every sidecar.
Verification still rejects unexpected signature files; accepting them for cleanup
does not relax verification. Cleanup stays beneath an opened metadata-directory
root, rejects non-regular entries and bounds the number of entries inspected.

Directories and symlinks inside `_CodeSignature` remain unsupported during the
initial scan. Native sign/removal can commit the executable before rejecting
these entries, and native dry runs can succeed; Go rejects them before writes.
This failure-order difference is recorded by acceptance tests. Cleanup failures
after a commit do not roll it back or commit later prepared executables.

The first bundle slice does not reproduce every native metadata side effect.
Native probes show Apple can add inherited executable-directory ACL entries and
change creation time; our replacement preserves the original ACL and birth time.
Mode, owner/group, the tested xattr and supported flags survive both writers.
New signature directories copy the canonical bundle root's stat metadata through
APFS. A versioned framework uses the selected physical version directory, including
when selected through the framework root. Only successful creation triggers the
copy; existing directory metadata stays intact. Dry runs and removal do not create
directories. Source xattrs and directory contents are not copied.

Darwin copies owner/group, mode, nanosecond access/modification times and supported
BSD flags, dropping source tracked/protected flags and privileged mode bits on
nosuid volumes. Other source flags and unsupported destination flags are rejected.
Linux copies owner/group, mode and times (kernel 5.8+); its inode flags and birth
time are outside this profile. Windows copies ordinary attributes and times while
retaining destination security descriptors, creation time and streams.

Apple's full `COPYFILE_SECURITY` also combines explicit source ACL entries with
inherited destination entries. Our directory-stat profile retains the destination
ACL but does not copy explicit source entries; subsequent CodeResources ACL
inheritance therefore also differs. Linux mode updates can change a POSIX ACL mask.
The current supported Darwin Go/x/sys API has no ACL reader; no native binding or
raw syscall was introduced to bypass that boundary. Apple ignores some metadata
copy errors, whereas this API returns them. Failure after directory creation can
leave an empty or partially updated directory, before its envelope/executable
commit. Creation time is not explicitly copied; Darwin can lower it when an older
modification time is applied. Later directory writes change its timestamps normally.
Compressed/protected files, wider permissions and failure order remain open.

Standalone file symlinks resolve to the physical target before reading, deriving
the default identifier, displaying the executable path or writing. Relative,
absolute and chained aliases are preserved. Resolution precedes lexical path
cleanup: `link/../tool` selects the physical parent, leaving the lexical neighbour
unchanged. Mach-O writes replace that physical target and detach its hard links;
DMG writes retain the target inode. `Report.Path` identifies the absolute resolved
standalone file. Broken and looping links fail before writes. Bundle directory
aliases and resource links retain the separate [bundle policy](bundles.md).

Re-signing copies the original Mach-O slice before writing the new signature,
matching Apple's allocation behavior. Existing bytes after the new SuperBlob
remain within the new allocation; newly allocated bytes start at zero.

Preparation failures and cancellation before commit leave the selected file and its neighbours
unchanged. Concurrent filesystem mutation and crash-durable transactions are
not supported; sign a copy if rollback is required.

## Evidence

`make research-writer` extracts nine complete Apple methods: `MachOEditor::commit`,
its destructor, and seven BundleDiskRep metadata/component/removal/flush methods,
with Clang for arm64 and x86_64. The [record](../spec/apple-writer.json)
pins the Apple source, SDK headers and complete excerpts, and names every private
interface shim. It records metadata copying before rename and temporary-file
cleanup. It also parses the complete `copyfile_stat` function on both targets,
using a pinned private flag header and internal flag enum. Its state carrier and
two helper interfaces are explicit declaration-only shims. This is source analysis,
not execution of Apple's source.

The directory follow-up adds 40 cases over eight layouts/selections and five
operations, with complete native tree comparisons and checks for copied modes,
existing-directory identity and dry-run absence. Eight macOS security profiles
record owner/group, BSD flags, raw times, xattrs, directory ACLs and subsequent
envelope inheritance. They assert the explicit-source-ACL difference rather than
claiming full security parity. Unit tests cover held roots with pathname decoys,
cancellation, metadata failure before executable commit and staging cleanup.
The existing 606-import/88-removal gate remains unchanged; these new metadata
observations do not represent additional foreign artifacts or completed three-OS
codesign evidence until the released dependency is pinned and CI passes.

Bundle acceptance adds 126 comparisons across seven layouts, three architectures
and six operations, including nested helpers/apps, external executable/envelope
links, new envelopes, unsigned removal and dry runs. macOS compares complete
trees with Apple and performs strict deep verification. Each foreign producer
exports 84 signed archives for independent native verification. Fifteen native
metadata profiles retain raw stat observations and ACL/xattr/flag results,
including the differences above. Failure tests cover preparation before envelope
creation, cancellation, changed target identity, partial commits and cleanup.

The signature cleanup matrix adds 105 complete tree comparisons: seven layouts,
three architectures and five operations. It includes named and unknown stale
files, hidden files, external hard links, deep signing and outer-only removal.
Each foreign producer exports another 42 cleaned signed archives; independent
Apple import verification now requires 606 signed artifacts in total. Eight
directory/symlink profiles record the non-regular rejection difference explicitly.
Unit tests cover flush failure after executable commit, later staged-file cleanup,
cancellation, directory replacement by a symlink, retained internal write-alias
rejection, and unchanged verification policy.

Host acceptance compares all output bytes and inode outcomes for fifteen
architecture/operation combinations, plus one in-place DMG case. Six newly
signed outputs also pass Apple's strict verifier. These tests execute on every
CI producer; Apple comparisons execute on macOS. A cancellation test proves
that both original hard links and bytes survive cancellation after staging,
with no temporary directory left behind.

Standalone alias acceptance runs 150 Mach-O architecture/path/identifier/operation
cases, ten signing/re-signing DMG cases and 350 complete display comparisons.
It checks symlink text, physical-target inodes, modes, hard-link neighbours,
lexical neighbours, dry runs and temporary-file cleanup. Nine additional native
comparisons cover shorter/equal-allocation/longer identifiers with nonzero input
padding. Broken and looping aliases fail all four CLI operations without writes;
unit tests cover report paths, cancellation, already-signed and malformed inputs.
These cases run on each producer; byte/display comparisons with Apple run on macOS.
The [path AST record](../spec/apple-paths.json) covers five complete CLI and
SingleDiskRep functions on both targets, including `realpath` before code creation.

The dependency's tests check xattrs, ownership, modes, Darwin ACLs/flags/birth
time, inherited directory ACLs, Linux POSIX ACLs, and Windows streams/security
descriptors. The shared API's cross-platform evidence is recorded in
[merged APFS PR #100](https://github.com/deploymenttheory/go-apfs-v2/pull/100) and
[root-relative PR #102](https://github.com/deploymenttheory/go-apfs-v2/pull/102);
a local compile is not treated as Windows or Linux execution evidence.
