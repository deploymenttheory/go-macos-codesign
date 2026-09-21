# File replacement and metadata

Standalone and bundle Mach-O signing, re-signing and signature removal prepare a new file,
restore its metadata, sync and close it, and rename it over the selected name.
Other hard-link names retain the original inode and bytes. Removing a signature
from an unsigned Mach-O also replaces the inode. Dry runs preserve all names.

The filesystem implementation belongs to
[`go-apfs-v2/pkg/hostmeta` in v0.8.0](https://github.com/deploymenttheory/go-apfs-v2/tree/v0.8.0/pkg/hostmeta).
Standalone writes call its `PrepareReplacement` and `RestoreMetadata` APIs.
Bundle writes use the root-relative `PrepareReplacementAt` API delivered in
[APFS PR #102](https://github.com/deploymenttheory/go-apfs-v2/pull/102) and released
in v0.5.0; this module now pins v0.8.0. Codesign owns the signing-specific decision
to rename. It has no copied platform metadata writer.
The existing `go-apfs-v2/pkg/disk` dependency continues to own the UDIF model.

`CopyDirectoryStat` comes from [merged APFS PR #104](https://github.com/deploymenttheory/go-apfs-v2/pull/104),
released in [v0.6.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.6.0).
The directory-stat implementation uses the published module directly. Its
[final CI](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/35562856598)
passed three-OS execution and all six CGO-disabled builds.

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
Preparation and cancellation failures before commit preserve original names and
contents and clean staging directories; executable reads can refresh access time.
Commits proceed descendant-first, with each
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

Stale directories and symlinks inside `_CodeSignature` are excluded from resource
seals and rejected during cleanup after the executable commits, matching the
native failure boundary. Cleanup follows the pinned case-insensitive APFS order
for supported ASCII names on every host: 22-bit name hash, then case-folded name
comparison on collisions. It stops at the first non-regular entry. CodeResources
participates in that order during removal; an earlier failure can retain it.
Signing keeps the newly written envelope. Dry-run signing succeeds without changing stale entries;
verification still rejects unexpected entries. Directory metadata is walked only
for the existing bounded path and internal hard-link checks; file contents are not
read and symlinks are never followed. Empty/populated directories and relative
internal, dangling and outside symlinks have independent native coverage.
Cleanup failure retains earlier executable/envelope commits, removes remaining
staging files, and stops later commits, including the parent after a child fails.

Removal also defers rejection of a directory or symlink named CodeResources until
cleanup, after replacing the main executable. During signing, a directory named
CodeResources fails when its envelope write is attempted, before that bundle's
main executable commits. Earlier child commits survive; later commits stop.
Dry runs do not attempt the write and retain the directory. Signing and removal
do not read old child envelopes: signing constructs a replacement or seals the
existing child executable, and outer removal preserves child signatures. On
POSIX hosts, a write-only envelope can therefore be rewritten, while a read-only
envelope fails at its write. Existing envelope modes and inodes are retained.
Verification still reads and validates the envelopes it needs.

Signing still rejects symlinked envelopes before writes. Native probes can follow
those links and mutate their targets before cleanup fails; this implementation
retains its no-follow and containment boundary. Special files, invalid names, unreadable
subtrees and internal write aliases can still fail before mutation. Case-sensitive
APFS and other filesystem orders, broader permission failures and raw diagnostics
remain different or unverified. Nothing recursively
deletes directories or unlinks the rejected symlinks.

Hashing and collision comparison use `go-apfs-v2/pkg/apfs`. Codesign PR #34 merged
with v0.6.0 still pinned. Merged [PR #35](https://github.com/deploymenttheory/go-macos-codesign/pull/35) consumes
[v0.6.1](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.6.1), which
fixes the API's concurrent first-use initialization through
[APFS PR #106](https://github.com/deploymenttheory/go-apfs-v2/pull/106), released by
[PR #107](https://github.com/deploymenttheory/go-apfs-v2/pull/107). Hash values and
public signatures are unchanged. PR #35 passed its own final codesign CI and
artifact audit with v0.6.1; its actual merge matches the audited source tree.
The [implementation plan](implementation_plan.md#merged-pr35) records the final
workflow and artifact evidence. No copied hashing implementation or local
dependency replacement is committed.

The bundle writer does not reproduce every native metadata side effect.
Native probes show Apple can add inherited executable-directory ACL entries;
our replacement preserves the original ACL. Creation-time updates use the explicit
`SetCreationTime` API from [merged APFS PR #108](https://github.com/deploymenttheory/go-apfs-v2/pull/108),
first released in [v0.7.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.7.0).
The released creation-time implementation matches the tested upstream API.

On Darwin, rewritten bundle executables receive a new creation time capped by an
earlier source modification time, matching native APFS observations. The timestamp
is selected before staging and applied only to the private replacement. Dry runs,
untouched descendants during outer removal, and existing envelope creation times
remain unchanged. Linux/Windows retain their existing replacement metadata policy;
the shared setter reports unsupported there. Standalone replacement still preserves
its source creation time. Exact wall-clock timestamps differ between independent
runs; tests assert the operation interval or exact source modification time.
Executable ACL inheritance remains outside this profile.
Mode, owner/group, the tested xattr and supported flags survive both writers.

Access-time recording uses `RecordReadAccess` from
[merged APFS PR #110](https://github.com/deploymenttheory/go-apfs-v2/pull/110),
released and pinned as [v0.8.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.8.0).
The published metadata implementation matches the tested upstream API. No APFS
module replacement or development workspace is required.

On Darwin, signing and re-signing record access on each successfully read bundle
executable, including nested code. Outer removal records access only on the main
executable. Dry-run signing records the same source reads without replacing files.
Source hard links observe that read-access time while retaining their bytes,
modification time and creation time. Each private replacement records a later
access time before commit. The source read stays bounded and identity-checked;
rejected oversized reads do not call the access recorder.

Ordinary reads on the tested APFS volume leave access time unchanged. APFS records
access through a one-byte, read-only private mapping of the held descriptor, then
unmaps it without reading mapped memory. This also works for empty files and
read-only files whose ACL denies attribute writes. The filesystem supplies the
timestamp; the API does not set one or change unrelated metadata. Other hosts
report unsupported and retain their existing read/replacement policy.
Standalone Mach-O signing, re-signing, signed/unsigned removal and signed/unsigned
dry runs also record the bounded source read. Replacements record a later access
before commit; aliases select the physical file, leaving alias text and lexical
decoys unchanged. Display and verification preserve standalone and bundle
executable access times. Supported DMG operations retain ordinary reads and do not
record mapped access. Native DMG dry runs modify bytes and modification time in
place; Go preserves both. This difference remains open and is asserted separately
from access-time equality. Envelope/resource access times, failed or shallow Mach-O
signing and broader filesystem/permission profiles remain outside this claim.

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

Preparation failures and cancellation before commit preserve the selected file's
and its neighbours' names, bytes and write timestamps; reads may refresh access
time. Concurrent filesystem mutation and crash-durable transactions are
not supported; sign a copy if rollback is required.

## Evidence

`make research-writer` extracts ten complete Apple methods: `SecCodeSigner::Signer::remove`,
`MachOEditor::commit`, its destructor, and seven BundleDiskRep metadata/component/removal/flush methods,
with Clang for arm64 and x86_64. The [record](../spec/apple-writer.json)
pins the Apple source, SDK headers and complete excerpts, and names every private
interface shim. It records metadata copying before rename and temporary-file
cleanup. It also parses the complete `copyfile_stat` function on both targets,
using a pinned private flag header and internal flag enum. Its state carrier and
two helper interfaces are explicit declaration-only shims. The complete allocation
`mapFile` function adds Apple's read-only private mapping and three SDK mapping
constants. Its error logger is a declaration-only shim. Both targets now record
twelve complete methods/functions and fifteen constants. This is source analysis,
not execution of Apple's source.
The signer removal method distinguishes the Mach-O allocate/commit path from the
generic writer's canonical-slot removal loop. Mach-O commit flushes directly;
the purge follows directory enumeration, including CodeResources. Private signer,
disk-representation and smart-pointer interfaces are declaration-only shims.

The directory follow-up adds 40 cases over eight layouts/selections and five
operations, with complete native tree comparisons and checks for copied modes,
existing-directory identity and dry-run absence. Eight macOS security profiles
record owner/group, BSD flags, raw times, xattrs, directory ACLs and subsequent
envelope inheritance. They assert the explicit-source-ACL difference rather than
claiming full security parity. Unit tests cover held roots with pathname decoys,
cancellation, metadata failure before executable commit and staging cleanup.
The existing 606-import/88-removal gate remains unchanged; these new metadata
observations do not represent additional foreign artifacts. Codesign three-OS
evidence for this released pin is recorded separately from upstream API testing.

Bundle acceptance adds 126 comparisons across seven layouts, three architectures
and six operations, including nested helpers/apps, external executable/envelope
links, new envelopes, unsigned removal and dry runs. macOS compares complete
trees with Apple and performs strict deep verification. Each foreign producer
exports 84 signed archives for independent native verification. Fifteen native
metadata profiles retain raw stat observations and ACL/xattr/flag results,
including the differences above. Failure tests cover preparation before envelope
creation, cancellation, changed target identity, partial commits and cleanup.

Creation-time acceptance adds 210 macOS comparisons across seven layouts, three
architectures, past/future source modification times and five operations. Each case
compares complete native trees and checks executable/neighbor identity and timestamps;
successful signatures receive native strict deep verification. Permission-denial
and cancellation tests require unchanged originals, no envelope commit and no
staging leaks. Both Clang targets record `ATTR_CMN_CRTIME` and `timespec` size, plus
the complete metadata-copy and commit methods. This Darwin-only corpus adds
metadata observations; the existing portable writer and native-import gates
continue to check Linux/Windows output. Final per-commit CI and artifact evidence
is recorded in the implementation PR.

Access-time acceptance adds 294 macOS comparisons: seven layouts, three
architectures, past/future access times and seven operations (sign, read-only sign,
re-sign, signed/unsigned removal and signed/unsigned-outer dry runs). Unsigned-outer
dry runs retain valid nested signatures. Tests snapshot access times before
reading output bytes or invoking native verification, compare complete trees,
and check source/replacement identity, external-link bytes, untouched descendant
times and dry-run preservation. Rewritten access must follow the original inode's
access; both must fall within the operation. A unit regression enforces read bounds
before access recording. The original writer fails the new access-time regression.
These Darwin metadata cases add no foreign import archives. Final per-commit
validation with the released dependency is recorded in the implementation PR.

Standalone access-time acceptance adds 216 Mach-O comparisons: three architectures,
four operand forms (direct, relative alias, chain and parent alias), past/future
access times and nine operations, including mode 0551 inputs and read-only
controls. Both source and replacement access must fall within the operation, with
replacement access later. The matrix checks hard-link bytes and identity, mode and
ownership, alias text, lexical decoys, output byte equality and native strict
verification. A sparse oversized-file regression rejects the read before mapping;
ordinary reads preserve metadata. The merged implementation fails the new
standalone signing regression.

Another 168 comparisons cover bundle display, verbose display, verification and
deep verification across seven layouts, three architectures and both timestamp
profiles. All executable stat metadata and tree bytes remain unchanged. Eighty DMG
comparisons cover five formats, both timestamp profiles and eight operations.
All retain access time; 60 also match bytes, while 20 signed/unsigned dry-run cases
assert the known native in-place write difference. Raw command results and each
side's hashes remain in the attestations. These cases add no foreign import archives.

The signature cleanup matrix adds 105 complete tree comparisons: seven layouts,
three architectures and five operations. It includes named and unknown stale
files, hidden files, external hard links, deep signing and outer-only removal.
Each foreign producer exports another 42 cleaned signed archives; independent
Apple import verification now requires 606 signed artifacts in total. Eight
directory/symlink profiles were the starting evidence for the failure-order change.
The expanded corpus now compares 210 complete trees across seven layouts, five
stale entry types and six operations on arm64, plus four nested child-failure/dry-run
cases. It records raw output/status, before/after hashes, replacement identity and
external-neighbour preservation. The regular writer corpus retains all three
architectures. Failed operations do not add signed import artifacts; the existing
606-import/88-removal gate remains in place.
Unit tests cover flush failure after executable commit, later staged-file cleanup,
cancellation, directory replacement by a symlink, retained internal write-alias
rejection, and unchanged verification policy.

The ordered-cleanup matrix adds 278 independent native tree comparisons on arm64.
The app cases put each of twenty names at the failure boundary, covering all named
components, a name before CodeResources, two hash-collision pairs, opposite
creation orders, signed/unsigned removal, re-signing, dry runs and verification.
Six other layouts cover representative boundaries for removal and re-signing.
Directory contents, symlink targets and external executable links remain intact;
each record includes raw status/output, survivor names, identity and tree hashes.
Unit tests cover the bounded directory snapshot and cancellation after an unlink.
These failures add no signed imports; the existing 606/88 gate remains unchanged.

The signing-envelope matrix adds 84 complete native comparisons on arm64 across
seven layouts, empty/populated envelope directories and six operations, including
signed/unsigned dry runs, force policy and verification. Another 20 nested cases
cover parent/child failure order, shallow signing and outer-only removal. Twenty
POSIX permission cases compare read-only and write-only envelopes at the parent
and child boundaries. The permission cases run on Linux/macOS and explicitly skip
Windows, whose access controls are not modeled by POSIX mode bits; hosts that
bypass the requested denial also skip instead of counting a pass. The records
include complete trees, raw outputs/status, inode effects and external-neighbour
preservation. Successful deep writes also pass native strict deep verification.
The existing 606 signed-import/88 removal gate remains unchanged; these cases
extend filesystem observations and tree comparisons, not foreign archive counts.
Unit checks retain internal alias rejection beneath envelope directories,
symlink-target preservation, staging cleanup and strict deep verification.

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
