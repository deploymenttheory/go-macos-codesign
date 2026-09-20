# File replacement and metadata

Standalone Mach-O signing, re-signing and signature removal prepare a new file,
restore its metadata, sync and close it, and rename it over the selected name.
Other hard-link names retain the original inode and bytes. Removing a signature
from an unsigned Mach-O also replaces the inode. Dry runs preserve all names.

The filesystem implementation belongs to
[`go-apfs-v2/pkg/hostmeta`](https://github.com/deploymenttheory/go-apfs-v2/pull/100).
Codesign calls its `PrepareReplacement` and `RestoreMetadata` APIs and owns the
signing-specific decision to rename. It has no copied platform metadata writer.
The existing `go-apfs-v2/pkg/disk` dependency continues to own the UDIF model.

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
claimed. A Windows read-only destination may reject the final rename.

The shared library's older compression-aware attribute reader retains its
existing raw-syscall/fallback implementation. The new replacement API does not
call it. Codesign's own production-source guard rejects direct syscalls.

DMGs retain Apple's in-place write behavior: both hard-link names observe the
new signature. Bundle executable/envelope writes also remain in place; internal
hard links are rejected by the bundle scan, but external links retain shared
inode behavior. These writes can leave partial output on an I/O failure.

Raw standalone symlink write targets remain unsupported. Preparation failures
and cancellation before commit leave the selected file and its neighbours
unchanged. Concurrent filesystem mutation and crash-durable transactions are
not supported; sign a copy if rollback is required.

## Evidence

`make research-writer` extracts complete Apple `MachOEditor::commit` and destructor
bodies with Clang for arm64 and x86_64. The [record](../spec/apple-writer.json)
pins the Apple source, SDK headers and complete excerpts, and names every private
interface shim. It records metadata copying before rename and temporary-file
cleanup. This is source analysis, not execution of Apple's source.

Host acceptance compares all output bytes and inode outcomes for fifteen
architecture/operation combinations, plus one in-place DMG case. Six newly
signed outputs also pass Apple's strict verifier. These tests execute on every
CI producer; Apple comparisons execute on macOS. A cancellation test proves
that both original hard links and bytes survive cancellation after staging,
with no temporary directory left behind.

The dependency's tests check xattrs, ownership, modes, Darwin ACLs/flags/birth
time, inherited directory ACLs, Linux POSIX ACLs, and Windows streams/security
descriptors. Cross-platform CI status is reported in the linked dependency PR;
a local compile is not treated as Windows or Linux execution evidence.
