# Mach-O signature removal

The pure-Go remover now reproduces native removal bytes for the committed
arm64, x86_64 and universal executable, dylib and MH_BUNDLE corpus. This fixes
the eight-byte executable padding discrepancy recorded in the bundle-layout
phase. It also preserves the signed `__LINKEDIT` virtual size instead of
recalculating it as the signing path does.

## Rules and bounds

- Delete `LC_CODE_SIGNATURE`, compact following load commands, and zero the
  vacated header space.
- Truncate at the signature offset. If that lies one to twelve bytes after the
  `LC_SYMTAB` string-table end, truncate to the table end instead. The boundary
  comes from metadata, not from searching for zeros. Meaningful zero bytes
  inside the string table remain intact; nonzero bytes in declared padding are
  removed as Apple does.
- Accept up to seven trailing bytes beyond the signature, matching native
  deallocation. More trailing bytes return an unsupported error without writes.
- Update `__LINKEDIT.filesize` while preserving `vmsize` exactly.
- Repack universal slices on 16 KiB boundaries, including unsigned slices.
  Already-unsigned thin images remain byte-identical.

All offsets and command lengths are bounded before slicing or truncation.
Duplicate/truncated symbol commands, overflowing tables, overlaps with the
signature or header, and a signature before `__LINKEDIT` fail without changing
the input. File replacement happens only after all architectures succeed.
Removal strips the outer bundle's main signature and CodeResources while
preserving descendants, resources, aliases and the empty signature directory.

## Evidence

[The Go research driver](../scripts/extract-removal.go) parses four complete
verbatim functions from pinned Apple `codesign_alloc.cpp`: `get32`, `get64`,
`remove_signature_space` and `code_sign_deallocate`. Real SDK declarations are
used for Mach-O/endian/overflow operations; I/O, logging and VM helper interfaces
are explicit declaration shims. [The two-target AST record](../spec/apple-removal.json)
pins source, excerpts, headers and translation-unit hashes.

The [44 native fixtures](../testdata/removal/README.md) include ad-hoc, runtime,
RSA and three ECDSA curves, unsigned images, padding boundaries, virtual sizes,
trailing bytes and different universal layouts. Every OS uses the compiled CLI
to reproduce these outputs and checks repeated removal. macOS repeats all 44
comparisons against its own `codesign`. Nine additional cases re-sign the removed
executables/dylibs/bundles, require byte equality with Apple, and pass native
strict verification. Eighteen complete bundle trees and three mixed trees are
also compared after removal, without the earlier padding exception.

Linux and Windows export their 44 outputs each. The downstream Mac CI job
independently removes the same input signatures and requires all 88 imported
results to match exactly, alongside the existing 300 signed-artifact checks.

## Remaining limits

These results cover the documented corpus, not every legacy representation or
malformed Mach-O accepted by Apple. The implementation validates symbol ranges
and handles relocated load commands safely; it does not reproduce native
corruption observed with malformed tables or an unusually early signature
command. Big-endian/32-bit and FAT64/swapped universal parsing have portable
unit coverage, but this phase does not establish complete native byte parity for
those forms. Unindexed nonzero inter-slice padding is not preserved by the Go
universal assembler. Dylinker/kext fixture cases mutate file types and do not
claim acceptance of arbitrary real loaders or kernel extensions.

Native-unsupported DMG removal remains unsupported. Detached/generic signatures,
xattrs and exact error text are separate outstanding work. The compatibility
inventory therefore keeps `--remove-signature` partial.
