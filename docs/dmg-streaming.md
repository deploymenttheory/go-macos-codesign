# Streaming disk-image signing

Path-based DMG signing hashes the payload through a held file descriptor and
writes the new signature and UDIF trailer at the end of that payload. It supports
first signing, force re-signing and the existing ad-hoc dry-run behavior without
loading or copying the image payload. These operations use the same Go path on
Linux, macOS and Windows.

The byte API and file API share signature policy and CodeDirectory construction.
The file path uses bounded range hashes; `SignBytes` retains its caller ownership,
complete returned byte slice and existing 1 GiB output bound. Above `UINT32_MAX`,
the builder selects at least CodeDirectory version `0x20300`, writes the saturated
32-bit limit and records the actual length in the 64-bit field.

## Writes and failures

All parsing, hashing, identity and timestamp work completes before writing.
The held source's size and modification time are checked after planning and
again after opening the destination. The destination must still identify the
same regular file. These checks detect ordinary changes; they do not provide
a snapshot or prevent changes after the last check.

The writer leaves the payload alone, writes the signature followed by its
trailer, truncates to the new end and syncs. It preserves the inode and its hard
links. This follows the complete Apple `DiskImageRep::Writer::flush` body already
captured in [the DMG AST evidence](../spec/apple-dmg.json). Failures or cancellation
before writing preserve bytes. A write/truncate/sync failure can leave a partial
tail in place; there is no rollback promise. Close failures are retained.

Ad-hoc dry runs write the native unsigned signature components and trailer. The
existing safe error for certificate-signed dry runs remains an explicit parity
gap because the qualified native profile terminates abnormally. Embedded DMG
signature removal remains outside the supported native removal profile.

## Evidence and qualification

The [large-file native corpus](../testdata/research/large-source.json) now captures
first-sign, identical force re-sign and dry-run tails at one byte below, at and
above 1, 2 and 4 GiB. It retains real native signatures, trailers and source hashes.
The native CI job regenerates every case; expected bytes are not produced by Go.
The [builder AST capture](../spec/apple-dmg-builder.json) compiles complete verbatim
`fixedSize`, `size` and `build` bodies for arm64 and x86_64. Surrounding declarations
are explicit shims, not runtime execution or serialized-layout evidence.

[Portable acceptance](../acceptance/dmg_source_test.go) signs, force re-signs,
dry-runs and recovers all nine real files. It compares complete tails with native
bytes, checks hard-link identity and requires strict verification. Existing sparse
fixture setup and the 30-second command deadline remain unchanged. Each Linux and
Windows producer exports nine actual signature tails with the pinned payload
recipe; macOS reconstructs all eighteen images and independently verifies their
entire logical payloads with native codesign. Existing populated DMG, hdiutil,
mounted-image, metadata, foreign signature and exact case gates remain required.

The [unit tests](../pkg/codesign/dmg_source_test.go) cover 64-bit offsets, no payload
writes, short writes, disk-full errors, truncate/sync failures, cancellation at
every observed signing checkpoint, source changes, target identity and format
representability. The real 4 GiB + 1-byte signing control allocated **81,128 Go
bytes** locally. It retains an 8 MiB total-allocation regression limit for this
small-metadata case; this is not RSS or a general memory guarantee.

## Remaining work

Signature metadata is still materialized and bounded by the legacy metadata
ceiling. Many small code pages can therefore require substantial memory. Shared
128 MiB accounting, spilling, metadata ownership and process-memory measurements
remain Phase 02 work. Large certificate/page/entitlement combinations, populated
multi-gigabyte images and further native failure qualification also remain open.
Mach-O and bundle mutation still use whole-file plans. This integration does not
complete Phase 02 or qualify every DMG profile.

APFS v0.17.2 supplies the UDIF model. The released SDK needs no new filesystem
primitive for this in-place tail write; codesign owns signature construction and
operation ordering. Image codecs, resource forks and replacement metadata remain
upstream responsibilities.
