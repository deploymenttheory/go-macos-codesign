# DMG signing with go-apfs-v2

DMG signing directly uses `github.com/deploymenttheory/go-apfs-v2/pkg/disk`, pinned
to `v0.3.1-0.20260916040812-a4b437d9dd8e`. Production reuses its exported
`DMGFooter`, including the signature offset/length fields. This repository adds
the signature adapter; it does not maintain another DMG reader, writer or codec.

## CLI and library

```sh
macoscodesign -s - -i org.example.image --timestamp=none ./Example.dmg
macoscodesign --verify ./Example.dmg
macoscodesign -dvvvv ./Example.dmg

macoscodesign -fs identity.p12 --password-file password.txt --timestamp ./Example.dmg
macoscodesign --verify --trust-root code-root.pem --timestamp-root apple ./Example.dmg
```

`Sign`, `Inspect`, `Verify` and their byte counterparts recognize the trailing
UDIF footer. A Mach-O header takes precedence, matching Apple's format detection.
Inspection reports `Format="disk image"` and one signature entry
named `dmg`; that is a format name, not a CPU architecture. Signing reuses the
requirements, CMS, certificate-chain and timestamp implementations. Trust remains
explicit; see [certificates](certificates.md) and [timestamps](timestamps.md).

Without an explicit identifier, path signing follows the tested native basename,
extension and numeric-suffix rules. Ad-hoc identifiers without a dot also include
the SHA-1 of the canonical footer. That is Apple's naming convention; signature
hashes use SHA-256. The byte API still requires an explicit identifier.

## Signed representation

Compressed data and resource-plist bytes remain unchanged. Signing appends an
embedded SuperBlob before the 512-byte footer and updates its signature fields.
The CodeDirectory covers every byte before the signature. Special slot 6 binds
the complete footer with signature length zeroed and signature offset set.
Verification requires that binding, payload integrity and applicable trust.

The default hash covers one unpaged payload block. Explicit power-of-two page
sizes from 2 bytes to 1 GiB are supported. The writer selects the native minimum
CodeDirectory version for Team ID/runtime fields and stores the actual CMS size
without Mach-O allocation padding. Runtime metadata, supported requirements and
forced library entitlements use the shared options. Entitlements are omitted by
default for images, matching the tested native behavior.

`--force` replaces an existing signature. Dry runs and construction failures,
including timestamp errors, preserve input bytes. Writes retain the inode and
are not atomic: I/O failures can leave partial output, and concurrent modification
is unsupported. Apple rejects `--remove-signature` for signed and unsigned DMGs
on the baseline. The Go CLI/removal APIs likewise return unsupported and preserve
the image; removal is not claimed as a native DMG feature.

## Evidence

- `make research-dmg` extracts five complete Apple methods through Clang on both
  architectures: trailer reading/setup, signing limit, writing and identifiers.
  [The record](../spec/apple-dmg.json) pins sources/excerpts and identifies shims.
  Wire representation comes from the APFS library, not the shim layout.
- Forty native ad-hoc cases cover five input profiles and eight option
  combinations, requiring complete byte equality, native strict verification
  and all five display levels.
- Fifteen portable ad-hoc/RSA/P-256 cases preserve payload bytes and pass both
  native `codesign --verify --strict` and `hdiutil verify`. Five committed
  [Apple fixtures](../testdata/dmg/README.md) run on every OS. Ad-hoc and
  matched-time RSA outputs are byte-identical; ECDSA compares CodeDirectories
  and verifies its randomized signatures.
- An independent loopback TSA tests online signing and failure preservation.
  A live run obtained an Apple timestamp on the APFS fixture at **2026-09-19
  21:31:11 UTC**, followed by native strict verification.
- CI exports fifteen DMGs per Linux/Windows producer. The downstream Mac
  requires signature and image-checksum verification of all thirty within the
  96-artifact matrix. [Progress](progress.md) distinguishes measured runs from
  configured checks.

Repeat the opt-in live check with:

```sh
MACOSCODESIGN_LIVE_TIMESTAMP=1 MACOSCODESIGN_REQUIRE_APPLE=1 \
  MACOSCODESIGN_EVIDENCE_DIR="$PWD/artifacts/dmg-live" CGO_ENABLED=0 \
  go test ./acceptance -run '^TestDMGLiveAppleTimestamp$' -count=1 -v
```

## Limits and encoder observation

The profile is single-segment UDIF v4, with a 512-byte footer, flags equal to 1,
a resource plist and non-overlapping data/resource/plist ranges. The in-memory
limit is 1 GiB, including output. Encrypted/segmented representations, detached
signatures, alternate digest writing, large-image streaming, stapled-ticket and
notarization policy, and full option/diagnostic parity remain incomplete.
External Info.plist/resource overrides are rejected. Production does not mount
or decompress the image; a valid signature does not prove filesystem mountability.
Native acceptance checks image checksums separately with `hdiutil`.

The pinned APFS encoder produced a small synthetic LZMA image that failed
`hdiutil` **before signing** on macOS 27 build 26A428: error 1000, calculated CRC32
zero. Its existing native LZMA fixture passes and is used for interoperability.
The unsigned reproducer is retained:

```sh
go run scripts/repro-apfs-lzma.go artifacts/unsigned-lzma-repro.dmg
hdiutil verify artifacts/unsigned-lzma-repro.dmg
```

The generator refuses to overwrite output. This single case does not establish
that every LZMA input fails. Further encoder investigation belongs in
`go-apfs-v2`; no APFS source files were modified by this signing phase.
