# DMG integration with go-apfs-v2

DMG support will directly use `github.com/deploymenttheory/go-apfs-v2/pkg/disk`.
The app-bundle phase does not yet sign disk images, but the existing APFS project
provides the UDIF format implementation needed for that work. There is no reason
to duplicate its DMG reader, writer or compression support in this repository.

## Reviewed API

The local checkout at revision
`a4b437d9dd8e62e3781004edc44be462793c883e` exposes:

| API | Use in the signing integration |
| --- | --- |
| `disk.DMGFooter` | Existing 512-byte UDIF trailer model, including `CodeSignatureOffset` and `CodeSignatureLength` |
| `disk.EncodeUDIF` and `disk.SourceBlock` | Deterministic image construction for portable test fixtures |
| `disk.WrapRawImageDMGFrom` | Stream a raw image into a DMG without loading the whole filesystem into memory |
| `disk.OpenDMG` | Read/decompress APFS image contents for independent content-preservation checks where applicable |

The existing reader and writer decode/encode `DMGFooter` with `encoding/binary`
in big-endian order. The reader's `readFooter` method and its footer instance are
private, but the exported type is sufficient for a signature-specific adapter.
`OpenDMG` locates an APFS partition, so it should not gate signing of an otherwise
supported UDIF containing a different filesystem. Signing operates on the
existing image bytes and its exported footer model.

## Work in this repository

1. Pin the APFS dependency when the adapter lands and reuse `disk.DMGFooter`.
   Add signature-specific bounds and overlap validation around the existing
   format model. Preserve compressed payloads and metadata bytes.
2. Establish Apple's DMG CodeDirectory coverage, trailer binding, signature
   placement and replacement/removal behavior using pinned source/Clang
   extraction and native fixtures. Reuse this project's SuperBlob, requirements,
   CMS, certificate-chain and timestamp implementations for those signatures.
3. Generate portable images using the existing APFS encoders, with native
   `hdiutil` images as independent fixtures. Prove signing, verification,
   tamper rejection, replacement and removal against host `codesign`; require
   exact bytes for deterministic cases and explicit invariants otherwise.
4. Run the dependency guard, per-package coverage gate and real three-OS CI.
   Send Linux/Windows-signed DMGs to the Mac verifier, as for Mach-O/app outputs.

The local `pkg/disk` dependency graph was checked with `CGO_ENABLED=0` for Linux,
Darwin and Windows arm64. It contained no CGO files, `crypto/x509`, `crypto/tls`,
`net/http`, `os/exec` or `purego` imports. This audit supports direct reuse;
it does not establish DMG signature parity before implementation and acceptance.
Recheck the resolved graph on the eventual integration commit.
