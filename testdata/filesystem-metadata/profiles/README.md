These are retained native observations from PR107's macOS 15 and 26 CI jobs,
not regenerated expectations. Each JSON contains the original native result
(status, diagnostic, complete bundle tar and root carrier), native seed
provenance, tested commit, CI run and hashes of the downloaded artifact and test
transcript. The seed source/module hashes describe that historical capture;
they must not be replaced with current working-tree hashes.

The six cases per OS are the four successful root/resource stripping cases and
the two competing resource/nested-code failures. They were extracted from the
`native` member of the job's `ATTEST` records. The two accompanying ASTs per OS
are copied unchanged from that job. They qualify the seed producer's actual SDK
calls, not Apple's private signing implementation.

`TestSigningProfileNativeArchives` replays all eight successful native signatures
on every host and compares every byte, including reserved zeros and the load
commands/page hashes affected by allocation. macOS 15 uses 4 KiB default ARM64
signing pages; macOS 26 uses 16 KiB. Both retain the 18,000-byte CMS blob budget
for ad-hoc signing. The macOS 27 baseline omits that extra ad-hoc reservation.

`TestNativeSigningProfiles` extends live comparison on macOS 15/26/27 to both
architectures, sixteen identifier lengths and default/4 KiB/16 KiB pages.
`TestNativeSigningProfileResourceOrder` repeats default and serial native signing
on FAT/exFAT to qualify the competing-error behavior separately from scheduling.
The ordinary filesystem suite continues to compare full CLI outcomes unchanged.

Source references used to interpret the observations:

- [CodeSigner.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/CodeSigner.cpp): CMS budget defaults to 18,000 bytes.
- [signer.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/signer.cpp): allocation sizing and resource preflight inside resource processing.
- [csutilities.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/csutilities.cpp) and [dispatch.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_utilities/lib/dispatch.cpp): storage-dependent scheduling and exception propagation. These sources do not establish deterministic precedence between concurrent failures. The repeated native probes remain required.
