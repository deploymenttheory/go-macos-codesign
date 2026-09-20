# Native signature-removal fixtures

These 44 Mach-O outputs are produced only by `/usr/bin/codesign
--remove-signature`. Inputs are reconstructed from the existing pinned native
fixtures and explicit mutations in `acceptance/removal_test.go`. The manifest
records every input/output hash, the host build and the native tool hash.

The corpus covers arm64, x86_64 and universal executables, dylibs and MH_BUNDLEs;
ad-hoc, runtime and RSA/P-256/P-384/P-521 signatures; already-unsigned images;
symbol string-table padding boundaries, nonzero padding and meaningful zero
bytes inside the table; virtual-size preservation; one/seven trailing bytes;
universal alignment and mixed signed/unsigned slices. Dylinker/kext cases are
file-type mutations, not compiled examples of working loaders or kernel code.
Mutated signatures are removal inputs, not claimed valid signatures.

Record on a Mac into a directory containing only this README:

```sh
MACOSCODESIGN_RECORD_REMOVAL=1 CGO_ENABLED=0 go test ./acceptance -run '^TestRecordAppleRemovalFixtures$' -count=1 -v
```

Every OS reproduces the recorded bytes with the production CLI. Mac acceptance
also repeats the live native comparisons. Linux and Windows export all 44
results for a further 88 native byte comparisons in the Mac CI job.
