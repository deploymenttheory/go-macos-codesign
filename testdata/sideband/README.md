# Native sideband metadata fixtures

These 29 snapshots let Linux, Windows and macOS test the same foreign macOS
metadata without restoring it onto their filesystems. They come from native
ad-hoc signed standalone/app fixtures, covering code, bundle roots, ordinary
resources and signature directories. No signing identity or keychain is used.

`policy.json` records raw native xattr values, an APFS-encoded AppleDouble snapshot,
native strict-sideband status and output, host/tool identity, and input/driver
hashes. Only the temporary fixture-root prefix in stdout is replaced by
`$FIXTURE`; raw output remains in `artifacts/sideband/native.json`.
`manifest.json` pins the portable fixture bytes. The unit test additionally checks
the capture driver's hash and its original unsigned executable hash.

Refresh on the reference Mac from the repository root:

```sh
go run scripts/probe-sideband.go -check -fixtures testdata/sideband
go test -count=1 ./internal/sideband
```

Export happens only after all 203 original native policy comparisons, their
before/after preservation assertions, and 406 metadata-adapter comparisons pass.
The 42 directory-fork combinations whose native setup returns EPERM remain
explicitly unexecuted. The portable corpus selects the 29 executable cases of
the strict-sideband policy; it does not count unavailable setups as successful.

The corpus proves the metadata observations and native diagnostic attribute order.
It does not prove complete codesign verification, link traversal, nested/framework
ordering, authorization failure ordering, or signing-time stripping. Those remain
separate obligations in the [integration plan](../../docs/sideband-policy.md).
