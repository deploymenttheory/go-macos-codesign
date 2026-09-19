# Native Apple certificate fixtures

These twelve executables were signed by `/usr/bin/codesign` on the Mac recorded
in each adjacent JSON provenance file, using this repository's deliberately
public test identities. They originate from `testdata/macho/unsigned-*`.
Normal tests never rewrite them. SHA-256 hashes are checked by the dependency
guard and portable tests.

To explicitly regenerate on a Mac, set `MACOSCODESIGN_NATIVE_EXPORT_DIR` to the
absolute path of this directory, then run:

```sh
go test -count=1 ./acceptance -run '^TestAppleNativeCertificateLayout$'
```

The harness imports only public test keys into disposable keychains and deletes
those keychains on cleanup. It neither adds trust settings nor imports into the
user's existing keychains. GoReleaser remains the product build/packaging tool;
this test command is development-only fixture generation and validation.

The host matrix also exercises runtime flags, entitlements, explicit requirements,
and sixteen identifier lengths. Only the twelve default cases are exported.
Native signing times are supplied to the Go signer for comparisons. RSA slices
must match in full, including CMS and padding. For ECDSA, layout, CodeDirectories,
requirements, other non-CMS blobs, authenticated attributes, and algorithm
identifiers match; randomized signature bytes differ. Both implementations verify
every signature.
