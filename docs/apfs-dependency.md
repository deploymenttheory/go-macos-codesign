# APFS v0.14.0 integration gate

The v0.14.0 upgrade compiles and passes codesign's package/internal unit tests,
lint, module verification and GoReleaser configuration validation. It is **not
ready to merge**: `make verify` stops at the existing production dependency guard:

```text
Native dependency for darwin: github.com/ebitengine/purego|
```

CGO being disabled does not satisfy this repository's stricter requirement:
production dependencies must not load native APIs through `purego`. The guard
remains unchanged. Full native acceptance, merged coverage and packaging
qualification have not passed for this dependency upgrade.

## Dependency paths

The published module, not a local replacement, introduces these paths:

- `codesign` → `hostdata` → `purego` for Darwin host adapters.
- `codesign` → `apfs` → `hostdata` → `purego`, because image metadata/security
  types and decoders share the coordinating host package.
- `hostdata` → `hostdata/acl` and `hostdata/sandbox` → `purego` for native capture.

`hostdata/accesstime` is already separate. However, the existing codesign call to
`hostdata.SetCreationTime` reaches `loadDarwinSecurity` and `fsetattrlist` through
the native binding layer in v0.14.0. This is a reachable behavior dependency,
not merely an unused package reference that can be ignored.

Reproduce the audit with CGO disabled:

```sh
make verify
CGO_ENABLED=0 GOOS=darwin go list -deps \
  -f '{{.ImportPath}} {{join .Imports " "}}' ./cmd/macoscodesign
```

## Required upstream correction

The correction belongs in APFS, retaining a single implementation of shared
filesystem behavior. The approved approach is a finite typed Darwin extension
following x/sys's static import/runtime-call pattern, preserving every existing
feature and removing purego entirely. The candidate is being prepared for APFS
v0.15.0 on `fix/remove-native-bindings`, cut from released main.

1. Replace the generic binding machinery with typed wrappers for the signatures
   missing from x/sys. Policy and codec implementation remains Go; Darwin host
   observations still call platform libraries through the approved boundary.
2. Give the replacement, directory-stat and timestamp operations used by
   codesign dependency boundaries that satisfy its existing guard. Retain their
   held-object identity, permissions, timestamp precision, cancellation and
   cleanup behavior on every supported OS. Inspect the creation-time binding
   specifically; an import move alone does not solve it. Do not substitute
   deprecated direct syscalls, copy implementations into codesign, silently
   suppress errors or drop symlink/directory support from the existing SDK API.
3. Keep native capture capabilities available to APFS callers that explicitly
   need them. Introduce no unsupported-host stub or reduced portable logical
   feature. Prove the dependency boundary with three-OS import audits as well
   as runtime tests; CGO-disabled builds alone cannot detect this regression.
4. Retain every APFS strict coverage, native evidence, large-fork, foreign-image
   readback, fuzz and CI gate. Add downstream codesign dependency qualification
   before calling a new APFS release ready for this consumer.
5. After maintainer merge and publication, update package PR72 if it remains open,
   pin the corrected published module here, and rerun the complete codesign
   guards/native/portable/coverage/GoReleaser and artifact audits. Do not qualify
   an external modfile or local replacement as the submitted dependency.

Only after this gate passes can the planned sideband/all/strip policy integration
proceed. No compatibility inventory status is upgraded by the attempted adoption.

## Candidate prerequisite check

The unchanged codesign dependency guard and package/internal unit tests pass
against the APFS candidate using an external temporary modfile. This confirms
that removing purego resolves the observed dependency failure. It does not
qualify the v0.14.0 pin submitted in this PR, replace full acceptance, or authorize
merging before the corrected upstream version has been published and tested.
