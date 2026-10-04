# Streaming bundle operations

Bundle signing, force re-signing, dry runs, inspection, verification and removal
read executable ranges from held files on Linux, macOS and Windows. Nested apps,
plain helpers and supported frameworks use the same pipeline. Resource payloads
are hashed incrementally. The former 1 GiB executable, aggregate-input and
aggregate-output ceilings no longer apply to these path operations.

## Ownership and write ordering

Each bundle owns a registry of executable descriptors. Discovery, signature
inspection, page hashing and output plans borrow those descriptors instead of
retaining complete executable byte slices. A repeated lookup checks the rooted
directory entry, file identity, size and modification time. Resource hashing
reads the known size plus at most one byte to detect growth, verifies the byte
count and rechecks identity and content metadata. Resources close individually;
executable handles remain available for nested seals and output transfer.
Resource identity rechecks use APFS's content-only reader, preserving Windows
signing when data access is allowed but unrelated ACL or EA reads are denied.

Output plans reuse the standalone Mach-O implementation. Parent envelopes seal
the planned child signatures; dry runs continue to seal unchanged on-disk child
signatures. Preparing every executable still precedes committing envelopes and
executables. Existing permission-failure handling, independent sibling commits,
ancestor suppression, stale-signature cleanup and in-place envelope writes retain
their order and their existing acceptance cases.

Released APFS v0.17.1 supplies rooted replacement staging and metadata restoration.
Codesign checks a borrowed executable before and after transfer, releases its
read handle before rename, and retains the SDK metadata source until restoration.
The prepared source is checked again before commit. Failure and cancellation
discard staging; already committed siblings remain committed where native policy
requires it. Close failures propagate to callers, and a failed final source check
cannot leave a verification report marked valid.

These checks detect ordinary replacement, truncation, growth and modification.
They do not create snapshots, stop concurrent writers, detect a same-size edit
whose timestamp is restored, or eliminate races after the last check. Entry,
depth, nested-code, parser and resource-envelope bounds remain in place. Checked
64-bit byte accounting replaces the obsolete aggregate payload ceiling; it is
not memory reservation accounting.

## Native evidence and acceptance

[Three complete Apple resource-hashing bodies](../spec/apple-bundle-streaming.json)
are compiled for arm64 and x86_64 using Clang and the host SDK. Both
`ResourceBuilder::hashFile` overloads and `CodeDirectory::multipleHashFileData`
retain their complete bodies. Private interfaces and the underlying scan helper
are explicitly declared shims. The AST records control flow; independently
executed Apple `codesign` supplies behavioral evidence. Existing writer and
allocation AST evidence remains required.

The [native bundle corpus](../testdata/research/large-bundles.json) contains ten
controls with reproducible file prefixes, logical lengths and populated regions:

- Main executables one byte below, at and above 1 GiB.
- Populated resources one byte below, at and above 4 GiB.
- A nested app and a plain helper whose executable exceeds 1 GiB.
- A containment tree exceeding 4 GiB in aggregate, with two large executables
  and two large resources.
- A flat universal framework exceeding 2 GiB. Its plist executable differs from
  the framework directory name, which Apple accepts and the portable path now
  supports. Versioned framework alias/discovery limitations remain separate.

Each control executes sign, deep strict verification, force re-sign, dry run and
outer removal. Every resulting file is compared by complete SHA-256 and length;
diagnostics, exits and the outer executable's external hard-link effects are
also checked. The ordinary metadata and partial-failure matrices remain intact.
Windows explicitly marks sparse fixtures; all logical bytes are still read,
hashed and transferred. Populated regions cross transport/page boundaries, but
these fixtures are not densely populated multi-gigabyte benchmarks.

All ten signed bundle trees per producer are exported as complete tar/gzip
streams. A separate macOS CI job validates both producer manifests, reconstructs
all twenty bundles, compares every member with native hashes, and runs Apple deep
strict verification. It adds runner capacity without changing the existing
foreign-signature corpus or its timeout. Native recapture and every OS's existing
coverage, race, fuzz, manifest and GoReleaser requirements remain enforced.

```sh
go run scripts/extract-bundle-streaming.go -check -out artifacts/apple-bundle-streaming.json
go run scripts/probe-large-bundles.go -check -out artifacts/large-bundles.json
go test -count=1 -run '^TestLargeBundleStreaming$' ./acceptance
```

## Remaining work

Signature metadata, load commands, plists, envelopes and reports are still
materialized. Shared 128 MiB reservation accounting, metadata spilling, temporary
storage limits, nested/concurrent budgeting and whole-process memory measurements
remain outstanding. Native Mach-O representability limits still apply to each
executable; large resources do not inherit those limits. Dense payload scaling,
broader operation policy and lifecycle qualification remain in
[Phase 02](implementation_plan.md#phase-02). This increment does not establish
complete bundle or `codesign` parity.
