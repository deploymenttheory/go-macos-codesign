# Strict verification policy

Verification now checks supported Mach-O layout boundaries by default. Use
`--strict=symlinks` to additionally check sealed resource destinations, and
`--no-strict` or `--strict=none` to disable these additional policies. Signature
integrity, certificate trust, parent requirements and safe parsing remain mandatory.
This is a bounded implementation, not full `codesign --strict` equivalence.

```sh
macoscodesign --verify --strict=symlinks --deep Example.app
macoscodesign --verify --no-strict executable
```

## Selectors and API

`symlinks` accepts native name prefixes (`s`, `symlink`). `none` accepts `n`.
The numeric syntax consumes a C base-0 unsigned prefix, ignores trailing text,
and truncates to 32 bits: `128`, `0x80`, `0200`, `128x`, and `4294967424` select
symlink policy; `0`, `08`, and `0x` select no additional destination policy.
Repeated numeric/name masks accumulate. Numeric zero does not erase earlier bits.
`none` and `--no-strict` disable destination/layout policy even if a later supported
selector adds bits. Invalid names still fail after a disabling option.

The host rejects comma lists and uppercase names with
`invalid strict option - VALUE`. Its behavior differs from the manual's comma-list
wording. Only attached optional arguments are consumed: `--strict=symlinks`.

Plain `--strict`, an empty selector, `all`, `sideband`, their prefixes and numeric
sideband/unknown bits remain explicitly unsupported. This also applies when a
disabling option is present: native sideband traversal has additional ordering
behavior that is not implemented. Strict controls outside verification remain
unsupported. Numeric overflow/unknown API masks are not claimed as native diagnostic
parity. No unsupported policy silently falls back to ordinary verification.

Library callers use `VerifyOptions.StrictSymlinks` and `VerifyOptions.NoStrict`.
Zero-value options now reject additional malformed layouts that previously passed
cryptographic checks. `NoStrict` is the explicit compatibility escape for those
layout extensions, not a bypass for signature validation. Byte-only verification
cannot resolve a supplied resource envelope; `StrictSymlinks` with external resource
bytes returns `ErrUnsupported` unless disabled. Path-based bundle verification
supplies an internal filesystem scope, independent of the displayed path alias.

## Mach-O boundaries

The first `__LINKEDIT` segment, or earlier legacy `LC_SYMTAB` fallback, must reach
the thin image boundary. The universal profile covers ordinary big-endian
`FAT_MAGIC` indexes: physical slice ordering, zero-filled gaps, inter-slice padding
smaller than the following alignment, and no trailing container bytes.
Selecting `-a` checks the selected thin image and bypasses outer universal padding
checks, matching the measured native behavior. Unselected signature corruption
remains outside that selection.

The native constructor stops populating its size index on suspicious padding.
When further slices remain, all-architecture verification reports
`An internal error has occurred.` even with `--no-strict`. A suspicious final gap
or trailing container data instead fails the optional strict layout check with
`main executable failed strict validation`. Both behaviors have native tests.

Alternate fat64/little-endian universal encodings retain portable support with
`NoStrict`; default strict equivalence for those formats is explicitly unsupported.
More than 100 slices, Apple's hidden ARM64 index-entry extension, legacy/object
representations, broader malformed ordering and architecture dispatch remain open.
The existing DMG trailer/code-limit checks remain owned by the DMG verification
adapter and its APFS dependency; this phase adds no duplicate image parser.

## Resource destinations

A sealed link's text is checked first. Changed text retains the ordinary modified
resource error. An unchanged link then resolves its target component by component,
preserving the physical meaning of `symlink/..`. Missing targets and cycles fail.
The measured native limit is 33 followed links in the target path; the sealed link
itself is not counted. Framework `Versions/Current` consumes a hop, and that alias
is retained for traversal and diagnostics. The explicit component walker is needed
because Go's `filepath.EvalSymlinks` permits 255 links; this is host filesystem
policy, not APFS/HFS image traversal. Native acceptance of a final slash on a regular
file and links to the resource root are retained in the measured profile.

Relative targets must belong to an included resource in the nearest containing
bundle or an enclosing verification scope. A child verified independently has no
enclosing scope. Exclusion in the nearest scope stops ancestor lookup. Signature
metadata, receipts and omitted files are excluded; the main executable is an
allowed soft target. Shallow verification skips child ordinary resources; deep
verification applies these checks with the parent's scope.

Absolute targets must exist and resolve below `/System/` or `/Library/` on the
verifying host. A Mac system file therefore passes on Mac and normally fails on
Linux/Windows; evidence identifies those host-dependent cases separately.

Portable scope containment requires path components. Apple's pinned source uses
a raw prefix comparison; prefix-collision destinations remain a deliberate
containment difference. Custom resource rules, Unicode/case behavior, Windows
UNC/drive/reparse classes, exact native path-length and permission errors,
concurrent filesystem mutation and broader multi-failure scheduling remain open.
This read-only policy does not relax signing, removal or dry-run discovery guards.

## Evidence

[The Clang driver](../scripts/extract-resource-verification.go) extracts 18 complete
verbatim Apple function bodies on arm64 and x86_64. The
[manifest](../spec/apple-resource-verification.json) records pinned source URLs,
source/excerpt/driver hashes, SDK/compiler and AST details. It covers resource
validation, enclosing scopes, rule inclusion/exclusions, Mach-O boundaries,
universal construction and diagnostics. Private interfaces are declaration shims;
this is research evidence, not a compiled native production dependency. The CLI
selector dispatcher and libc realpath implementation are not included: those
behaviors come from executable probes and permanent differential tests.

[The acceptance matrix](../acceptance/strict_verification_test.go) contains:

| Matrix | Cases | Checks |
| --- | ---: | --- |
| App/framework, ad-hoc/RSA, 24 destinations, intact/retargeted, quiet/verbose | 384 | API validity, native result/details, immutable tree |
| Three architectures, layout/integrity mutations, selected slices, five policies | 120 | Native status and exact diagnostics; immutable file |
| Selector prefixes, numbers, repetitions, disabling and invalid names | 25 | Exact native status/output; immutable tree |
| Nested app/framework, four states, shallow/deep, text/JSON | 32 | Enclosing scope, 16 native comparisons and 16 JSON reports |

There are 561 portable cases, 545 native comparison profiles and 1,026 comparable
hashes. Native output is exact in 503 profiles. The remaining 42 link profiles
retain bounded resource ordering/primary-summary differences and three raw native
observations each; every resource path must still match. Absolute-target input
hashes and system-file outcomes are explicitly host-dependent. JSON has no native
output counterpart and is checked for parseability and validity.

The previous native-signing corpus retains its 102 strict observations: 34 now
exercise the implemented symlink selector and 68 still assert unsupported plain/all
policy. The earlier native cyclic-framework process termination remains a hard
failure if repeated; no native-test retries conceal it. Existing signing rejection,
explicit certificate trust and cross-platform native-import tests remain enabled.

Full CI and artifact validation for this branch are recorded in the pull request.
No broad feature is marked fully verified.

PR66's first hosted run and unchanged-source debug rerun both exposed native
SIGKILL in the earlier plain-strict framework observations (dangling-chain, then
pair-cycle). The new strict matrices passed, but those attempts are failed gates.
The harness now records PID/start/duration and preserves each failing public
fixture as a tar archive. A bounded post-failure collector captures codesign-related
kernel/AMFI logs, recent codesign crash reports and memory state. A temporary Mac
preflight constructs 100 fresh affected frameworks before the full matrix; any
signal remains a hard failure. This gathers evidence rather than masking the issue.
