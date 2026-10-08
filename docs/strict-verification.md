# Strict verification policy

Verification now checks supported Mach-O layout boundaries by default. Use
`--strict=symlinks` to additionally check sealed resource destinations, and
`--no-strict` or `--strict=none` to disable these additional policies. Signature
integrity, certificate trust, parent requirements and safe parsing remain mandatory.
This is a bounded implementation, not full `codesign --strict` equivalence.

```sh
macoscodesign --verify --strict=symlinks --deep Example.app
macoscodesign --verify --no-strict executable
macoscodesign --verify --strict=sideband executable
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
sideband masks are supported for standalone Mach-O, supported bundles and UDIF inputs. Mach-O rejects
nonempty prohibited metadata; UDIF bypasses that policy, matching Apple's override.
Bundle traversal checks included resources and nested code, then the canonical root
and main executable. A disabling option permits ordinary verification. Unknown bits and strict controls outside verification remain
unsupported. Numeric overflow/unknown API masks are not claimed as native diagnostic
parity. No unsupported policy silently falls back to ordinary verification.

Library callers use `VerifyOptions.StrictSymlinks`, `VerifyOptions.StrictSideband`
and `VerifyOptions.NoStrict`. Optional `VerifyOptions.AppleDouble` adds an explicit
carrier for one standalone operand; `AppleDoubleFiles` binds snapshots to bundle
members. These are library inputs; CLI operations use filesystem-selected metadata. See [sideband policy](sideband-policy.md) for
held-object lifetime, format-specific behavior and first-error ordering.
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
policy. The 68 plain/all native observations add `--strict=4096` to request serial
resource validation; their attestations record `native_args` and
`native_single_threaded`. They characterize policy outcomes, not equivalence to
the native asynchronous execution mode. Implemented symlink comparisons and all
default verification commands keep their original flags. Existing signing
rejection, explicit certificate trust and cross-platform native-import tests remain
enabled. No native-test retries conceal failures.

Full CI and artifact validation for this branch are recorded in the pull request.
No broad feature is marked fully verified.

### Native asynchronous verification crash on Xcode 27

PR66's first hosted run and unchanged-source debug rerun exposed native SIGKILL
in the plain-strict dangling-chain and pair-cycle framework observations. The new
strict matrices passed, but those attempts remain failed gates. A diagnostic run
with 100 fresh frameworks reproduced multiple crashes before the full suite:
[run 36318321522](https://github.com/deploymenttheory/go-macos-codesign/actions/runs/36318321522).
Its `evidence-xcode-27` artifact retains 29 failing input archives, invocation
details, system logs and 25 native crash reports. Reports include `EXC_BAD_ACCESS`/SIGSEGV
and `PAC_EXCEPTION`/SIGKILL. The faulting worker stack passes through
`tre_tnfa_run_parallel`, `ResourceBuilder::Rule::match`, `findRule`, `includes`
and `SecStaticCode::validateResource`. The main thread waits in
`Security::Dispatch::Group::~Group()`.

The likely cause is a lifetime race in Apple's resource validation during error
unwinding; this is an inference from the crash stacks and pinned source, not an
Apple-confirmed diagnosis. In
[validateResources](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/StaticCode.cpp#L1367),
the dispatch group is declared before `ResourceBuilder`, and scanning queues
workers that use `mResourceScope`. A scan exception can therefore destroy the
resource rules before the group destructor waits for outstanding workers. The
[group destructor](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_utilities/lib/dispatch.cpp#L96)
and [LimitedAsync dispatch](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/csutilities.cpp#L287)
support that explanation. The hosted crashes are not classified as expected policy
rejections or attributed to memory pressure.

The Mac SDK documents `kSecCSSingleThreaded = 1 << 12` (4096) as serial resource
validation. `validateResources` passes `false` to `LimitedAsync` when this bit is
set. Native CLI numeric strict selectors add API bits, so the reference invocation
retains `--strict` or `--strict=all` and appends `--strict=4096`. It does not clear
symlink/sideband policy or enable a resource-validation bypass. Local probes of 32
original/serial profile pairs produced identical status, stdout and stderr; the
full native-signing corpus still asserts the expected successes and rejections.
This test-only accommodation does not add native calls or dependencies to production.

The Mac preflight exercises the selected profiles against 100 fresh affected
frameworks. Every unexpected status, signal or timeout remains a hard failure.
To reproduce the original asynchronous native commands explicitly:

```sh
MACOSCODESIGN_REQUIRE_APPLE=1 MACOSCODESIGN_REPRODUCE_NATIVE_STRICT_CRASH=1 \
  go test -count=50 -run '^TestResourceSymlinkNativeSigning/framework/(pair-cycle|dangling-chain)$' ./acceptance
```

This diagnostic can crash Apple's `codesign`; it only uses temporary test fixtures.
The harness records PID/start/duration and preserves each failing public fixture.
CI's bounded post-failure collector captures related system logs, recent native
crash reports and memory state. Its best-effort collection cannot turn a failed
test into a pass. The original asynchronous native defect remains outside this
project's control and is not claimed fixed.
