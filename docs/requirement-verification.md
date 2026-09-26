# Requirements during verification

Quiet verification now checks signature integrity without asserting that the code
satisfies its own stored designated requirement. For example, an intact ad-hoc
signature containing `designated => never` passes `--verify`. Adding `--verbose=1`
performs the separate self-requirement check and returns status 3. This resolves
the thirty quiet-verification differences recorded during [default merging](requirement-defaults.md).
Certificate verification still requires explicit pins or roots in the portable API
and CLI; this change does not adopt Apple's complete default trust policy.

## CLI stages and architecture selection

1. Verify the selected signature components, pages, certificate policy and bundle
   resources. Parent-sealed child requirements remain mandatory, including during
   shallow verification. `--deep` additionally verifies child pages and resources.
2. With verbosity greater than zero, print `valid on disk` and check the selected
   architecture's stored designated requirement. Print either `satisfies its
   Designated Requirement` or `does not satisfy its designated Requirement`.
3. If `-R`/`--test-requirement` is supplied, evaluate that caller predicate even if
   the self check failed. Success prints `explicit requirement satisfied` only
   with verbosity; failure prints `test-requirement: code failed to satisfy
   specified code requirement(s)` and returns status 3.

An integrity or parent-seal failure stops the later checks for that operand and
returns status 1. A failed parent-sealed requirement is classified as invalid
nested code, rather than a failed top-level test requirement. Across multiple
operands, the first nonzero status is retained; later processing does not replace
status 3 with status 1. Diagnostics retain operand order.

| Operation | No explicit architecture / `--all-architectures` | `-a ARCH` |
| --- | --- | --- |
| Signature integrity | All slices | Selected slice |
| Verbose self requirement | Preferred slice, arm64 on the measured baseline | Selected slice |
| Explicit `-R` predicate | Every verified slice | Selected slice |

The 64-case universal matrix changes one slice at a time and tests slice-specific
CDHash predicates. It distinguishes these selection rules; it does not establish
every architecture or CPU-subtype default. An absent stored designated requirement
passes the self check for the supported implicit identity forms.

## Library migration

`Verify` and `VerifyBytes` no longer automatically evaluate a stored designated
requirement. Callers that relied on the earlier behavior must opt in:

```go
opts := codesign.VerifyOptions{
    CheckDesignatedRequirement: true,
    // Retain your existing TrustedCertificates or TrustedRoots.
}
report, err := codesign.Verify(ctx, path, opts)
```

`VerifyOptions.Requirement` remains a mandatory caller predicate. Either option's
failure returns an error and a report with `Valid == false`. The self option checks
all verified slices, and is inherited by deep child verification. This is stricter
than the CLI's single selected outer self check.

Callers can instead separate integrity and policy without rereading the input:

```go
report, err := codesign.Verify(ctx, path, opts)
if err != nil {
    return err
}
if err := report.CheckRequirement(`identifier "org.example.tool"`, ""); err != nil {
    return err
}
return report.CheckDesignatedRequirement("")
```

Here `opts` contains the caller's existing verification/trust configuration with
the optional self check disabled. Both report methods require a successful verified
report and leave its `Valid` field unchanged. Inspection alone is insufficient.
Do not modify the report before evaluating predicates. Empty architecture checks
all slices selected by the original verification; an explicit name can narrow
that selection but cannot widen it to an unverified slice. Verified certificate
context remains available to predicates. These methods do not reevaluate pages,
read files, fetch certificates, or turn parsed metadata into a trust decision.

The CLI's portable `--json` extension sets `valid` to false when either requested
post-verification predicate fails. Eight cases check this separately from native
output because Apple has no corresponding JSON mode.

## Evidence and retained differences

The [research driver](../scripts/extract-requirement-verification.go) records
[six complete Apple bodies on two Clang targets](../spec/apple-requirement-verification.json):
`staticValidateCore`, `validateNonResourceComponents`, `validateRequirements`,
`validateRequirement`, `internalRequirements` and `validateNestedCode`. They show
component validation preceding a supplied requirement, separate contextual checks
and the mapping of a failed child predicate to invalid nested code. Real SDK flags,
errors and CoreFoundation/C++ declarations are used; private interfaces are
declaration-only shims and tracing is a no-op. The full trust engine, evaluator
and current private CLI call sites are not reconstructed. Native probes establish
CLI verbosity, architecture selection, diagnostics and operand ordering.

[Acceptance coverage](../acceptance/requirement_verification_test.go) adds:

| Matrix | Cases | Scope |
| --- | ---: | --- |
| Five identities × six representations × three self predicates × two verbosity levels × three caller predicates | 540 | CLI status and exact raw output; library opt-in policy and input preservation |
| Ad-hoc/RSA × three architectures × file/app/framework children × five states × shallow/deep | 180 | Parent-sealed requirements, replaced self metadata, identifier/page/component mutations |
| Two changed slices × two mutations × four selections × four checks | 64 | Universal integrity, selected self checks and all-slice explicit predicates |
| Three architectures × three damaged components × quiet/verbose | 18 | Requirements binding, correctly rebound malformed sets and CMS corruption |
| Six operand orders × two explicit predicates | 12 | First failing status, diagnostic order and preserved inputs |
| Two self predicates × quiet/verbose × two caller predicates | 8 | Portable JSON result |

All 822 cases run on each producer; 814 additionally invoke native `codesign` on
Mac. Raw diagnostic equality is required for 630 cases. The other 184 native
records retain both outputs without claiming exact wording: failed nested-code
checks, page/CMS/component failures and unsigned architecture augmentation remain
open. In three quiet malformed-set cases, native verification accepts a correctly
bound malformed structure while Go rejects it; verbose native checks reject it.
All six malformed-set records flag this bounded structural policy difference.
The implementation deliberately retains existing eager structural rejection.

The matrix supplies 1,382 deterministic hashes per producer for cross-OS auditing;
randomized ECDSA CMS bytes are excluded from deterministic comparisons. Inputs
are checked unchanged in every case. Unit tests cover report preconditions,
architecture narrowing, certificate context and explicit trust; `FuzzInspect`
also exercises the report methods after successful verification. The previous
default, compiler and extraction matrices remain in the suite. Final coverage,
CI revisions, downloaded artifacts and packaged-binary evidence belong to the PR.

Full certificate/default policy, contextual host/guest/library/plugin enforcement,
revocation, notarization, process targets, remaining requirement opcodes and all
verification diagnostic forms remain outstanding in [WP-10](implementation_plan.md#wp-10).
No broad inventory obligation becomes fully verified.
