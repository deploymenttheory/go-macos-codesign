# Verification failure diagnostics

This extends [verification policy](requirement-verification.md) with structured
context for a bounded set of native failures. Explicit certificate trust, eager
malformed-requirement rejection and first-failing-operand exit status are unchanged.
[Resource collection](resource-verification.md) extends this contract with ordinary
added/modified/missing details and a documented deterministic ordering choice.

## CLI contract

| Failure | Primary diagnostic | Context |
| --- | --- | --- |
| Unsigned code | `code object is not signed at all` | Failing Mach-O architecture |
| Code page or signed requirements binding | `invalid signature (code or signature have been modified)` | Failing Mach-O architecture |
| Info.plist binding | `invalid Info.plist (plist or signature have been modified)` | Failing Mach-O architecture |
| Resource-directory binding | `invalid resource directory (directory or signature have been modified)` | No architecture line |
| Malformed CMS import | `Unknown format in import.` | Failing Mach-O architecture |
| CMS cryptographic signature | `invalid signature (code or signature have been modified)` | Failing Mach-O architecture |
| Requested architecture absent | `object file format unrecognized, invalid, or unsuitable` | No architecture line |
| Parent-sealed child requirement fails | `nested code is modified or invalid` | Verbose modified-child detail |

The primary line starts with the original operand. Nested component context
follows on stderr, then architecture context. Child paths are absolute. Integrity
failures two levels deep retain the innermost failing component. A failed parent
requirement instead records the modified child; when this happens inside another
child bundle, that bundle supplies the subcomponent context.

Verbose `file modified` details appear on **stdout**, matching Apple. The portable
`--json` extension sends these details to stderr to keep one parseable report on
stdout, with `valid: false`. All measured operations preserve their input bytes.

Default and `--all-architectures` validation prefer arm64, then container order;
`-a` narrows validation. Inspection and JSON retain container order. This matches
the arm64 host for the supported arm64/x86_64 corpus: it is a deterministic portable
choice, not a claim about every native host architecture. DMGs never receive a
synthetic `In architecture: dmg` line.

## Library contract

Use `errors.As(err, &detail)` with `var detail *codesign.VerificationError` to read
`Diagnostic`, `Architecture`, `Subcomponent`, `AddedResources`, `ModifiedResources`
and `MissingResources`. `Error()`
retains the detailed Go description and `Unwrap()` preserves sentinel identity.
Context augmentation copies errors rather than mutating earlier contexts.

Missing external Info.plist/resource data still unwraps to `ErrUnsupported`;
damaged bindings unwrap to `ErrInvalid`. Failed parent requirements unwrap to
`ErrInvalid`, not caller-predicate `ErrRequirement`. Unclassified failures,
including explicit trust and unsupported CMS algorithms, retain their own errors.
`VerifyCMS` provides import/signature context without an architecture;
`VerifyBytes` adds the failing Mach-O architecture.

## Independent evidence

The [Go driver](../scripts/extract-verification-diagnostics.go) extracts eight
complete, verbatim bodies from pinned Apple `StaticCode.cpp`, `cs_utils.cpp` and
`cserror.cpp`. The [manifest](../spec/apple-verification-diagnostics.json) records
whole-source, excerpt, driver and translation-unit hashes, compiler/SDK versions
and separate arm64/x86_64 Clang ASTs. Real SDK declarations are used; private
interfaces, errno-range declarations, slot aliases and `cfmake` remain declaration
shims, and tracing is a no-op. ASTs establish control flow and streams; native
probes establish current wording and context behavior. Production requires neither
Clang nor macOS frameworks.

[New acceptance tests](../acceptance/verification_diagnostics_test.go) add:

| Matrix | Cases | Evidence |
| --- | ---: | --- |
| Three Mach-O forms × five failures × four selections × quiet/verbose | 120 | Exact native status/stdout/stderr; unchanged bytes |
| Apps/frameworks × seven failures × quiet/verbose | 28 | Includes valid Info.plist/resource binding damage |
| DMGs × five failures × quiet/verbose | 10 | No architecture context |
| Three two-level child failures × relative/absolute operand × quiet/verbose × text/JSON | 24 | Twelve native comparisons and twelve JSON/stream checks |

The five common failures are unsigned, code page, requirements binding, CMS import
and CMS cryptographic signature. All **182 cases** run on each OS; **170** also
invoke native `codesign` on Mac. The 158 direct cases contribute input and
diagnostic hashes; the 24 nested cases contribute input hashes, totaling **340
deterministic hashes** per producer. Nested absolute temporary paths remain raw,
locally compared output, not cross-OS diagnostic hashes. CMS mutations use RSA.

The retained 822-case requirement matrix now requires exact diagnostics in **808
of 814 native comparisons**, up from 630. Six malformed-set cases remain explicit
differences, including three quiet native acceptance/Go rejection cases. Eight
portable JSON cases retain their existing scope. All earlier matrices remain
gates; final coverage, CI revisions and package audits are recorded in the PR.

## Remaining work

Resource aggregation now has a [bounded contract](resource-verification.md), with
native ordering and dangling-link differences retained. Malformed Mach-O/signature
containers, other CMS attribute/policy errors,
strict validation, alternate framework-version failures, symbolic/Unicode aliases,
localized text, other architecture preferences and certificate policy diagnostics
need further probes. Malformed binary Info.plist parsing is distinct from the
valid-plist binding cases here. ECDSA corruption diagnostics remain unproven.
The broad inventory is unchanged; WP-10 and WP-20 remain open.
