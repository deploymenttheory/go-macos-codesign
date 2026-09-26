# Resource verification diagnostics and collection

This extends [verification error context](verification-diagnostics.md) to ordinary
sealed resources. Valid V2 envelopes use the existing rule/digest profile and
bundle scanner. Signing bytes, containment policy and explicit certificate trust
are unchanged; no macOS code-signing implementation is called by production code.

## Implemented behavior

A supported added, modified or missing resource rejects verification with exit 1
and `a sealed resource is missing or invalid`. Resource detail lines appear on
stdout only with verbosity enabled, grouped as **added, modified, missing**.
`--json` routes the detail lines to stderr and leaves a parseable report on stdout.
Failures preserve their input files and trees; resource errors add no architecture
line. Deep nested resource errors retain the child subcomponent context.

| Situation | Result |
| --- | --- |
| Unsealed regular file or supported symlink added | Added resource |
| Sealed file content changed | Modified resource |
| Required regular file, symlink or sealed nested executable removed | Missing resource |
| Symlink target text changed, or regular file and symlink exchanged | Modified resource |
| Optional localization resource removed | Accepted |
| Optional localization resource modified or an unsealed one added | Rejected with the corresponding detail |
| Required `Base.lproj` resource removed | Missing resource |
| Child fails the requirement in its parent's seal | Collected modified child; native nested-code summary |
| Child has its own integrity/resource exception | Propagated with subcomponent context |
| Malformed seal or unsupported envelope profile | Rejected without converting it to a normal resource mismatch |

Default versioned-framework diagnostics retain `Versions/Current`; explicit `A`
selection and direct `Versions/A` input retain the corresponding physical spelling.
Reads remain confined to the resolved physical version through the existing root.
Unversioned frameworks and Contents-based apps are included. Default shallow
verification skips a nested child's ordinary resources; `--deep` checks them.

## Collection and ordering

Verification visits present names in lexical order, then absent sealed names in
lexical order. It collects supported local resource failures, retains all causes,
and sorts each detail group by path. Missing optional entries do not fail. Nested
exceptions and malformed/unsupported profiles remain immediate failures instead
of being absorbed into a parent's resource list. Cancellation is checked during
the bounded traversal.

Apple's collecting context records the first arriving error and appends details
under a lock; its resource validator can run workers concurrently. Repeated native
probes observed different orders for the same added and modified files. Missing
entries also use dictionary iteration rather than lexical order. Consequently,
**ordering within a multi-file category is an explicit difference**, not a raw
output equivalence claim. The portable implementation chooses stable ordering.

When ordinary resource failures and parent-sealed child failures coexist, native
scheduling also selects the primary error. Portable lexical traversal may select
the nested-code summary where Apple selects the ordinary-resource summary.
Acceptance requires rejection, every resource detail, and the correct group order,
while retaining both summaries as a bounded difference. It does not infer a new
native precedence rule from one run or discard unmatched diagnostic lines.

## Library API

`VerificationError` now includes `AddedResources` and `MissingResources` alongside
`ModifiedResources`. Path-based verification returns absolute paths with the
selected framework spelling. `Diagnostic`, `Architecture` and `Subcomponent`
retain their earlier meanings. `Error()` includes the underlying detailed causes;
`Unwrap()` exposes the joined causes to `errors.Is`/`errors.As`. Ordinary resource
and parent-seal failures remain `ErrInvalid`; parent-seal failures do not become
caller `ErrRequirement` failures. Invalid bundle reports have `Valid == false`.

## Research and acceptance evidence

The [Go research driver](../scripts/extract-resource-verification.go) extracts eight
complete verbatim Apple bodies: resource loading, optional-resource checks,
individual resource validation, immediate/collecting contexts, collector throw,
and grouped diagnostic rendering. [Two-target Clang evidence](../spec/apple-resource-verification.json)
records source, excerpt, driver and translation-unit hashes. Real SDK declarations
are used with declaration-only private interfaces and no-op tracing. The complete
asynchronous traversal is reviewed as source but is not compiled in that shim;
repeated host probes establish the actual ordering variation. Clang and macOS are
development tools, not production requirements.

[Acceptance tests](../acceptance/resource_verification_test.go) add:

| Matrix | Cases | Native scope |
| --- | ---: | --- |
| Four representations × ad-hoc/RSA × 19 states × quiet/verbose | 304 | 264 exact profiles; 24 within-group ordering and 16 mixed-summary profiles |
| App/framework children × three changes × shallow/deep × quiet/verbose × text/JSON | 48 | 24 exact native comparisons and 24 portable JSON checks |
| Three changes × Current/A/direct framework selection × quiet/verbose | 18 | Exact native diagnostics |
| App/framework × three dangling-link states × quiet/verbose | 12 | Explicit existing discovery differences |

All **382 cases** run on each producer; **358** also invoke native `codesign` on
Mac. **306** require exact raw native output. The 40 ordering/summary cases retain
three native observations each and compare complete grouped detail lists without
losing duplicates. The twelve dangling-link cases retain both outputs and statuses.

There are **686 deterministic hashes** per producer: two per ordinary matrix case
and one input hash per remaining case. The ordinary diagnostic hash normalizes
only the asserted fixture-root prefix and Windows separators. Every reported
resource path is checked within that fixture root. Raw Go/native outputs and the
fixture root remain in evidence; independent audits recompute the normalized
hash. No native output is normalized for an exact local comparison. JSON and
dangling-link output do not receive a cross-OS diagnostic hash.

Unit tests additionally check aggregation, full retained causes, deterministic
ordering, malformed nested seals, changed types, cancellation and nested exception
boundaries. Existing matrices and >95% coverage gates remain in force. Final
coverage, three-OS CI revisions and downloaded artifact audits belong to the PR.

## Outstanding work

The scanner still requires supported symlink targets to resolve within its root.
An unchanged link whose required target is removed, a link retargeted to a missing
file and a link to a removed optional localization file fail that existing check.
Apple rejects the first two through resource diagnostics and accepts the last in
the measured default policy. Four of the twelve dangling records therefore expose
native acceptance versus portable rejection. Signing and containment behavior are
not relaxed here; a separate verification-specific symlink-policy phase must prove
safe behavior for dangling links, chains, escapes and strict-mode interactions.

Other outstanding work includes custom/legacy rules and digests, empty directory
and type transitions, recursive/excluded resources, alternate framework versions,
filesystem races, Unicode/case aliases, strict/xattr/revocation policy, and native
scheduling/primary-error equivalence. No broad inventory status becomes verified.
