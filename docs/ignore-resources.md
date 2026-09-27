# Verification without resource checks

`--ignore-resources` selects a limited verification policy. It checks the selected
main executable and its non-resource signature components while skipping the
resource envelope, resource contents and parent-sealed nested code. A successful
result does not establish integrity of the complete bundle.

```sh
macoscodesign --verify --ignore-resources --verbose=1 Example.app
macoscodesign --verify --ignore-resources --deep --json Example.app
```

The first command reports the native limited-scope success wording:

```text
Example.app: valid on disk (not all contents verified)
Example.app: satisfies its Designated Requirement
```

The suffix also appears for standalone files and DMGs. Quiet success has no text.
The option takes no argument; repeated occurrences are idempotent. Signing,
display and removal accept it without changing their behavior. Their other
options, input requirements and limitations still apply.

## What is skipped and retained

| Verification component | With `--ignore-resources` |
| --- | --- |
| CodeDirectory and CMS integrity | Enforced |
| Explicit certificate pin/root trust and Team ID policy | Enforced |
| Main executable code pages | Enforced in each selected architecture |
| Info.plist, requirements, entitlements and other non-resource slots | Enforced within the existing supported signature profile |
| UDIF representation-specific trailer binding | Enforced through the existing APFS adapter |
| CodeResources special-slot hash | Skipped |
| Reading/parsing CodeResources contents | Skipped |
| Ordinary resource contents and symlink targets | Skipped |
| Parent-sealed nested-code checks | Skipped, including with `--deep` |
| Verbose self-designated requirement and explicit `-R` predicate | Enforced with existing ordering/status semantics |
| Default Mach-O and supported bundle structure | Enforced unless `--no-strict` disables these additional checks |

Changed, missing, added, cyclic and external resource links do not cause resource
failure in this mode. Missing, malformed or changed child code also does not
cause child verification failure. `--deep` does not re-enable child traversal.
The supported `--strict=symlinks` selector does not re-enable resource checks.
Plain/all/sideband strict selectors remain unsupported; combining them with this
flag does not silently bypass that restriction.

Main metadata discovery still precedes verification. In a framework,
`Resources/Info.plist` is required metadata. Deleting that whole directory removes
Info.plist as well as ordinary resources; it is not a resource-only mutation.
Missing/malformed main metadata and unsupported bundle layouts retain existing
discovery limitations and diagnostics.

Structural validation inspects the outer app root and the selected signature
directory without opening CodeResources or traversing nested resources. Missing
CodeResources or the whole signature directory is accepted. A regular bound
CodeResources file can contain arbitrary bytes. A directory or symlink at that
name, an unexpected signature entry or an unexpected outer app-root file fails
with `unsealed contents present in the bundle root`. An empty regular
`CodeSignature` entry is accepted; a nonempty one is rejected. A regular file
where `_CodeSignature` should be a directory reports `Not a directory`.
These additional checks are suppressed by `--no-strict`; safe layout discovery
and parsing remain required. A regular unbound CodeResources file is still an
unexpected signature entry under default structure policy.

## Library and JSON contract

```go
report, err := codesign.Verify(ctx, path, codesign.VerifyOptions{
    IgnoreResources: true,
    Deep: true,
    // Supply the usual explicit certificate trust when applicable.
})
```

`VerifyBytes` also honors `IgnoreResources`: it skips the resource slot even if
the caller supplies changed or absent `Resources` bytes. Other supplied metadata
still binds normally. Existing rejection of external slot overrides on bundle
paths and DMGs remains unchanged.

`Report.ResourcesIgnored` records this selected policy, including on reports
returned with an integrity/structure/requirement error after successful parsing.
`Report.Valid` is true only if all remaining selected checks passed. Failed
discovery/parsing may return no report. Context cancellation remains an error.
The JSON extension includes `"ResourcesIgnored": true`; the field is omitted
when false, preserving earlier default JSON output. Apple provides no equivalent
JSON response, so JSON evidence is a portable API contract, not native JSON parity.

Because the envelope is unread, `Bundle.ResourceVersion`, `ResourceRules` and
`ResourceFiles` are zero in these reports. They mean unavailable in this mode,
not that the signed bundle has no resources. Info.plist entry metadata remains
available. Existing explicit trust and verification limitations still apply.

## Research and acceptance evidence

[The Go research driver](../scripts/extract-ignore-resources.go) compiles four
complete verbatim bodies from pinned Apple Security commit
`db15acbe6a7f257a859ad9a3bb86097bfe0679d9`:

- `SecStaticCode::staticValidate`: per-architecture core before the optional
  resource stage, followed by independent strict/structural checks.
- `staticValidateCore`: executable/non-resource integrity and supplied requirement.
- `validateNonResourceComponents`: all signed special components except resources.
- `BundleDiskRep::validateMetaDirectory`: used-component filenames, regular-file
  checks and the empty CodeSignature exception.

Sources are Apple's
[StaticCode.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/StaticCode.cpp)
and [bundlediskrep.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/bundlediskrep.cpp).
The [AST record](../spec/apple-ignore-resources.json) retains source, excerpt,
driver and translation-unit hashes plus function nodes/references on both Mac27
targets. SDK flags, CoreFoundation, C++ and blocks are real declarations. Private
interfaces/flags use declaration-only shims and tracing is a no-op. The actual
`TARGET_OS_OSX` branch is retained; the research does not implement notarization
or reproduce Apple's full trust engine/private CLI. Production remains pure Go.

[Acceptance tests](../acceptance/ignore_resources_test.go) add 385 portable cases:

| Matrix | Cases | Assertions |
| --- | ---: | --- |
| Resource suppression | 260 | App/framework, ad-hoc/RSA, 14 app states and 12 framework states, quiet/verbose/deep/symlinks/no-strict |
| Retained structure | 26 | 13 app/framework states with default/no-strict; exact diagnostics |
| Retained integrity/requirements | 74 | Thin/universal, app/framework and DMG; clean/pages/requirements/CMS/self/explicit/Info.plist, quiet/verbose |
| Architecture selection | 6 | Damage either universal slice; default-all and each explicit slice |
| Nested apps/frameworks | 12 | Missing child, malformed child Info.plist, changed child pages; shallow/deep |
| JSON extension | 4 | Valid/invalid results, explicit scope marker, unread resource counts and preserved trees |
| Inert operations | 3 | Signing/display/removal outputs and bytes identical with and without the flag |

Mac adds eight fresh independently Apple-signed cases and three native inert
controls, for 396 records in total. The 386 differential verification profiles
require exact status, stdout and stderr. All verification cases assert complete
input-tree preservation. Linux/Windows record the same portable policy and emit
767 comparable hashes (input trees, diagnostics, normalized JSON, inert outputs).
JSON hashing normalizes only the separately checked executable path separators;
raw JSON and both tools' raw diagnostics remain in evidence.

[Unit tests](../pkg/codesign/ignore_resources_test.go) additionally check byte API
slot independence, cancellation, explicit trust, absence of a resource slot,
unbound signature entries and shared structural entry bounds. The
[CLI tests](../internal/cli/ignore_resources_test.go) cover repeat/applicability,
attached-value rejection, help and verbose scope wording. Full local/hosted gate
results are recorded in the pull request; matrix existence alone is not a passing
three-OS gate.

## Remaining work

This flag is partial in the 88-entry inventory. Noncanonical framework roots,
symlinked main metadata/signature directories, external signature components,
generic/xattr and detached signatures, custom rules, filesystem xattr sidecars,
concurrent mutation and broader permission/alias/Unicode behavior remain open.
Attached values are rejected with the portable parser's diagnostic/status; the
native CLI has a different malformed-option path. Arbitrary combinations with
other options are not claimed equivalent. `--no-strict` does not remove bounded
discovery restrictions or make unsupported layouts valid.

Sideband enforcement and `--strip-disallowed-xattrs` need strict shared APFS
metadata APIs. Released `go-apfs-v2 v0.11.2` still provides a best-effort
`hostmeta.ListXattrs` reader that can suppress individual value errors. That is
insufficient evidence of absence for strict verification. A future APFS change
must distinguish missing, present-empty and unreadable attributes; expose bounded
no-follow/pinned-object queries and removal; and retain real errors and object
identity. Tests must cover ResourceFork/FinderInfo on code, resources, directories
and links, unrelated attributes, dry runs and partial failures before integrating
the released API here. This phase adds no duplicate xattr syscall implementation.
