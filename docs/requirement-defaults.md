# Requirements during signing

Certificate signing now fills a missing designated requirement in an absent,
explicitly empty or partial requirement set. Explicit designated requirements
override synthesis, including `always` and `never`. Ad-hoc signing adds no stored
designated requirement. All preparation is pure Go on Linux, macOS and Windows.

```sh
macoscodesign -s identity.pem -i org.example.tool -r='host => never' ./tool
macoscodesign -s identity.pem -i org.example.tool -r='designated => always' ./tool
```

Use the documented [identity inputs](certificates.md) for the CLI's PEM/key or
PKCS#12 options. The same rules apply to `SignOptions.Requirements` in the library.

## Merge and ownership contract

1. Validate the caller's entire compiled set using the existing bounded decoder.
2. Retain each supplied kind and its exact requirement child bytes.
3. If kind 3 is absent and a certificate identity is selected, call the existing
   certificate designated-requirement builder for this code object's identifier
   and validated chain. Explicit kind 3 avoids this builder entirely.
4. Sort entries by unsigned kind and tightly repack into a newly owned SuperBlob.
   Unreferenced padding is discarded. Never mutate caller-owned bytes.

Both input and output are limited to 1 MiB and 64 entries. Adding a default to an
already full set fails before writing; an explicit designated requirement can
occupy the last permitted entry. Structural/opcode validation still applies to
explicit requirements, but signing does not evaluate their truth. Chain, identity,
Team ID and signing-option checks retain their existing behavior.

Nested signing prepares each object's requirements independently. A synthesized
parent identifier cannot leak into its children through shared options. Forced
replacement derives requirements from the current options and identity; old host
or designated requirements are not implicitly preserved. This does not implement
`--preserve-metadata`. Malformed source and measured dry runs preserve input trees.
Certificate DMG dry runs retain their existing unsupported status.

The supported default builders retain leaf/organization anchors and the existing
bounded Developer ID policy. The new byte comparisons use public RSA and three
ECDSA identities, plus the root/intermediate/leaf organization fixtures. They do
not establish full Apple-issued identity policy.

## Independent evidence

The [Clang driver](../scripts/extract-requirement-defaults.go) extracts six complete
pinned Apple function bodies on arm64 and x86_64 into the
[AST manifest](../spec/apple-requirement-defaults.json). It covers merge precedence,
lazy generation, non-Apple anchor selection and representation delegation. Real
SDK declarations are used with declaration-only private interfaces. Clang and
Apple tools are development oracles, with no production runtime dependency.

[Unit tests](../pkg/codesign/requirement_sign_test.go) cover ownership, idempotence,
sorting, padding, exact limits, lazy generation and unchanged inputs on failure.
`FuzzRequirementSet` also exercises ad-hoc and certificate preparation.
[Acceptance tests](../acceptance/requirement_defaults_test.go) add:

| Matrix | Cases | Compared behavior |
| --- | ---: | --- |
| Five identities × six representations × seven sets | 210 | Requirements, CodeDirectories, other non-CMS components, layout, code bytes, extracted text and native strict verification |
| Ad-hoc/RSA nested apps across three architectures | 6 | Six independently identified objects per case, components and deep verification |
| Root/intermediate/leaf organization anchors | 3 | Chain-based generated requirements and supplied-root verification |
| Replacement, empty/partial override, malformed source and dry runs | 58 | Fresh defaults, component bytes, preservation and measured diagnostics |
| Four certificate algorithms × three architectures × four sets | 48 | Native layout, non-CMS bytes and matched-time complete RSA signatures |

The first 277 cases run on all three CI producers and compare against Apple on
Mac. The last 48 extend the [native certificate suite](../acceptance/native_identity_test.go).
Representations are arm64, x86_64, universal Mach-O, apps, versioned frameworks
and DMGs. Profiles are absent, empty, host-only, all non-designated named kinds,
explicit true/false overrides and unordered binary indexes. Complete ad-hoc trees
are compared; nondeterministic ECDSA CMS bytes are not claimed identical.
Per-case attestations distinguish comparisons actually run from portable checks.
Final-commit coverage, CI and downloaded-artifact audits belong to the PR.

The previous 87 extraction and 75 compiler cases remain. Legacy certificate
fixtures without stored designated requirements are constructed explicitly as
described in [extraction evidence](requirement-extraction.md), rather than changing
the production signing contract to preserve an obsolete fixture assumption.

## Explicit differences and next work

Thirty signing cases use `designated => never`. Apple signs and ordinarily verifies
them successfully. Go produces matching signed components but its verifier returns
`ErrDesignatedRequirement`, because it evaluates the object's own designated
requirement automatically. This is recorded as a known difference in every
producer's evidence. The next verification phase must distinguish ordinary
integrity verification from caller-requested and parent-sealed requirements,
retain malformed-component rejection, and preserve explicit certificate trust.

The twelve malformed-source lifecycle cases preserve inputs on both implementations
but retain different syntax diagnostics. Other outstanding work includes:

- Mach-O library dependency defaults from `LC_DYLIB_CODE_SIGN_DRS`, generic script
  interpreter defaults and other representation-specific requirements.
- Complete Apple-proper/default certificate policy and metadata preservation.
- Stdin, `$self.identifier`, broader expression grammar and exact parser errors.
- Wider slots, representations, resource policies and operation interactions.

The [implementation plan](implementation_plan.md#wp-09) retains these obligations.
No broad compatibility inventory item becomes fully verified.
