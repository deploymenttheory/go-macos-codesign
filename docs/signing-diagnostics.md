# Signing diagnostics

Forced signing of a supported, already-signed input prints this notice to stderr:

```text
Example.app: replacing existing signature
```

It appears once per top-level operand, before signature construction and resource
traversal. Deep signing does not add one notice per descendant. The path retains
the operand's spelling, including a file alias, bundle main-executable path or
framework `Versions/Current` directory. Repeated operands produce repeated notices.
An unsigned input produces no replacement notice even when `--force` is present.

The notice describes an attempted replacement. It also appears during `--dryrun`
and before later resource or write failures. It does not prove success, integrity,
certificate trust or that any signature bytes changed. Structurally readable
signatures with altered code pages or identifiers still produce the notice;
certificate-backed inputs do not need a trusted certificate for this observation.
DMG components without a CodeDirectory remain unsigned and produce no notice.

Without force, already-signed rejection remains `is already signed`. Invalid
non-power-of-two page sizes are rejected before processing any operand or printing
notices. With `--continue`, a failed target's notice and error precede the next
target's notice; without it, later targets remain untouched.

## Library contract

`SignOptions.OnReplace` is an optional, synchronous callback for the same bounded
path-signing event. It receives no path: the caller already supplied the operand
to `Sign`. It runs at most once per call, before construction, and can precede an
error. It must not modify inputs or options. No callback means no notification
work. `SignBytes` and nested byte construction never call it, and the library
never prints diagnostics itself.

Bundle notification reads only the selected main executable through its existing
root before resource traversal. It does not enumerate resources or record a mapped
source access. The normal signing path retains APFS v0.9.0 metadata handling and
the existing deferred source-access and commit boundaries.

## Evidence and limits

- `TestSigningReplacementNotice`: 80 cases across thin/universal Mach-O, five DMG
  formats, APPL/recursive apps and six other layouts; exact stderr, exit status and
  whole-file/tree byte comparisons on Mac. All cases execute on Linux and Windows.
- `TestSigningNoticeSignatureState`: seven ad-hoc, tampered, RSA/P-256,
  linker-marked and malformed-signature cases. Six have exact diagnostics; the
  malformed case retains and records the existing repair/rejection difference.
- `TestSigningNoticeAliasesAndTargets`: five operand-spelling and multiple-target
  cases with exact output and preserved dry-run bytes.
- Eight Mac permission/envelope/continuation cases require the notice before the
  failure and compare preserved or subsequently signed bytes. Complete raw error
  text is recorded; broader OS error wording still differs.
- All 70 existing DMG dry-run lifecycle cases now require exact native diagnostics.
- Unit tests cover callback timing, pre-cancelled calls, cancellation from the
  callback, later validation/traversal failures and silent byte APIs.

The [Clang record](../spec/apple-paths.json) includes the complete published Apple
`note` helper on arm64 and x86_64, using real SDK stdio and variadic declarations.
It establishes the helper's stderr/newline and verbosity control flow. The pinned
source does **not** publish the current CLI signing call site; live native tests
establish replacement-notice conditions and ordering independently.

This slice does not complete verbosity output, malformed or mixed-signature
universal selection, linker-signature replacement without force, arbitrary
planning/permission failures, localization or diagnostic parity. Native errors
must not be normalized away to claim equivalence. All 88 inventory statuses and
the full-parity gate remain unchanged.
