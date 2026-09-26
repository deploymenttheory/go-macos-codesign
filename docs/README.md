# Project documentation

Start with [project progress](progress.md) for delivered milestones, measured
coverage, native acceptance evidence and the next phase. The implementation is
partial; the [capability matrix](compatibility.md) records the remaining gaps.
The [detailed implementation plan](implementation_plan.md) maps those gaps to
work packages, dependencies, native acceptance criteria and proposed PR slices.

| Guide | Contents |
| --- | --- |
| [Progress](progress.md) | Milestones, tested commit/workflow, coverage and maintenance checklist |
| [CLI/build quick start](../README.md) | GoReleaser, common operations and library entry points |
| [Signing diagnostics](signing-diagnostics.md) | Replacement notices, callback timing, native comparisons and remaining output gaps |
| [Signature file lists](file-lists.md) | Ordered signature paths, append output, partial effects and explicit native differences |
| [Entitlement extraction](entitlement-extraction.md) | DER/XML selection, typed text, append output, error ordering and remaining limits |
| [Requirement extraction](requirement-extraction.md) | Canonical text, implicit designated requirements, slot binding and truncate-before-validation output |
| [Requirement compilation](requirement-sets.md) | Named/decimal sets, expression grammar, duplicate ordering and limits |
| [Signing defaults](requirement-defaults.md) | Missing certificate requirements, explicit overrides and nested/replacement defaults |
| [Requirement verification](requirement-verification.md) | Integrity, verbose self checks, caller/parent predicates and API migration |
| [Certificate signing](certificates.md) | PEM/PKCS#12, CMS, certificate chains, Team IDs and explicit trust |
| [Timestamps](timestamps.md) | Online HTTP signing, RFC 3161 verification, TSA roots and live testing |
| [App bundles](bundles.md) | XML/binary metadata, resource sealing, native evidence and filesystem limits |
| [DMG signing](dmg-integration.md) | Direct go-apfs-v2 dependency, native signatures, evidence and limits |
| [File writes](file-writes.md) | Shared APFS metadata API, hard-link behavior, staging and limits |
| [Native inventory](native-inventory.md) | Expanded parser/operation evidence, source gaps and live-state access constraints |
| [Compatibility](compatibility.md) | Implemented behavior, native comparisons and unresolved requirements |
| [Roadmap](implementation.md) | Delivered components, next phase and outstanding work |
| [Detailed implementation plan](implementation_plan.md) | Complete remaining-feature backlog, 24 work packages, acceptance matrices, blockers and delivery order |
| [Testing](testing.md) | Local commands, native acceptance, CI artifacts and full-parity audit |
| [Releases](releases.md) | Release Please, GoReleaser, App/PAT setup, SBOMs and signed checksums |
| [Research](research.md) | Clang AST extraction, source pins and provenance |
| [Reference implementations](reference-implementations.md) | GitHub source comparisons and how they informed the work |
| [Contributing](../CONTRIBUTING.md) | Development and PR requirements |
| [Changelog](../CHANGELOG.md) | Unreleased implementation history |
