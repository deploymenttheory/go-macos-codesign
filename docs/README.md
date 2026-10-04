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
| [Detailed implementation plan](implementation_plan.md) | Outstanding-only roadmap: eleven remaining larger phases, 88 feature owners, prerequisites and acceptance gates |
| [Testing](testing.md) | Local commands, native acceptance, CI artifacts and full-parity audit |
| [Releases](releases.md) | Release Please, GoReleaser, App/PAT setup, SBOMs and signed checksums |
| [Portable I/O and lifecycle](portable-io-lifecycle.md) | Phase 02 scope, APFS v0.17.1 integration, mounted HFS+ acceptance and remaining work |
| [Held-file inspection](source-range-io.md) | Range parsing, native large-file verification, memory evidence and remaining size limits |
| [Streaming DMG signing](dmg-streaming.md) | Held-file signing, 64-bit limits, native tail writes and large-file qualification |
| [Streaming Mach-O mutation](macho-streaming.md) | Held-file signing/removal, universal assembly, native allocation limits and staged replacement |
| [Operation I/O](operation-io.md) | Bounded transfers, cancellation checkpoints, partial writes, cleanup and current streaming limits |
| [Research phase and harness](research-phase.md) | Whole-roadmap evidence map, prerequisite findings, native probe refactor and strict CI partitioning |
| [Research](research.md) | Clang AST extraction, source pins and provenance |
| [Sideband policy](sideband-policy.md) | Shared three-OS attribute API, complete Apple AST bodies, native controls and release/integration sequence |
| [Reference implementations](reference-implementations.md) | GitHub source comparisons and how they informed the work |
| [Contributing](../CONTRIBUTING.md) | Development and PR requirements |
| [Changelog](../CHANGELOG.md) | Unreleased implementation history |
