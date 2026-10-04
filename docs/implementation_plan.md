# Remaining implementation roadmap

This roadmap contains only outstanding work toward a pure-Go equivalent of the
macOS `codesign` CLI: the same options and operational behavior on Linux, macOS
and Windows. It replaces the former incremental work-package plan. Completed
implementation and validation evidence belong in the [focused guides](README.md),
[progress record](progress.md), source/fixture manifests and Git history.

Planning baseline: 2026-10-04, main at
`12b40468f39d040d66776d3eed6c18b8cd090d48`, now consuming published go-apfs-v2 v0.17.1.
The [compatibility inventory](../spec/compatibility.json) has **88 outstanding
entries: 32 partial, 48 not implemented and eight blocked; zero fully verified**.
These are obligations of different sizes, not a percentage-complete calculation.
The reference is macOS 27.0 build 26A428, arm64; its binary/manual hashes are in
that inventory. Other native versions and architectures need explicit profiles.

The delivery unit is now a cohesive subsystem phase, including research,
implementation, API/CLI integration, failure behavior, portable tests, native
acceptance and documentation. The default is **11 remaining phase PRs (02–12)**,
with separately
released APFS prerequisites and justified splits when required. This is not a
promise that eleven PRs can resolve unavailable hardware, private protocols or
conflicting constraints. No partial or blocked entry disappears to meet a PR count.

The work below remains outstanding. Use the merged [whole-roadmap research](research-phase.md)
and capture/audit each phase's complete native case corpus before implementing its
behavior. Avoid both one-encoding-per-PR delivery and speculative implementation
based only on source declarations.

## Delivery map and dependencies

| Phase | Cohesive result still required | Inventory owners | Dependencies |
| --- | --- | ---: | --- |
| [02](#phase-02) | Portable streaming, filesystem behavior and operation lifecycle | 7 | Merged research; released APFS prerequisites |
| [03](#phase-03) | Remaining plist interpretation, bundle discovery and resource policy | 10 | 02 |
| [04](#phase-04) | Mach-O allocation, architectures and complete CodeDirectory profiles | 17 | 02; 03 for bundle interactions |
| [05](#phase-05) | Metadata preservation, entitlements, requirements and constraints | 17 | 03–04; authenticated evaluation also needs 07/10/11 |
| [06](#phase-06) | Identities, CMS, multiple signature slots and hybrid signatures | 7 | 04–05; legitimate native hybrid/provider evidence |
| [07](#phase-07) | Certificate policy, timestamps, revocation and portable transport | 7 | 05–06 |
| [08](#phase-08) | Generic files, native detached signatures and certificate interchange | 6 | 02–07; released APFS prerequisites |
| [09](#phase-09) | Wider and large DMG signing profiles | 1 | 02/04–08; released APFS image prerequisites |
| [10](#phase-10) | Authenticated notarization checks | 1 | 04–09; legitimate tickets/protocol evidence |
| [11](#phase-11) | Remaining CLI contracts and actual live-state/provider operations | 15 | Recorded feasibility findings; 02–10 integration |
| [12](#phase-12) | Full interaction qualification, documentation and release audit | Cross-cutting | All owners and prerequisites closed |

Feature ownership is enumerated [below](#inventory-ownership). An owner coordinates
closure; dependency work may be delivered in another phase. For example, phase 05
implements requirement grammar, but a notarization predicate cannot be called
verified before phase 10 supplies authenticated context. Every phase wires its own
CLI options immediately; phase 11 is not a backlog for unfinished earlier wiring.

Research and independently testable prerequisite preparation can overlap. Each
implementation phase starts on a fresh branch from the latest merged main.
Avoid building a stack of large unmerged implementation branches. Complete and
release shared APFS prerequisites before updating this project's dependency.

## Implementation boundaries

- Production remains pure Go without CGO, purego, custom native bindings, raw
  syscalls or subprocess fallbacks. Preserve the existing transitive dependency
  guards, including their Darwin trust-bridge exclusions. Native C/C++/Objective-C,
  Clang, Apple frameworks and Apple tools are research/acceptance tools only.
- Keep Cobra/Viper for the CLI and GoReleaser for production builds and archives.
  Preserve the established Release Please/release workflows and golangci-lint.
- APFS owns reusable filesystem/metadata primitives, AppleDouble/resource forks,
  image models/codecs, decryption and segment reconstruction. Audit its released
  public APIs first. Codesign owns representation selection, signature policy and
  operation ordering; do not copy an upstream implementation into this repository.
- `pkg/plist` owns shared plist decoding/encoding and native string interpretation.
  `pkg/codesign` owns signing schemas, requirements and authenticated interpretation;
  `internal/cli` owns arguments, output and exit policy. Share format primitives
  without merging distinct trust or operation contracts.
- Preserve existing byte APIs, caller ownership and explicit-trust guarantees.
  Add context-aware, known-size seekable/streaming interfaces without silently
  changing existing allocation, mutation or trust behavior. Represent omitted,
  explicitly empty and explicitly zero metadata options separately.
- Use one native-compatible policy across all three hosts. Explicit AppleDouble
  carriers and, where needed, logical filename representations supply metadata
  that a host cannot store directly; they are not alternate permissive policies.
  Do not auto-discover unrelated sidecars or silently rename unrepresentable names.
- Model architecture slices, CodeDirectories, SuperBlob slots and native signature
  slots separately. Extend reports without assuming one chain/signature per slice.
  Keep integrity, requirements, chain trust, timestamps, tickets and live runtime
  state separate, with authenticated inputs to evaluators.
- Native crashes or unsafe behavior do not justify reproducing a crash. A necessary
  safe divergence remains an explicit full-parity gap. Correct unsupported errors,
  snapshots and successful parsing do not count as implementing an operation.

## Evidence and test-data contract

Extend the existing [research scripts](../scripts/), [specifications](../spec/),
[test fixtures](../testdata/), [acceptance suite](../acceptance/) and
[testing harness](testing.md). Keep existing native capture and foreign-producer
verification; do not replace them with Go-generated expected values.

For every new behavioral family, create a versioned case manifest before its
implementation. Use stable case IDs shared by native probes, portable replay,
mutation tests, CI exports and the final audit. A manifest row must include:

| Field group | Required information |
| --- | --- |
| Scope | Phase, inventory IDs, operation, representation, option combination, purpose and unqualified neighboring cases |
| Oracle | macOS/build/architecture, binary/manual hashes, SDK and Clang versions/targets, filesystem, locale, timezone and evaluation time |
| Source | Pinned repository revision, source/header hashes, complete body names/ranges, translation-unit hash, preprocessing options, declared shims and unavailable/private dependencies |
| Inputs | Exact bytes or reproducible public fixture references/hashes; argument vector, working-directory relationships, nonsecret environment, setup and selected trust/provider inputs |
| Observation | Raw stdout/stderr, exit status or signal, all output bytes/hashes, extracted files, selected metadata and complete before/after tree manifest |
| Filesystem | Relevant modes, ownership, ACLs, xattrs/forks, timestamps, file identity/link count, symlink text, temporary objects, cleanup and committed partial state |
| Failure | Injected checkpoint, competing failures, observed precedence, cancellation point and preservation/commit invariants |
| Provenance | Probe/generator revision and transitive driver/helper hashes, fixture hashes, producer OS/Go version and tested project commit |
| Comparison | Exact fields, explicitly permitted nondeterministic fields, independently checked invariants and the complete observed native outcome profiles |
| Qualification | Native executed, portable replay executed, synthetic negative, source-only hypothesis or blocked; exact missing input and effect on the claim |

Separate three kinds of evidence:

1. **Static source evidence:** Clang ASTs of complete verbatim Apple bodies plus
   SDK declarations/layouts explain code paths. Declaration shims permit analysis;
   they do not execute Apple's private policy. Analyze both arm64 and x86_64
   Darwin targets, but do not claim Intel runtime evidence from cross-compilation.
2. **Native execution:** Clang-built research oracles and installed `codesign`,
   `csreq`, `plutil` and `hdiutil` establish observed behavior. Record framework/API
   calls made by an oracle; source-derived predictions remain hypotheses until
   execution. Public source can lag the installed binary; preserve discrepancies.
3. **Portable implementation proof:** all three OSes consume native-produced data;
   Linux and Windows produce artifacts that Apple independently checks. Supplement
   this with mutations, fault injection, fuzzing and independent cryptographic
   implementations where useful. These do not replace the native oracle.

Exhaust finite byte/codepoint/state domains where practical; use documented
boundaries and generated malformed cases for larger spaces. Never claim that a
finite corpus proves all possible inputs. Preserve complete deterministic bytes,
not just CDHashes. For randomized signatures, verify authenticated bytes, algorithm
parameters and cryptographic validity independently. For native scheduling, keep
whole observed outcomes and invariants; do not combine individually acceptable
fragments into an outcome Apple never produced. Unexplained differences remain gaps.

Include positive, negative, malformed, cancellation and interacting-option cases
for each new API and CLI path. Native permission tests need setup controls that
prove the intended denial; a privileged runner bypassing the denial is not a pass.
Retain Windows path/volume/DACL/share diagnostics without secrets. Native-only
oracle tests may run on macOS, but portable feature tests must run on every OS.
Unavailable required tools, credentials or devices are missing evidence, not
successful skips. Public fixture replay cannot prove current provider access.

## Shared acceptance dimensions

Apply these dimensions in every phase where relevant. Pairwise combinations may
cover low-risk interactions; enumerate high-risk combinations explicitly and
record why any dimension is inapplicable.

| Dimension | Required cases |
| --- | --- |
| Operations | First sign, force re-sign, verify, display/extract, remove, dry run, standalone validate/merge, repeated and multiple operands |
| Representations | Thin/FAT Mach-O, apps/bundles/framework versions, nested code, generic/xattr, detached and DMG |
| Existing state | Unsigned, valid, linker-signed, malformed, multiple directories/signature slots, old allocation larger/smaller than replacement |
| Identity/policy | Ad-hoc, supported RSA/EC, legitimate Apple-issued fixtures, new algorithms/providers; explicit roots/pins and missing/invalid trust |
| Metadata | Missing, empty, defaults, preserved, explicit override, contradictory per-slice values, malformed input and unknown fields |
| Paths/storage | Relative/absolute, aliases plus `..`, Unicode/case, broken/cyclic/external links, internal/external hard links, APFS/HFS+, Linux/Windows filesystems |
| Failures | Parse, discovery, identity, read/hash, allocate, sign/provider, network, metadata restore, commit and cleanup; failures in parents/children/siblings |
| Scale | Zero/minimal, normal, every boundary minus/at/plus one, large sparse and adversarial inputs; checked arithmetic and operation-wide budgets |
| Results | Whole bytes/tree/metadata, raw channels/status, extraction ordering, retained partial commits, no unexplained temporary objects |

Required cross-phase combinations include force + preserve + explicit override +
per-slice disagreement; deep signing + alternate versions + constraints + a late
child failure; alias + hard link + growth/shrink + dry run; multiple directories +
hash agility + selected slot + damaged alternate; expired leaf + timestamp +
explicit requirement; detached/embedded disagreement + resource change; continue +
extraction collision + failed write; and streaming + cancellation/source mutation/
disk exhaustion + metadata restoration.

<a id="phase-02"></a>
## Phase 02 — Portable I/O, filesystem behavior and lifecycle

**Deliverable:** remaining creation/open/transfer/restore/close behavior integrated
with streaming, cancellation and precise partial-failure semantics on all hosts.

- [ ] Specify context-aware `ReaderAt` plus size, output reservation, incremental
  hashing, staging and commit interfaces. Retain byte APIs as bounded convenience
  paths. Share global budgets for memory, temporary storage, open handles, parsed
  values, network work and nested children; do not multiply per-child limits.
- [ ] Audit current size/path/parser/chain/KDF limits against native-accepted
  workloads. Distinguish intentional resource budgets from unsupported formats.
  Use checked 64-bit offsets and host-int conversions before allocation or seeks;
  raising the existing in-memory ceiling alone is not streaming support.
- [ ] Complete first sign/re-sign/remove/dry-run metadata profiles: inherited ACLs,
  independent file/directory permissions, owner/mode, access/creation times,
  compression/resource-fork preservation and non-cloning filesystem fallback.
  Use released APFS APIs for the underlying operations, including Windows DACLs,
  share/rename semantics and Linux representable metadata.
- [ ] Define operation checkpoints from discovery and source access through
  allocation, signature cleanup, staging, restoration, close and commit. Complete
  inaccessible-directory, temporary-permission and new/existing-envelope cases.
  Preserve native differences between replacement and in-place writers.
- [ ] Resolve broader asynchronous siblings, planning failures, parent suppression
  and `--single-threaded-signing`. Capture native dispatch/commit order and whole
  observed failure states; serial implementation alone does not establish the
  option's contract. Keep unrelated sibling commits where native permits them.
- [ ] Cover source identity/content changes between discovery, hashing and commit,
  including rooted containment, aliases and internal/external hard links. Define
  the last cancellable boundary and unavoidable partial commits. Do not promise
  whole-bundle atomicity where neither native nor the filesystem provides it.
- [ ] Complete `--preserve-afsc` and other compression interactions from observed
  option applicability. Keep representation-specific dry runs and signing/removal
  side effects distinct; do not infer that every dry run avoids writes.

**Dependency integration gate:** qualify published APFS v0.17.1 with the complete
three-OS harness. The [filesystem controls](portable-io-lifecycle.md) now pass
locally, including 108 mounted comparisons of standalone and rooted bundle writers.
Keep source-preserving SDK transport distinct from the still-unqualified native
operation metadata profiles. No complete Phase 02 family is closed by this fix.

**Source/oracles:** Apple `signer.cpp`, `signerutils.cpp`, disk-representation bodies,
`codesign_alloc.cpp`, `copyfile.c`, authorization source and existing writer/path/
removal AST drivers. Retain independent native permission controls and metadata
snapshots; shared filesystem fixes require the APFS native harness as well.

**Data points:** every checkpoint with cancellation/short write/disk full/close or
restore failure; file versus directory denial; ACL inheritance; new/stale envelopes;
APFS and HFS+ write strategies; Windows open handles and readonly attributes;
changed source identity; deep children and siblings; sparse inputs across old and
32-bit size boundaries. Record bytes, inode/link identity, timestamps and cleanup.

**Exit:** owned operations have matching qualified commit/failure behavior, measured
bounded memory and portable execution. Any required APFS extension is released and
consumed before this phase's PR is ready to merge.

<a id="phase-03"></a>
## Phase 03 — Plists, discovery and resource policy

**Deliverable:** remaining metadata/discovery/resource families implemented together,
using `pkg/plist` and the common lifecycle, rather than separate encoding PRs.

- [ ] Enumerate and close remaining native multibyte/stateful codecs and aliases,
  including GB18030 and other ISO-2022 families where accepted. Retain all delivered
  UTF, legacy, Shift-JIS, EUC-JP and JP/JP-1/JP-2 evidence. Generate mapping/state
  data from independent native observations, with attribution and reproducibility.
- [ ] Complete remaining OpenStep NUL/escape/type contexts, XML declarations/grammar/
  entities/types and binary object graphs, duplicate keys, references, widths,
  malformed lengths and normalization. Keep strict signing parsers distinct from
  removal's native interpretation/fallback policy; do not globally loosen decoding.
- [ ] Complete CoreFoundation selection/property authorization, platform overrides,
  raw plist URL retention, executable name arbitration and operation-specific
  fallback. Exercise signing, removal, display and verification independently.
- [ ] Complete flat/additional bundle layouts, nested-code locations, physical/
  Current framework paths and selectors. Preserve containment while matching root,
  intermediate and final symlinks, aliases, `..`, external links and error order.
- [ ] Resolve Unicode normalization, case matching and filesystem-dependent names.
  Provide an explicit logical representation where Windows cannot store a valid
  native name; prove export/restoration against Apple. Unsupported direct-host
  names remain a documented limitation until that route works, not silently renamed.
- [ ] Complete v1/v2 resource rules: weighting/precedence, omission, optionality,
  localization, nested requirements/digests and custom/deprecated specifications.
  Determine `--seal-root`, `--verify-resource` and `--deep-verify` from source and
  native probes; do not guess semantics from option names.
- [ ] Close remaining strict/no-strict selectors, outer scopes, sideband and
  ignore-resources interactions. Extend the existing `--strip-disallowed-xattrs`
  implementation for unqualified profiles, failure timing and deep traversal;
  do not reimplement its already delivered native/explicit-carrier behavior.
- [ ] Resolve or retain explicit native ordering and mixed-primary-error differences.
  Preserve duplicates and full grouped details. Keep malformed-set and quiet
  acceptance differences visible until independently qualified structural policy
  resolves them; sorting text cannot establish native scheduling parity.

**Source/oracles:** `CFBundle.c`, `CFBundle_InfoPlist.c`, `CFPropertyList.c`,
`CFOldStylePList.c`, `CFBinaryPList.c`, `CFStringEncoding*`, `CFICUConverters.c`,
`CFBuiltinConverters.c`, `CFDictionary.c`, Unicode helpers, `bundlediskrep.cpp`,
`StaticCode.cpp` and resource bodies. Extend existing extraction/probe families;
use Clang-built CF oracles plus `plutil` and whole native `codesign` operations.

**Data points:** exhaustive feasible codec units/states, alias equivalence and
intentional differences, reset/flush/partial-unit and buffer boundaries; complete
values as well as byte observations; duplicate/malformed plist graphs; selected
metadata location × layout × operation; Unicode/case aliases, cycles and permission
contexts; rule conflicts and every strict selector; multiple directory/slot nested
seals. Every portable artifact needs both foreign-producer results.

**Exit:** the remaining family checklist is exhausted or each unresolved case is
explicitly retained. No unsupported codec is changed to success without native
stream and operation evidence. Resource verification remains distinct from discovery.

<a id="phase-04"></a>
## Phase 04 — Mach-O allocation and CodeDirectories

**Deliverable:** native-supported architecture/layout/digest profiles across parsing,
allocation, writing, verification, removal and display, including large offsets.

- [ ] Complete thin/FAT32/FAT64, 32/64-bit, endian and legitimate CPU/subtype cases.
  Implement native architecture aliases/numeric selectors, duplicates, absent
  slices, defaults and `--all-architectures`/`--edit-arch` interactions. Preserve the
  explicit arm64 reference default across hosts; qualify Intel defaults separately.
- [ ] Support insufficient load-command padding by relocating every affected
  structure, not just moving `LC_CODE_SIGNATURE`. Preserve segment/section mapping,
  relocations, symbol/string tables, dynamic-link data, alignment and zero fill.
  Cover nonterminal signatures, trailing/opaque data and native removal behavior.
- [ ] Complete versioned CodeDirectory fields and semantics: scatter, 64-bit limits,
  executable segments, runtime, platform, linkage, pre-encrypt and newer evidenced
  fields. Use wire offsets independent of C struct padding; reject invalid counts,
  overlaps and overflow before reading or allocating.
- [ ] Complete digest families/truncation, legacy selection, repeated digest
  families, preferred CDHash and both CMS hash-agility bindings. Associate a
  directory with its slice and signature slot rather than only a digest name.
- [ ] Complete page sizes, option masks/names and runtime-version parsing, including
  zero/special values, final partial pages and representation applicability.
  Model special slots with presence/empty/zero/external binding separately.
- [ ] Implement remaining private/legacy options only from evidence: full-metal-
  jacket, pre-encrypt generation/validation, legacy/no-legacy, no-macho, omitted
  ad-hoc flag, platform identifier and signature reservation. Retain accepted but
  ignored behavior only where the operation matrix proves it.
- [ ] Extend two-pass reservation for growing signatures, variable-length algorithms,
  multiple directories and future signature slots. Propagate directory selection
  into resources, requirements, display, detached signatures and ticket lookup.

**Source/oracles:** `codesign_allocate.c`, `codesign_alloc.cpp`, `macho++.cpp/.h`,
`machorep.cpp`, `codedirectory.cpp/.h`, `sigblob.cpp/.h`, `superblob.h` and SDK
`cs_blobs.h`. Compare Clang layouts with actual serialized bytes and native outputs.

**Data points:** legitimate legacy files; padding/alignment limits; slice ordering;
32-bit and 4 GiB offset boundaries via streaming fixtures; growth/shrink/removal;
every field/hash/special-slot mutation; missing/duplicate alternates; malformed
load commands; metadata preservation during relocation. A valid alternate must
not hide damage in a directory that native requires.

**Exit:** each claimed format supports all applicable operations and exact
allocation/binding behavior; merely displaying a field does not qualify its policy.

<a id="phase-05"></a>
## Phase 05 — Metadata, entitlements, requirements and constraints

**Deliverable:** complete metadata precedence and authenticated policy formats,
with native compilation/rendering and operation-specific validation.

- [ ] Add presence-aware preservation selectors and resolve explicit override >
  selected preserved value > native default where independently observed. Test
  identifier/prefix, flags/runtime, entitlements, requirement sets, constraints
  and other evidenced fields separately, including per-slice disagreements and
  parent/child inheritance. Preserve caller ownership and existing byte APIs.
- [ ] Complete identifier/prefix sources and Team ID assignment/display/preservation.
  Coordinate authenticated Team ID/Apple marker decisions with phase 07; familiar
  names, subject OU values or unverified extensions cannot establish Apple identity.
- [ ] Complete native entitlement types, integer widths, ordering, duplicates,
  Unicode, XML preservation and DER versions. Establish XML/DER preference for
  each operation, mismatched/missing slots and special transformations. Retain
  baseline CLI rejection of binary entitlement input unless new native evidence
  changes it; a library conversion extension is a different contract.
- [ ] Complete library-entitlement applicability and DER-generation defaults/no-op
  behavior by representation, preservation and deep signing. Extend raw/decoded
  extraction and unknown DER type/version handling without conflating parsing
  success with authenticated entitlement values.
- [ ] Complete the remaining requirement lexer/parser, opcodes, binary forms,
  canonical rendering and evaluator: precedence, escapes/comments, date/numeric
  literals, certificate positions/fields/extensions/policies, existence/absence,
  ordering/string predicates, Info.plist and entitlement contexts. Complete stdin,
  source/file/binary inputs, `$self.identifier` and exact syntax diagnostics. Retain
  the existing five named requirement kinds and numeric-set support.
- [ ] Complete designated/default requirement synthesis by identity/representation,
  including interpreter and `LC_DYLIB_CODE_SIGN_DRS` cases, preservation and explicit
  overrides. Preserve whole sets rather than flattening to a designated expression.
- [ ] Supply typed authenticated evaluation contexts for Apple anchors, platform,
  notarization and dynamic predicates. Distinguish false, malformed and unavailable
  evaluation. Do not return true for unavailable state; phase 07/10/11 supplies the
  missing context before affected inventory entries can close.
- [ ] Implement self/parent/responsible/library constraints, category and designated
  LWCR behavior from versioned native schemas. Establish typed plist-to-DER rules,
  correct special slots, unknown keys/operators and canonical ordering rather than
  assuming entitlement DER is interchangeable.
- [ ] Implement standalone constraint validation, enforcement warning/error policy,
  validation timing, preservation and deep inheritance. Distinguish schema validity,
  authenticated binding and actual runtime enforcement. Match the `codesign`
  operation; do not claim Linux/Windows enforce Apple's kernel launch policy.

**Source/oracles:** requirement grammar/generated parser, `reqparser.cpp`,
`reqdumper.cpp`, `requirement.h`, `drmaker.cpp`, `CodeSigner.cpp`, `StaticCode.cpp`,
SDK constraints/entitlement declarations and available implementation bodies.
Use `csreq`/`codesign` mutual compile/decompile/evaluation plus Clang-built oracles
where private framework behavior has no CLI observation. Record unavailable bodies.

**Data points:** every remaining grammar/opcode/type; native binary bytes and text;
true/false/malformed/missing-context predicates; empty/explicit/preserved metadata;
XML-only/DER-only/contradictory slots; nested collections and budget exhaustion;
constraint schemas and all slots; selected architecture and deep inheritance;
warning/failure precedence before mutation. Do not equate semantically similar
requirement text with native canonical output.

**Exit:** format, selection and applicable CLI operations have independent evidence;
affected trust/live-context obligations stay open until their dependencies close.

<a id="phase-06"></a>
## Phase 06 — Identities, CMS and hybrid signature slots

**Deliverable:** remaining identity interoperability and native signature-container
profiles, with real algorithm/provider evidence and separately addressable slots.

- [ ] Complete encrypted PEM/PKCS#8 and required PKCS#12 content/bag/cipher/MAC
  profiles using reviewed portable cryptography. Specify password encoding,
  empty/absent/password-file behavior, authentication and KDF budgets. Keep file
  identity inputs explicitly distinct from native keychain search semantics.
- [ ] Support explicit selection in multi-identity archives, friendly names/local
  key IDs, duplicates and extra/cross-signed chains. Prove the selected key matches
  its leaf. Preserve the current unambiguous single-identity contract; do not
  silently choose a different first key or treat archive order as trusted chain order.
- [ ] Complete native CMS BER/DER forms, SignerInfo/SignedData versions and identifier
  forms, algorithms/parameters, attributes, certificate choices, countersignatures
  and CRLs where native accepts them. Retain original authenticated bytes: parser
  normalization must not repair invalid signed content into a passing signature.
- [ ] Complete hash-agility attributes for multiple/repeated digest directories and
  slot associations. Validate absent versus NULL algorithm parameters, RSA-PSS
  where accepted, duplicate attributes, ambiguous certificates and complete bindings.
- [ ] Implement `--edit-cms`, `--dump-cms`, `--signing-data` and signing-time semantics
  from the operation matrix, including raw output, edit integrity, input ownership,
  allocation and failure behavior. Do not infer private formats from names.
- [ ] Implement native signature-slot numbering, selection/default preference and
  report models, distinct from slices/SuperBlob slots. Probe absent, duplicate and
  out-of-range slots and mixed old/new signatures.
- [ ] Complete hybrid/PQC algorithms, certificate structures, binding, downgrade
  policy and provider selection only with legitimate native-created fixtures and
  independent algorithm vectors. Select reviewed pure-Go components; do not guess
  an OID/algorithm or translate unreviewed cryptographic arithmetic.
- [ ] Integrate larger keys/signatures/chains with streaming/reservation and timestamp
  imprint budgets. Define signer callback capabilities, signature encodings and
  cancellation limits. Actual remote/hardware access remains phase 11 work.

**Source/oracles:** CMS/ASN.1 and signing bodies, `cmsasn1.c`, SDK CMS interfaces and
native slot evidence. Extend existing certificate/CMS extraction. Obtain independent
OpenSSL/LibreSSL/platform archive vectors and native import/signature comparisons;
legitimate restricted-provider evidence is a phase 01 prerequisite, not a final surprise.

**Data points:** independent archive exports; correct/wrong/empty passwords; multiple
keys, mismatches, duplicate bags and KDF exhaustion; BER nesting/indefinite lengths;
algorithm parameters and signed-byte mutations; native deterministic RSA bytes;
independently verified randomized signatures; classical/PQC component damage,
downgrade attempts, slot selection and allocation boundaries. Keep public test
identities only in fixtures; do not log private material or promise Go heap erasure.

**Exit:** actual supported identities can sign and verify under native slot policy.
Parsing a hybrid fixture without producing/validating its required components does
not close hybrid signing; unavailable credentials remain an explicit prerequisite.

<a id="phase-07"></a>
## Phase 07 — Trust, timestamps and network policy

**Deliverable:** remaining native operation-specific trust decisions and transport,
while retaining the library's explicit-trust guarantees.

- [ ] Finish the operation policy table separating integrity, implicit/self/caller
  requirements, certificate-chain validity/trust, timestamp validity, expiration,
  revocation and notarization. Keep quiet versus verbose policy and per-architecture
  failure order explicit. Do not silently weaken callers requiring supplied roots/pins.
- [ ] Complete evidenced chain construction and validation: alternate/cross-signed
  paths, name comparison, self-issued versus self-signed, critical extensions,
  constraints/path length, policies, key usage/EKU and weak/legacy algorithms.
  Bound graph search across the entire operation.
- [ ] Complete authenticated Apple marker and Team ID policy: missing/duplicate OU,
  leaf/directory/nested agreement, real Developer ID and other legitimate Apple
  fixtures. Synthetic look-alikes remain negative controls, never positive proof.
- [ ] Implement check-expiration/revocation, software-signing-certificate validation,
  skip-root-exception, skip-validation and no-TSA-cert behavior as observed. Do not
  assume software-update validation is an identity-selection flag.
- [ ] Complete timestamp defaults by identity and representation: omitted/bare/URL/
  none, preserved metadata, dry runs, repeated architectures and nested code.
  Preserve provider calls and allocation ordering until native evidence justifies
  changing them. Imported-token verification and nonce-bound acquisition differ.
- [ ] Extend TSTInfo/ESS/BER policy: supported IDs/names/OIDs/extensions, fractional
  time, accuracy/ordering, nonces, certificate validity, skew and trusted evaluation
  time. Reuse phase 06 CMS handling; do not create a second inconsistent verifier.
- [ ] Complete native-required proxy/redirect/authentication/framing/compression,
  DNS/IPv6, retry, timeout and cancellation behavior. Audit secure transport needed
  for issuer/revocation/notary services under the existing production dependency
  guard; adding `net/http`/`crypto/tls` is not implicitly permitted.
- [ ] Preserve the recorded native-baseline rejection of HTTPS TSA URLs. That is
  not automatically a missing TSA feature; authenticated service transport is a
  separate requirement. Add issuer retrieval, OCSP/CRL, caches/freshness and offline
  hard/soft failure only where the native operation requires them.

**Source/oracles:** certificate/policy/signature verification source,
`tsaSupport.c`, `tsaTemplates.c/.h`, `timestampclient.m` and existing timestamp/HTTP
extractors. Use controlled local protocol servers, recorded tokens and legitimate
Apple public chains; isolate evaluation time/trust inputs from changing host state.

**Data points:** alternate issuers and ambiguous subjects; every relevant critical
extension/policy; expired/future/revoked leaves and TSA chains; missing intermediates;
trusted/untrusted timestamps crossing validity boundaries; malformed/partial
responses, redirects/proxies/retries and cancellation; dry-run call counts; cache
freshness/offline failures and exact policy diagnostics.

**Exit:** defaults, transport, cryptographic binding and trust each have completed
matrices. Offline replay proves replay behavior, not current service availability;
a native signature check does not establish Gatekeeper acceptance.

<a id="phase-08"></a>
## Phase 08 — Generic files and detached interchange

**Deliverable:** native generic signing/display/verification and detached containers,
including detached-certificate input/output/merge policy on every host.

- [ ] Extend the existing generic removal/discovery implementation to signing,
  inspection and verification, with native attached xattr/fork representations,
  resource binding, identifier/default requirement behavior and operation dispatch.
- [ ] Implement native detached signature containers, object indexes, architecture
  binding, replacement and selection precedence against embedded/xattr signatures.
  Do not substitute another project's custom detached format for Apple's format.
- [ ] Complete detached-certificate formats and linkage to chains/slots. Establish
  ordering, duplicates, missing components and malformed data; concatenated PEM
  is not assumed to be the native interchange format.
- [ ] Implement root-retention and certificate merge using native classification,
  deduplication and output rules. Distinguish self-issued, self-signed and trusted
  root properties; preserve cross-signed variants where native does.
- [ ] Integrate preservation, timestamps, requirements, digests, extraction/file-list
  side effects, output collisions, cancellation and partial writes. Maintain rooted
  identity checks and unrelated metadata/data-fork preservation through APFS APIs.
- [ ] Prove explicit AppleDouble carrier export/restoration against real native
  attached metadata. Add any genuinely missing reusable primitive upstream and
  consume its release; native database registration is separately owned by phase 11.

**Source/oracles:** `diskrep.cpp`, `filediskrep.cpp`, `singlediskrep.cpp`, generic and
external signature representations, `sigblob.cpp`/`superblob.h` and native fixtures.
Extend generic-removal and sideband research without regressing their qualified cases.

**Data points:** empty files, scripts, ordinary data and objects; xattr/sidecar
conflicts; foreign restored metadata; embedded/detached disagreement; wrong object
or architecture index; missing chains; repeated/duplicate/cross-signed certificate
inputs; readonly/output collisions; partial merge failures and preserved old output.

**Exit:** native/Go interchange works in both directions for applicable operations;
carrier support supplies metadata faithfully and does not claim live database access.

<a id="phase-09"></a>
## Phase 09 — Wider and large disk images

**Deliverable:** native-supported DMG signing beyond the bounded in-memory adapter,
using APFS's public image APIs and the shared streaming/policy layers.

- [ ] Audit current APFS APIs and complete ReaderAt/size inspection, incremental
  hashing and native in-place/staged writes. Preserve opaque compressed payload;
  appending a signature must not cause unnecessary decompression/recompression.
- [ ] Qualify encrypted, segmented, sparse and other native-accepted image forms.
  Determine when an operation requires passwords, all segments or filesystem
  decoding before designing adapters. Keep codecs, decryption and reconstruction
  in APFS, with released and tested upstream prerequisites.
- [ ] Complete signed-byte ranges, footer/trailer canonicalization, resource plist,
  special slots, trailing data and old allocation rules with checked 64-bit math.
  Extend supported profiles without removing overlap/length/flag validation.
- [ ] Complete image applicability for identity/digest/page size, identifier,
  preservation, entitlements/constraints, timestamps, detached signatures and
  architecture options. Investigate broader certificate dry-run behavior and
  diagnostics; retain recorded signal/crash profiles as safe divergences until resolved.
- [ ] Retain native DMG removal rejection on the reference baseline. A custom image
  remover is not parity. Keep signature validity separate from mountability,
  decryption, notarization and Gatekeeper policy.

**Source/oracles:** `diskimagerep.cpp`, `signer.cpp`, existing DMG extraction,
APFS image sources and `hdiutil` native fixture generation/inspection. Reuse and
extend the established APFS/HFS+ commercial image corpus; pin versions, hashes and
redistribution constraints. An upstream fixture-generator defect is not evidence
that an independently created image cannot be signed.

**Data points:** large/sparse and >4 GiB offsets; multiple compression/encryption/
segment forms; unsigned/replaced signatures; footer/resource/trailer mutations;
cancellation, disk-full and permissions; complete chunk-manifest byte comparison;
measured peak memory; Apple verification of Linux/Windows outputs.

**Exit:** the accepted image matrix has bounded-memory operation and exact native
binding/write behavior; all required APFS work is released before adoption.

<a id="phase-10"></a>
## Phase 10 — Notarization checks

**Deliverable:** authenticated native `--check-notarization` behavior, not a claim
that chain trust or an ordinary signature check establishes notarization.

- [ ] Complete source/protocol/ticket research begun in phase 01: discovery,
  object identifiers, request/response formats, trusted roots, lookup/cache and
  forced-online behavior for Mach-O, bundles and DMGs.
- [ ] Implement ticket parsing and cryptographic/content binding separately from
  retrieval. Match selected architecture, CodeDirectory and signature slot;
  reject a valid ticket for different code and unauthenticated positive responses.
- [ ] Implement required lookup, cache/freshness, offline and revoked/unknown/
  rejected/error behavior using phase 07's audited portable transport. Replay
  must not stand in for a native-required fresh lookup.
- [ ] Supply authenticated notarization context to requirements and complete CLI
  output/exit behavior alongside trust, timestamps and explicit predicates.
- [ ] Limit this phase to evidenced `codesign` operations. Submission, accounts and
  stapling are not automatically in scope because another Apple tool supports them.

**Source/oracles:** available Security ticket/policy code, SDK interfaces and
legitimate public notarized artifacts with recorded native results. Private formats
and credential/protocol availability must already have phase 01 prerequisite records.

**Data points:** bound/unbound/tampered/unknown-version tickets; architecture/slot
selection; expired/stale/revoked/unknown status; offline/cache/forced-online and
service errors; exact diagnostics with recorded evaluation times and cache state.

**Exit:** authenticated results reproduce the requested native check. Missing
protocol access, valid fixtures or transport keeps the feature incomplete.

<a id="phase-11"></a>
## Phase 11 — CLI closure and live-state operations

**Deliverable:** remaining cross-feature CLI behavior and real implementations of
feasible state/provider features. Research of their feasibility must not wait here.

- [ ] Complete native argument grammar: operation conflicts/defaults, short clusters,
  repeated verbosity/options, optional/equals arguments, abbreviations if accepted,
  `--`, dash-prefixed paths and parse/error precedence. Preserve Cobra/Viper while
  preventing their generic defaults from changing native behavior.
- [ ] Complete display at every verbosity, numeric errors, architecture/slot
  selection, certificates, Team IDs, timestamps, requirements, constraints and
  allocations. Match path spelling/quoting, stdout/stderr, newlines and exit codes.
- [ ] Resolve locale/calendar/timezone differences, including retained hosted date
  profiles, without broad output normalization. Separate each qualified native
  environment; do not claim one machine establishes every locale/version.
- [ ] Complete multi-operand continue/abort and aggregate statuses, file lists,
  certificate/entitlement/requirement/CMS extraction, destination prefixes,
  truncation/append modes, collisions and partial-output ordering.
- [ ] Complete numeric process-versus-file routing, including explicit relative
  filenames. Match live hosting/verification only with actual process state and
  identity, PID reuse/races, loaded code and dynamic invalidation; file verification
  or a caller-supplied snapshot is insufficient.
- [ ] Implement feasible keychain, hardware and remote providers through permitted
  pure-Go interfaces with real authorized access. Preserve key non-exportability,
  search/selection order and authorization errors. Never prompt against unrelated
  user keychains merely to make a test case pass.
- [ ] Complete native detached database schema, matching/precedence, transactions,
  permissions and persistence using isolated state. An offline codec alone cannot
  establish registration in the actual system database.
- [ ] Resolve exact signing-dylib and allocator-override contracts against the
  production boundary. A built-in allocator matching default output cannot also
  claim arbitrary helper execution. Preserve unresolved conflicts as blockers.

The eight existing blocked entries require the following evidence:

| Entry | Missing prerequisite to close it |
| --- | --- |
| `--hosting` | Actual authorized host/guest process state and dynamic ordering, accessible under the allowed runtime boundary |
| `live-process-verification` | Actual loaded-code/kernel signing state, target identity and race handling; an on-disk signature is insufficient |
| `--keychain` | Real search lists, preferences, scope, duplicate selection, unlock/ACL decisions and usable protected-key access |
| `--detached-database` | Actual native database access/update semantics and observable effect; offline replay proves only the format |
| `hardware-identities` | The real device/service and authorized signing operation through a permitted implementation |
| `--remote-signing` | The actual protocol/provider, identity and authorization, with matching failure and cancellation behavior |
| `--signing-dylib` | A resolution of native arbitrary-library execution versus the no-native-binding requirement |
| `CODESIGN_ALLOCATE` | A resolution of arbitrary external allocator execution versus the no-production-helper requirement |

Maintain the [recorded prerequisite classifications](research-phase.md) and resolve
their concrete external inputs or conflicts with the original constraints. A
macOS bridge/service would change
the objective and cannot silently resolve a zero-macOS-dependency requirement.
Implement all feasible behavior within the constraints; keep unsupported state
explicit and preserve the blocker until the required capability exists.

**Source/oracles:** installed manual/parser behavior, available `cs_utils.cpp`,
`dispatch.cpp`, `cserror.cpp`, dynamic-code/provider/database sources and SDK APIs.
The pinned systemkeychain utility source is not assumed to be the current CLI
parser. Use isolated harmless processes/stores and authorized test providers only.

**Data points:** the complete operation/argument/error matrix; repeated extraction
and collisions; locale profiles; process/PID reuse; keychain preference/duplicate/
locked-store behavior; denied/cancelled provider calls; database precedence and
persistence; actual helper selection behavior where research can safely observe it.

**Exit:** all owned entries have full evidence or remain explicitly blocked. Do
not replace real behavior with a successful no-op, simulation or portable snapshot.

<a id="phase-12"></a>
## Phase 12 — Full-objective qualification and documentation

**Deliverable:** a defensible final parity decision based on the exact code and
artifacts being released, including every original obligation and discovered delta.

- [ ] Re-run the entire applicability and high-risk interaction matrix against the
  declared native profiles and every portable OS. Re-enumerate manual/parser/SDK
  inputs for newly discovered options and environment behavior. Preserve all
  original obligations when splitting umbrella entries into subprofiles.
- [ ] Close inventory entries only when all applicable operations, negative cases,
  interactions and dependencies are independently verified. Statement coverage,
  parser recognition and success on one fixture are separate from feature closure.
- [ ] Qualify all six packaged OS/architecture targets. Inspect linked dependencies,
  CGO status, version/APFS pins, checksums and SBOMs; perform executable smoke and
  feature tests on actual matching runtimes. Cross-compilation alone does not prove
  target runtime behavior. Add runners/emulation with declared limits as needed.
- [ ] Audit final-commit CI artifacts: source hashes for each checkout, fresh native
  observations, both foreign producers, complete case manifests, coverage per OS,
  race/fuzz, guards, lint and package contents. A stale green commit or cancelled
  upload/import job cannot qualify the final tree.
- [ ] Reconcile API comments, CLI help, README, focused guides, compatibility tables,
  examples and migration notes with actual behavior. Describe storage/name/size,
  trust/network/provider and native-version requirements; distinguish extensions
  from native CLI behavior. Retain source/reference license attribution.
- [ ] Remove completed tasks from this roadmap and retain their evidence in focused
  guides/PR records. Keep current inventory counts mechanically reconciled; avoid
  summing historical fixture counts as if they were disjoint current totals.
- [ ] Run `make release-check` with its complete-inventory requirement intact.
  Do not remove blocked entries, bypass guards or set `full_parity` just to release.
  Any unresolved behavior, unavailable required context or deliberate safe
  divergence means the original full-equivalence objective remains incomplete.
- [ ] After user-authorized release, verify downloaded archives, checksums/SBOMs and
  signed-checksum provenance against the expected repository/workflow identity.
  Continue to label supported-subset releases as partial until every gate is met.

**Exit:** current code, native evidence, all portable runtimes and shipped artifacts
support every full-parity claim. If a constraint prevents completion, report the
specific unresolved obligation rather than declaring a narrower objective complete.

<a id="delivery-status"></a>
## Phase delivery contract

For each phase, complete these gates before requesting merge:

1. Cut a fresh branch from merged main. Define the owned remaining behaviors and
   prerequisite releases; keep unrelated local work intact.
2. Complete its case manifest, pinned source/Clang research and native captures.
   Investigate contradictory observations before implementing their expected policy.
3. Implement the complete subsystem phase, including portable APIs, CLI behavior,
   malformed inputs, cancellation/cleanup and important interactions. Extend the
   existing harness; do not defer its difficult cases to make the PR smaller.
4. Keep every existing gate and add meaningful tests for the new behavior. Require
   strict >95% coverage for every production package on each OS, complete native
   capture/imports, all fuzz/race checks, guards, lint and GoReleaser packaging.
5. Update source/fixture manifests, focused documentation and the compatibility
   inventory in the same PR. Remove only completed roadmap tasks; retain any
   residual profiles with explicit ownership and dependencies.
6. Commit and push all reviewed work so the IDE branch matches the PR. Use ordinary
   conventional commit titles without `!` or unintended breaking-change markers.
   Open the PR **as a draft**, with concrete behavior, evidence and remaining gaps.
7. Wait for all required CI on the final commit, inspect its artifacts and report
   readiness. A new commit invalidates stale final evidence. The user merges;
   do not merge, publish or start the next implementation branch from an unmerged PR.

The normal target is one draft PR per phase. Split only for an independently
reviewable dependency, an evidenced size/risk boundary or an upstream release;
explain the remaining phase scope. A dependency PR does not count as finishing
its consumer. Do not return to one native encoding or tiny discovery case per PR.

<a id="inventory-ownership"></a>
## Inventory ownership

Each existing ID below has exactly one accountable phase. Status is copied from
`spec/compatibility.json` at the planning baseline, not upgraded by this roadmap.
Cross-phase dependencies are specified above. Phases 01 and 12 apply to all rows.

| Inventory ID | Current status | Accountable phase |
| --- | --- | --- |
| `--sign` | partial | [02](#phase-02) |
| `--remove-signature` | partial | [02](#phase-02) |
| `--force` | partial | [02](#phase-02) |
| `--deep` | partial | [02](#phase-02) |
| `--dryrun` | partial | [02](#phase-02) |
| `--single-threaded-signing` | not-implemented | [02](#phase-02) |
| `--preserve-afsc` | not-implemented | [02](#phase-02) |
| `bundles` | partial | [03](#phase-03) |
| `--bundle-version` | partial | [03](#phase-03) |
| `--ignore-resources` | partial | [03](#phase-03) |
| `--strict` | partial | [03](#phase-03) |
| `--no-strict` | partial | [03](#phase-03) |
| `--strip-disallowed-xattrs` | partial | [03](#phase-03) |
| `--resource-rules` | not-implemented | [03](#phase-03) |
| `--seal-root` | not-implemented | [03](#phase-03) |
| `--verify-resource` | not-implemented | [03](#phase-03) |
| `--deep-verify` | not-implemented | [03](#phase-03) |
| `--all-architectures` | partial | [04](#phase-04) |
| `--architecture` | partial | [04](#phase-04) |
| `--options` | partial | [04](#phase-04) |
| `--pagesize` | partial | [04](#phase-04) |
| `--runtime-version` | partial | [04](#phase-04) |
| `--digest-algorithm` | not-implemented | [04](#phase-04) |
| `--edit-arch` | not-implemented | [04](#phase-04) |
| `--full-metal-jacket` | not-implemented | [04](#phase-04) |
| `--generate-pre-encrypt-hashes` | not-implemented | [04](#phase-04) |
| `--legacy-signing` | not-implemented | [04](#phase-04) |
| `--no-legacy-signing` | not-implemented | [04](#phase-04) |
| `--no-macho` | not-implemented | [04](#phase-04) |
| `--omit-adhoc-flag` | not-implemented | [04](#phase-04) |
| `--platform-identifier` | not-implemented | [04](#phase-04) |
| `--signature-size` | not-implemented | [04](#phase-04) |
| `--validate-pre-encrypt-hashes` | not-implemented | [04](#phase-04) |
| `legacy-formats` | not-implemented | [04](#phase-04) |
| `--force-library-entitlements` | partial | [05](#phase-05) |
| `--generate-entitlement-der` | partial | [05](#phase-05) |
| `--identifier` | partial | [05](#phase-05) |
| `--entitlements` | partial | [05](#phase-05) |
| `--requirements` | partial | [05](#phase-05) |
| `--test-requirement` | partial | [05](#phase-05) |
| `--prefix` | not-implemented | [05](#phase-05) |
| `--preserve-metadata` | not-implemented | [05](#phase-05) |
| `--launch-constraint-self` | not-implemented | [05](#phase-05) |
| `--launch-constraint-parent` | not-implemented | [05](#phase-05) |
| `--launch-constraint-responsible` | not-implemented | [05](#phase-05) |
| `--library-constraint` | not-implemented | [05](#phase-05) |
| `--enforce-constraint-validity` | not-implemented | [05](#phase-05) |
| `--validate-constraint` | not-implemented | [05](#phase-05) |
| `--constraint-category` | not-implemented | [05](#phase-05) |
| `--designated-lwcr` | not-implemented | [05](#phase-05) |
| `--team-identifier` | not-implemented | [05](#phase-05) |
| `certificate-signing` | partial | [06](#phase-06) |
| `hybrid-pqc` | not-implemented | [06](#phase-06) |
| `--signature-slot` | not-implemented | [06](#phase-06) |
| `--edit-cms` | not-implemented | [06](#phase-06) |
| `--dump-cms` | not-implemented | [06](#phase-06) |
| `--signing-data` | not-implemented | [06](#phase-06) |
| `--signing-time` | not-implemented | [06](#phase-06) |
| `--timestamp` | partial | [07](#phase-07) |
| `--check-expiration` | not-implemented | [07](#phase-07) |
| `--check-revocation` | not-implemented | [07](#phase-07) |
| `--use-software-signing-cert` | not-implemented | [07](#phase-07) |
| `--no-tsa-certs` | not-implemented | [07](#phase-07) |
| `--skip-root-exception` | not-implemented | [07](#phase-07) |
| `--skip-validation` | not-implemented | [07](#phase-07) |
| `generic-files` | partial | [08](#phase-08) |
| `--detached` | not-implemented | [08](#phase-08) |
| `--input-detached-certificates` | not-implemented | [08](#phase-08) |
| `--output-detached-certificates` | not-implemented | [08](#phase-08) |
| `--keep-root-detached-certificates` | not-implemented | [08](#phase-08) |
| `--merge-detached-certificates` | not-implemented | [08](#phase-08) |
| `dmg` | partial | [09](#phase-09) |
| `--check-notarization` | not-implemented | [10](#phase-10) |
| `--display` | partial | [11](#phase-11) |
| `--verbose` | partial | [11](#phase-11) |
| `--verify` | partial | [11](#phase-11) |
| `--continue` | partial | [11](#phase-11) |
| `--extract-certificates` | partial | [11](#phase-11) |
| `--file-list` | partial | [11](#phase-11) |
| `--numeric-errors` | not-implemented | [11](#phase-11) |
| `--detached-database` | blocked | [11](#phase-11) |
| `--hosting` | blocked | [11](#phase-11) |
| `--keychain` | blocked | [11](#phase-11) |
| `live-process-verification` | blocked | [11](#phase-11) |
| `hardware-identities` | blocked | [11](#phase-11) |
| `--remote-signing` | blocked | [11](#phase-11) |
| `--signing-dylib` | blocked | [11](#phase-11) |
| `CODESIGN_ALLOCATE` | blocked | [11](#phase-11) |
