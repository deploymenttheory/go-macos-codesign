# Phase 02 allocation and limit audit

This is a call-site inventory for the remaining streaming work, checked against
the Phase 02 completion branch. A managed 128 MiB budget does not currently cover
every allocation in these paths. A passing virtual-reader test does not establish
native acceptance or bounded process memory for the corresponding real file.

The governing closure requirements remain in
[the implementation plan](implementation_plan.md#phase-02). This inventory is
not an alternative completion checklist with fewer requirements.

## Limits requiring qualification

| Site | Current limit or allocation | Classification and next action |
| --- | --- | --- |
| `cmsEnvelopeRanges` in `cms_range.go` | 16 MiB complete CMS message | Implementation ceiling. Held-field decoding is integrated; stream individual certificates and authenticated fields before removing it. Native capture must distinguish large individual attributes/certificates from aggregate message growth. |
| `decodeDER`, `pemBlocks` in `identity.go` | 16 MiB DER value / PEM input | Parser/import resource policy, not an established native format limit. DER is shared with certificates, requirements and timestamps. Audit callers separately; replacing the CMS outer ceiling alone does not make large certificates work. |
| `readCMSBERRange` in `cms_range.go` | Four length octets, depth 32, 4096 shared element visits in the envelope caller | Existing parser policies retained by the range refactor. Four octets cover signature-component lengths; depth/element admission still needs native qualification. Indefinite outer containers revisit nested headers, so the budget is not simply a certificate count. |
| `decodeSignedData` in `cms.go` | At most 32 embedded certificates; one signer and one digest algorithm | Existing CMS policy. Decode individual certificates without retaining an aggregate certificate-set copy; determine native admission for counts independently of bounded storage. Single-signer support must not be silently broadened without binding and trust-policy work. |
| `EncodeEntitlements` in `entitlements.go` | 16 MiB input; recursive encoding and complete returned XML/DER buffers | Existing input/owned-output policy. Stream path input and generated output while preserving owned byte API results. Native shape/size qualification and entitlement semantics remain separate requirements. |
| `parseTimestampToken` and timestamp HTTP readers | 1 MiB token/response; 32 KiB HTTP headers; additional framing/signature limits | Existing transport/parser policies. Prove native admission with the controlled TSA harness. Keep framing validation and cancellation; do not simply increase response allocation limits. Timestamp policy remains with its roadmap owner. |
| Requirement parsers, metadata and signing merge | 1 MiB expressions/sets and count/depth policies | Existing parser/owned-output policies. Ranged requirement access must preserve native parsing and diagnostic order. Parser limits require separate native controls, rather than being labelled format constraints. |
| `maxBundlePlist`, `maxBundleEntries`, `maxBundleDepth` | Plist package limits, 10,000 entries and nesting depth 8 | Existing bundle admission/storage policies. Qualify aggregate growth and discovery depth before scheduler/scaling closure. Resource-policy and layout expansion remain coordinated with the bundle phase; do not retain an unqualified size rejection as a storage solution. |
| `codeSource.read` in `source.go` | 1 GiB materialized metadata range | Implementation ceiling on a whole-value read. Range callers must stop requesting complete values when only fields/hashes are needed. Explicit public owned reads require distinct result-allocation accounting and checked host-integer conversion. |
| `materializeOutput` and owned DMG assembly | 1 GiB owned output/input ceilings | Owned byte API policy, distinct from held-source path payloads. Preserve documented ownership while qualifying caller-owned allocations separately; never route normal CLI payloads back through these helpers. |
| `superblobOutput` in `signature_output.go` | 32-bit signature length/index bounds; complete output index in memory | Encoded length bounds remain format checks. Current production callers generate known directory/requirement/entitlement/CMS slots, rather than forwarding arbitrary input indexes. Account these small allocations and preserve the caller bound; do not invent an unbounded output-index scenario. Arbitrary input indexes already use spillable `signatureIndex` sections. |
| `newWorkingSection`, `transferBuffer` | Default 128 MiB managed pool; minimum one 64 KiB transfer buffer | Deliberate operation resource policy. Persistent sections leave transfer capacity free and spill. Additional parsed/codec reservations must preserve this progress guarantee. |

Legacy `readFile`, `readFileWithAccess`, `readFileContext` and
`readOpenFileContext` in `sign.go` currently have **only test callers**. Their
1 GiB read limit must not be cited as a limit on the live standalone signing
pipeline. Removing these helpers requires migrating their access-time,
cancellation and non-regular/large-file assertions to the live source paths;
deleting the assertions is not the migration.

## Live whole-value consumers

The following consumers still materialize signature metadata even when a report
is borrowed. CMS now reads individual fields from its held component; other
consumers still request complete components. `Signature.componentBytes` delegates to the public owned `ReadBlob`
method for a `signatureView`.

| Consumer | Current data flow | Required replacement |
| --- | --- | --- |
| `InspectCertificateMetadata` / `verifyInput` in `verify.go` | Read certificate/signer fields separately from the held CMS component | Stream certificate and authenticated-attribute internals, bound parsed indexes, and account returned certificate metadata independently. Retain readable inspection when verification fails. |
| `entitlement_metadata.go` | Read complete DER or XML entitlement component | Ranged input and a bounded/planned semantic representation; preserve DER/XML selection and malformed-input precedence. |
| `requirement_text.go`, `requirement_verify.go`, `requirement_metadata.go`, requirement checks in `verify.go` | Read the complete requirements component | Ranged requirement lookup/evaluation/formatting with checked offsets, preserving requirements semantics and explicit owned output APIs. |
| `signatureView.report` | Read complete identifier and team strings, then convert each slice to a string | Avoid duplicate copies and account parsed/report storage. Scoped display needs a streaming representation for unusually large strings; owned reports still own their result. |
| `appBundle.read` / bundle resource plist handling | Bounded full plist reads, decoded maps and complete serialized envelopes | Shared-budget parsing/indexing/output for aggregate resource growth. Reuse the project's plist implementation; do not create a competing plist codec. |
| `SignCMS`, DER construction and timestamp insertion | Concatenate certificate, attribute, signer and outer envelope buffers | Generated output plans/sections with explicit ownership. Preserve original signed encodings and byte parity, including timestamp embedding. |

`BlobReader` already exposes a bounded component reader, and requirement
extraction uses it. `VisitInspection` / `VisitVerification` keep source and
scratch storage alive through the callback. Neither fact makes the consumers
listed above streamed: they must be integrated individually.

## Accounting and lifecycle dependencies

`WorkingStorageStats` currently measures reserved transfer/generated-section
memory and scratch extents/files. It explicitly excludes replacement outputs
and caller-owned buffers. Those exclusions must not disappear only in the
documentation; they require corresponding implementation and measurements.

- Count parsed objects, attribute/index maps, generated headers and codec working
  memory in the shared scope. Native validation and owned output copies are
  separate allocation classes, not reasons to leave hidden intermediate copies.
- Account replacement output logical extents from allocation through transfer,
  metadata restoration, close, rename and cleanup. A clone can have a nonzero
  initial extent before the first Go write. Keep logical size separate from
  filesystem allocated blocks and scratch spill extent.
- Account held source, root, staging, metadata and spill handles through their
  actual ownership boundaries. Bundle discovery currently retains sources for
  later identity checks; a semaphore added around opens can deadlock if it fills
  before discovery can release any source. Scheduling and descriptor admission
  therefore need one design.
- Count queued/admitted/active work and bound sibling execution. Share the memory
  pool across descendants and reserve a transfer/spill progress path. Preserve
  native default versus serial failure ordering and completed partial writes.
- Retain primary and cleanup errors. A failed deletion must remain visible in
  final accounting. Cancellation must release operation-owned reservations and
  handles without treating completed native-permitted writes as rolled back.

APFS owns rooted metadata, replacement, compression and filesystem observation.
Its writer/codec allocations must be included in the audit through the pinned
dependency, rather than reimplemented in codesign. Any required APFS change gets
its own branch from main and draft PR with its native and all-host gates.

## Evidence needed to close this audit

1. Capture valid native large-field and aggregate-growth cases on macOS 15/26/27,
   alongside malformed/unauthorized controls. Retain C/SDK probes, both Clang
   targets, complete inputs/results and source provenance. A changed source hash
   requires recapture, not an edited old receipt.
2. Exercise the same operations through CLI and library APIs on every host, and
   compare owned and scoped results. Export foreign results for native readback.
3. Run real dense/sparse 1/2/4 GiB boundary cases where representable. Use virtual
   ranges additionally for overflow and fault injection, not instead of files.
4. Measure managed reservations, total Go allocation, heap/RSS or working set,
   temporary extents/blocks, open handles and queued/active work in fresh
   processes at the existing 64 KiB/128 MiB/256 MiB budgets.
5. Extend exact case/attestation membership, coverage and race/fuzz gates. Record
   obsolete-case replacements by requirement. Closure requires the final code
   and pinned APFS prerequisite to pass CI; an earlier green revision is not proof.

The implemented CMS copy reductions, held-field integration and range tests are described in
[CMS storage and verification](cms-streaming.md). They address intermediate
copies and field traversal; they do not close this audit's remaining consumers,
native admission questions or operation-wide accounting.
