# CMS storage and verification

CMS authenticates a CodeDirectory and Apple's attributes binding the alternate
CodeDirectories. Timestamp tokens carry their own SignedData message. Both paths
use the same envelope decoder on Linux, macOS and Windows.

## Original encodings and owned results

Decoding walks the original BER envelope and decodes each field separately.
It does not rebuild the entire message into nested DER buffers. Only the four
outer containers accept indefinite BER; certificates, signer sets and signed
attributes retain strict DER validation. Internal fields borrow the input for
the duration of verification. Public certificate results own their storage.
Constructing a new timestamped message still assembles an owned envelope.

Signature verification hashes the DER SET header and original attribute content
separately. It does not allocate another complete signed-attributes buffer. The
same path handles code signatures and timestamp signatures with SHA-1, SHA-256,
SHA-384 and SHA-512. Ordering and duplicate-attribute checks precede hashing.

The shared BER walker represents values as checked source ranges. It reads only
headers (at most six bytes per read), skips definite-length payload ranges, and
walks child headers for indefinite containers. It checks source-base overflow,
truncation, cancellation and I/O failures, and retains the existing depth and
element bounds. The byte decoder uses this walker and borrows the resulting
slices; verification still needs integration with held CMS component sources.

This follows the existing Apple
[CMS ASN.1 templates](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_smime/lib/cmsasn1.c)
and [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652.html#section-5.4).
The retained native certificate fixtures and SDK/Clang evidence remain in
`testdata/certificate-layout` and `spec/apple-cms.json`.

`TestCMSBorrowedFields` checks borrowed envelope fields and independent returned
certificate storage, including a 4 MiB unknown-attribute parser control.
`TestCMSFieldValidation` adds malformed content/field/order/set cases. Both run
in every host's required unit shard. The unknown attribute is a synthetic parser
control, not evidence that native codesign accepts that attribute.

`TestCMSLargeSignedAttributes` authenticates an 8 MiB attribute using the public
test key, checks the signature with Go's independent X.509 verifier, requires
less than 2 MiB of additional Go allocation during CMS verification, and rejects
a changed final payload byte. This measures allocation rather than RSS.
`TestCMSAttributeDigestLengths` independently checks DER length transitions for
all four digest algorithms. Both are required on every host.

`TestCMSRangeLargeValues` forbids payload reads while exercising BER ranges around
1/2 GiB and through the maximum four-octet length. These virtual ranges prove
arithmetic and bounded header reads, not native acceptance or real-file scaling.
`TestCMSRangeIOFailures` checks source offsets, short/failed reads and cancellation.

## Remaining Phase 02 integration

Avoiding envelope copies does not make the complete CMS path bounded. The input
message, certificate parsing, attribute maps, cryptographic fields and timestamp
output still need ranged parsing and shared-budget integration. The 16 MiB CMS
and DER ceilings remain until their replacements and native large-message
qualification are complete. Individually large certificates and attributes,
aggregate growth, authenticated range hashing, cancellation/source mutation,
owned-output accounting and foreign-output native verification remain required.
See [Phase 02](implementation_plan.md#phase-02).
