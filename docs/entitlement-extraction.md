# Entitlement extraction

Display supports a bounded native entitlement extraction profile on Linux,
macOS and Windows. Signing continues to preserve original XML input bytes;
extraction reconstructs values from the selected signature.

```sh
macoscodesign -d --entitlements=- Example.app
macoscodesign -d --entitlements=:- Example.app
macoscodesign -d --entitlements=:entitlements.plist Example.app
```

The ordinary form emits a typed, tab-indented dump. A colon prefix selects compact
XML and emits Apple's deprecation warning. XML uses the observed HTTPS plist DTD,
sorted keys, signed decimal integers, escaped strings and paired empty collection
tags. Supported values are booleans, signed 64-bit integers, UTF-8 strings, arrays
and dictionaries. Arrays mixing primitive types can be extracted as XML, but the
native text dumper rejects them with exit 65. Constructed array/dictionary children
do not themselves conflict with primitive children.

The colon is consumed after the first reached extraction in an invocation. With
`--entitlements=:- first second`, the first operand emits XML and the second emits
the text dump. The warning appears only when a colon is consumed, including when
that operand has no entitlements. A repeated option uses its last argument. An
explicitly empty argument fails with `Missing entitlements file path` and exit 1.

## Selection and integrity

`codesign.InspectEntitlements` returns owned reconstructed XML/text bytes and a
`TextValid` flag. It selects DER before XML and checks the component's required
special-slot hash against the primary CodeDirectory. A changed, unused XML slot
does not override valid DER. XML-only signatures reuse the bounded plist reader
and existing DER encoder; they require an absent DER hash. The common reader
limits input to 8 MiB, nesting to 32 and values including keys to 100,000.

Absence returns a nil result without error. Hash failures return `ErrInvalid`;
CLI extraction warns and leaves output files untouched. Correctly bound but
malformed DER returns a nonnil result with nil XML and invalid text: colon mode
warns without opening a file, while text mode opens its append destination and
then exits 65. Unknown DER versions/types and alternate CodeDirectories are
explicitly unsupported. Inspection does not verify executable pages, CMS trust
or entitlement authorization; a modified code page does not prevent this display
operation. Use the separate verification API for its supported integrity policy.

The shared architecture selector prefers arm64 by default and honors explicit
arm64/x86_64 selection in the measured universal profile. Supported representations
include thin/universal Mach-O, Contents apps, versioned frameworks and UDIF DMGs.
The latter two acceptance fixtures explicitly force library entitlements during
signing; extraction does not add entitlements to inputs which lack them.

## Output lifecycle

Extraction prints normal display metadata to stderr. Certificate extraction occurs
before entitlement extraction; verbose signature-count lines follow successful
entitlement extraction, and file lists follow those lines. Failures retain any
previous certificate/output files. The portable `--json` option continues to yield
to entitlement output when both are requested.

Entitlement destinations use append mode, preserve existing bytes, modes and
inodes, and follow existing symlink/hard-link targets. New files request mode
0666 subject to the host's umask and filesystem permissions. Parent directories
are not created. Absent/invalid bound components do not open or create output
files. A text-validation failure can create an empty file or leave an existing
prefix intact. Missing-parent, directory and empty-colon destinations produce the
measured English output-path diagnostics. Output-open and text-validation failures
stop even with `--continue`. Multiple successful operands append to the same file.

Go checks write and close errors. The extracted generic Apple stdio helpers ignore
those errors; equivalence for short/full/blocked streams is not claimed.

## Evidence and remaining work

[Native acceptance](../acceptance/entitlement_extraction_test.go) records 91 cases:
44 representation/value/output cases, 26 lifecycle/interaction cases, 18 slot-state
cases and three universal architecture selections. Ninety cases compare raw native
stdout/stderr/exit status and output bytes on Mac; the JSON case records the
portable extension. Every case checks input preservation. Link lifecycle tests
also check actual inode and mode retention; deterministic archives preserve
content/path comparisons across producers without claiming portable stat equality.

[Clang evidence](../spec/apple-entitlement-extraction.json) records six complete
Apple functions on arm64 and x86_64: component/entitlement access, slot presence,
XML decoding and generic output helpers. Source/excerpt/translation-unit hashes,
source revisions and declaration-only private interfaces are recorded. The private
CoreEntitlements parser/serializers and current CLI call sites are unavailable;
current formatting, append mode and operation ordering come from native probes.

Remaining work includes full malformed-input/unsupported-type parity, legacy DER,
alternate CodeDirectories/signature slots, detached/external components, CMS policy
interactions, native special-entitlement transformations, larger/deeper inputs,
all architecture defaults, additional locales/OS versions, output aliases to
inputs, permission/short-write/disk-full behavior, and requirement/constraint
extraction interactions. `--entitlements` remains partial. This work changes no
compatibility inventory status and does not establish full codesign equivalence.
