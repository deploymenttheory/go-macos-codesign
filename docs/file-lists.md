# Signature file lists

`--file-list PATH` appends one absolute signature-file path per line after a
successful signing or display operation. `--file-list=-` writes the list to
stdout; normal display and replacement notices remain on stderr. Both attached
and separate arguments work, and the last occurrence wins. An empty attached
argument is an empty filename and fails when the output is opened.

```sh
macoscodesign -s - --deep --file-list changed-files.txt Example.app
macoscodesign -d --file-list=- Example.app
macoscodesign -d --extract-certificates=cert --file-list files.txt Example.app
```

The list describes the selected representation's signature storage. For a
standalone Mach-O or DMG it contains the physical file. For a supported bundle,
it contains the main executable followed by existing signature metadata files
not supplied by embedded slots, normally `_CodeSignature/CodeResources`. It
excludes Info.plist, ordinary sealed resources, helpers, child bundles and other
framework versions. Native deep signing also lists only the outer representation;
this is **not a complete recursive write journal**.

Directory parents resolve physically. Framework-root display preserves the
selected version spelling and a literal dot in the metadata path, for example:

```text
/Applications/Fixture.framework/Versions/Current/Fixture
/Applications/Fixture.framework/Versions/Current/./_CodeSignature/CodeResources
```

Direct `Versions/Current` directory operands select the physical version, whose
metadata path has no inserted dot. The 76-case representation matrix checks raw
output against native `codesign` at the same path. It covers three Mach-O
architectures, nine bundle layouts, recursive apps, five DMG profiles, relative
parent aliases, stdout and append destinations. DMG signing comparisons use
already signed images because fresh native signing with this option crashes.

## Output and failure ordering

New list files use mode `0666` subject to the process umask. Existing files are
appended in place, preserving their inode and mode; symlinks and hard links follow
their targets. Each successful operand appends its own list, including repeated
entries. The output is opened after signing or after display and certificate
extraction. An output-open failure leaves preceding changes and extracted
certificates intact and terminates the command even with `--continue`. English
missing-parent, directory and permission diagnostics name the output destination.
An empty destination produces only the error text.

A failed input operation produces no list for that operand. Ordinary input errors
still follow the command's existing `--continue` behavior. Verification ignores
`--file-list` without creating its destination. `--json` may be combined with a
file destination as a portable extension; directing both JSON and the list to
stdout produces consecutive outputs, not a single JSON document.

Signed Mach-O and bundle dry runs preserve their inputs and list the existing
signature files. A signed DMG dry run retains the pre-signing representation for
the list while performing the [existing unsigned in-place writes](dmg-integration.md).
This option does not turn a DMG dry run into a read-only operation.

## Library API and limits

A report from `codesign.Inspect` or `InspectWithOptions` exposes
`report.SignatureFiles(architecture)`. It selects the same signed architecture as
`report.SelectArchitecture(architecture)`: an empty name prefers arm64, then the
first container architecture. Byte-only reports have no filesystem path and are
rejected. The list is descriptive; neither API establishes integrity or trust.
External component existence is checked when `SignatureFiles` is called, so a
report is not an immutable filesystem snapshot.

Three library/native cases check missing resources, external component ordering
and exclusion of embedded entitlement slots. They inspect a supported bundle
before adding external files, then compare the report API with native display.
**CLI inspection still rejects extra signature files.** These API comparisons do
not claim CLI support for external-signature bundle representations. Alternate
CodeDirectories, malformed external slots and architecture-specific external
metadata require broader format/inspection work.

Six Mac cases retain explicit native crash differences: removal with a file list
for standalone Mach-O/apps, unsigned dry runs for Mach-O/apps/DMGs, and fresh DMG
signing. Go rejects removal with a file list before changing the input, reports an
unsigned error after the existing dry-run operation, and successfully lists a
freshly signed DMG. The native baseline instead terminates by signal; removal has
already happened, and signing/dry-run bytes are independently compared. These
are recorded differences, not equivalent successful outcomes. Native DMG removal
is already unsupported and is outside that crash matrix.

Go reports write/close errors; the extracted Apple stdio helper does not check
those results. Output paths that overlap input files, blocked/special streams,
full disks, all errno translations, additional CMS/signature slots, detached and
generic signatures, complete architecture defaults and entitlement/requirement
extraction interactions remain outside this profile. `--file-list` is **partial**.

The [Clang evidence](../spec/apple-file-list.json) contains six complete Apple
functions on two targets, with pinned source and filename-macro hashes and
explicit private-interface shims. The [testing guide](testing.md#signature-file-lists)
distinguishes exact CLI comparisons, library-only comparisons and divergences.
