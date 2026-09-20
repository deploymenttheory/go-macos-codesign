# Native option inventory and remaining access constraints

The 2026-09-20 D01 record retains all 55 original obligations and adds 32
undocumented switches recognized by the installed macOS 27 parser, plus the
documented `CODESIGN_ALLOCATE` environment hook. The compatibility inventory now
has 88 entries. No feature status is upgraded by parser recognition.

`make research-inventory` reproduces [the native record](../spec/apple-cli-inventory.json).
The Go driver checks the pinned binary/manual hashes before probing, records the
OS/build, architecture, locale, timezone, filesystem and case sensitivity, and
uses fresh disposable files. Binary strings are candidates: ten unrecognized
strings are recorded separately rather than promoted to features.

Every option has a seven-operation table. Five operations have bounded probes
using one existing signed arm64 fixture and an empty constraint plist. Signing
uses an ad-hoc identity and `--dryrun`. Argument vectors, raw output, status and
before/after file hashes are retained. Repeated operation flags deliberately
expose conflicts/precedence. A successful result does not establish general
applicability or ignored-option semantics. In particular the native constraint
validator can print a validation error while returning zero in this probe.
The `--remove-signature --file-list=files.txt` probe terminates by signal after
changing its disposable fixture; the record retains the signal and both hashes.
Native crashes are evidence of a safe-divergence requirement, not behavior to copy.

Hosting and detached-certificate merging have explicit unavailable-context cells.
Keychain/database, remote/helper and online trust operations are also excluded
where they would need unrelated state or external activity. These are evidence
gaps, not successful tests. The pinned [`security_systemkeychain` revision](https://github.com/apple-oss-distributions/security_systemkeychain/tree/2b4c65b1074521e9c1dd2c8dc7fbf45dd775ec70) supplies
`cs_utils.cpp` but not the current main/parser; the new private switches therefore
have installed-binary evidence rather than invented parser-source provenance.

The installed manual describes `--use-software-signing-cert` as software-update
validation policy. Its name alone does not establish an identity-selection or
PQC algorithm contract; those earlier research hypotheses remain unproven.

| Obligation | Required input or constraint |
| --- | --- |
| Hosting/process verification | Authorized live process identity, loaded code, host/guest chain and kernel validity, including races |
| Keychain | Isolated search lists, preferences, authorization and a usable key provider |
| Detached database | Actual schema, lookup/update behavior and isolated authorized persistence |
| Hardware/remote signing | The real non-exportable key and authorized device/service protocol |
| Hybrid/PQC and detached certificates | Legitimate native algorithm, slot and certificate-interchange fixtures |
| Notarization/revocation | Authenticated protocol/trust fixtures, freshness decisions and audited portable transport |
| Allocator/signing-library hooks | Arbitrary helper/library execution conflicts with the original no-helper/no-native-binding production boundary |

The original full-parity objective remains unresolved. This is an expanded
discovery baseline, not closure of WP-01/WP-22 or authorization to weaken the
production dependency guards.
