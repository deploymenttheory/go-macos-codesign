# Certificate policy fixtures

`developer-id-0`, `-1`, `-2` are public DER certificates from the host's Microsoft
VS Code signature. Native `codesign -dvv` reported TeamIdentifier `UBF8T346G9` and
authorities Microsoft Corporation, Developer ID Certification Authority, Apple
Root CA. The leaf expires in February 2027; tests use their fixed verification
time. These are certificate-chain fixtures, not a redistributable signed VS Code
executable, and contain no Developer ID private key.

The root SHA-256 was independently matched to Apple's published certificate:
https://www.apple.com/appleca/AppleIncRootCertificate.cer
The implementation also pins G2 and G3 root hashes from Apple's PKI page.

The three synthetic identity bundles use the repository's public P-256 leaf,
P-384 intermediate and RSA root keys. Their Organization fields select the root,
intermediate or leaf for Apple's default designated requirement. Their OU is
`FAKETEAM00`; native and Go signatures must leave TeamIdentifier unset.

To intentionally regenerate only the synthetic bundles:

```sh
MACOSCODESIGN_CHAIN_EXPORT_DIR="$PWD/testdata/chains" go test ./pkg/codesign -run '^TestExportChainFixtures$' -count=1
```

Update the manifest and rerun native acceptance after regenerating. Native chain
tests temporarily append their disposable keychain to the user search list and
restore the original list on cleanup. They do not change certificate trust settings.
