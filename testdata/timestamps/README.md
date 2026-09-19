# Native timestamp fixture

`apple-rsa-arm64` is the repository's unsigned arm64 test program signed by
Apple `codesign` with the public RSA identity in `testdata/identities` and a live
Apple TSA token. `manifest.json` records its SHA-256, signing command, native
display, host version and native tool hash. It is public test data, not a private
distribution credential.

Routine unit and acceptance tests replay the token without network access.
Timestamp trust is explicitly anchored to the Apple Root CA DER already pinned
as `testdata/chains/developer-id-2`; short-lived TSA certificates are validated at
the authenticated timestamp, not the current date.

To deliberately replace the fixture on a Mac with Apple TSA connectivity:

```sh
MACOSCODESIGN_RECORD_TIMESTAMP=1 CGO_ENABLED=0 go test ./acceptance \
  -run '^TestRecordAppleTimestamp$' -count=1 -v
```

Recording creates a temporary keychain containing only public test credentials
and deletes it afterward. It writes the new native file and manifest only after
Apple's strict verification succeeds. Re-recording produces different bytes and
requires reviewing the manifest and rerunning acceptance. The fixture proves one
RSA arm64 case; synthetic timestamp tests additionally cover other algorithms
and Mach-O forms.
