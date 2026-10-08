package codesign

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestCMSBorrowedFields(t *testing.T) {
	encoded, directories := testCMS(t)
	sd, _, err := decodeCMS(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// An unknown unsigned attribute exercises a large envelope without changing
	// the signature or relying on a particular trust store. This is a parser and
	// ownership control, not a claim of native acceptance for the attribute.
	payload := bytes.Repeat([]byte{0xa5}, 4<<20)
	sd.Signers[0].Unsigned = asn1.RawValue{FullBytes: derWrap(0xa1,
		derAttribute(asn1.ObjectIdentifier{1, 2, 3, 4}, derWrap(4, payload)))}
	encoded = encodeCMSForTest(t, sd)
	got, _, err := decodeCMS(encoded)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(encoded, got.Signers[0].Unsigned.FullBytes)
	if at < 0 || &encoded[at] != &got.Signers[0].Unsigned.FullBytes[0] {
		t.Fatal("decoding copied the CMS envelope")
	}
	// The old envelope decoder is retained for owned timestamp output. Require
	// structural parity against that independent ASN.1 decoding path.
	der, err := cmsEnvelopeDER(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var envelope cmsContent
	if err := decodeDER(der, &envelope); err != nil {
		t.Fatal(err)
	}
	var want cmsSignedData
	if err := decodeDER(envelope.Content.Bytes, &want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(testDER(t, *got), testDER(t, want)) {
		t.Fatal("borrowed and envelope decoders disagree")
	}
	// Public results must still own certificate storage independently of input.
	encoded, _ = testCMS(t)
	info, err := VerifyCMS(encoded, directories)
	if err != nil {
		t.Fatal(err)
	}
	signer := bytes.Clone(info.SignerCertificate)
	cert := bytes.Clone(info.Certificates[0])
	clear(encoded)
	if !bytes.Equal(info.SignerCertificate, signer) || !bytes.Equal(info.Certificates[0], cert) {
		t.Fatal("public certificate result aliases input")
	}
}

func TestCMSFieldValidation(t *testing.T) {
	encoded, _ := testCMS(t)
	oid, fields, err := cmsEnvelopeFields(encoded)
	if err != nil {
		t.Fatal(err)
	}
	parts := make([][]byte, len(fields))
	for i, field := range fields {
		parts[i] = field.raw
	}
	wrap := func(p ...[]byte) []byte {
		return cmsBERWrap(0x30, oid, cmsBERWrap(0xa0, cmsBERWrap(0x30, p...)))
	}
	for _, bad := range [][]byte{
		cmsBERWrap(0x30, []byte{5, 0}, cmsBERWrap(0xa0, cmsBERWrap(0x30, parts...))),
		cmsBERWrap(0x30, derOID(oidData), cmsBERWrap(0xa0, cmsBERWrap(0x30, parts...))),
		wrap([]byte{5, 0}, parts[1], parts[2], parts[3], parts[4]),
		wrap(parts[0], []byte{5, 0}, parts[2], parts[3], parts[4]),
		wrap(parts[0], parts[1], cmsBERWrap(0x30), parts[3], parts[4]),
		wrap(parts[0], parts[1], cmsBERWrap(0x30, derOID(oidData), []byte{5, 0}, []byte{5, 0}), parts[3], parts[4]),
		wrap(parts[0], parts[1], cmsBERWrap(0x30, []byte{5, 0}), parts[3], parts[4]),
		wrap(parts[0], parts[1], cmsBERWrap(0x30, derOID(oidData), []byte{5, 0}), parts[3], parts[4]),
		wrap(parts[0], parts[1], cmsBERWrap(0x30, derOID(oidData), cmsBERWrap(0xa0, []byte{4, 0})), parts[3], parts[4]),
		wrap(parts[0], parts[1], cmsBERWrap(0x30, derOID(oidData), []byte{0xa0, 1, 0xff}), parts[3], parts[4]),
		wrap(parts[0], parts[1], parts[2], cmsBERWrap(0xa0, fields[3].content), parts[4]),
		wrap(parts[0], parts[1], parts[2], parts[3], parts[3], parts[4]),
		wrap(parts[0], parts[1], parts[2], parts[3], []byte{5, 0}),
	} {
		if _, _, err := decodeCMS(bad); err == nil {
			t.Fatalf("accepted malformed fields %x", bad[:min(40, len(bad))])
		}
	}
	var values []algorithmIdentifier
	if err := decodeCMSSet([]byte{0x31, 0, 0}, &values); err == nil {
		t.Fatal("accepted trailing DER set bytes")
	}
}
