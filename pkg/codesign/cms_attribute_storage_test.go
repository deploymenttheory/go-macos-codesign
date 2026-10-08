package codesign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"runtime"
	"testing"
)

func TestCMSLargeSignedAttributes(t *testing.T) {
	encoded, directories := testCMS(t)
	sd, _, err := decodeCMS(encoded)
	if err != nil {
		t.Fatal(err)
	}
	budget := 4096
	children, err := cmsBERChildren(sd.Signers[0].Attributes.FullBytes, 0xa0, &budget)
	if err != nil {
		t.Fatal(err)
	}
	var parts [][]byte
	for _, child := range children {
		parts = append(parts, child.raw)
	}
	// Synthetic authenticated unknown attribute: the existing identity and
	// CodeDirectory bindings stay valid. Native acceptance is qualified by
	// separate probes; this regression proves storage and cryptographic checks.
	payload := bytes.Repeat([]byte{0x5a}, 8<<20)
	parts = append(parts, derAttribute(asn1.ObjectIdentifier{1, 2, 3, 4}, derWrap(4, payload)))
	signed := derSet(parts...)
	digest := sha256.Sum256(signed)
	id := testIdentity(t, "rsa")
	signature, err := id.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(id.Certificates[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignature(x509.SHA256WithRSA, signed, signature); err != nil {
		t.Fatal("independent signature check", err)
	}
	signed[0] = 0xa0
	sd.Signers[0].Attributes = asn1.RawValue{FullBytes: signed}
	sd.Signers[0].Signature = signature
	encoded = encodeCMSForTest(t, sd)
	original := bytes.Clone(encoded)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	info, err := VerifyCMS(encoded, directories)
	runtime.ReadMemStats(&after)
	if err != nil || info == nil {
		t.Fatal("large authenticated attributes", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<20 {
		t.Fatalf("verification allocated %d bytes for an 8 MiB attribute", allocated)
	}
	if !bytes.Equal(encoded, original) {
		t.Fatal("verification modified authenticated input")
	}
	at := bytes.Index(encoded, payload)
	if at < 0 {
		t.Fatal("missing authenticated payload")
	}
	encoded[at+len(payload)-1] ^= 1
	if _, err := VerifyCMS(encoded, directories); !errors.Is(err, ErrInvalid) {
		t.Fatal("changed authenticated attribute accepted", err)
	}
}

func TestCMSAttributeDigestLengths(t *testing.T) {
	for _, size := range []int{0, 1, 127, 128, 255, 256, 65535, 65536} {
		data := bytes.Repeat([]byte{0x3c}, size)
		for _, kind := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			// encoding/asn1 independently chooses short/long length octets.
			encoded, err := asn1.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			encoded[0] = 0x31
			h := kind.New()
			_, _ = h.Write(encoded)
			if !bytes.Equal(cmsAttributeBytes(data).digest(kind), h.Sum(nil)) {
				t.Fatalf("size=%d hash=%v: wrong authenticated SET encoding", size, kind)
			}
		}
	}
}
