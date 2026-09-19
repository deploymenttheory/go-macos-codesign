package codesign

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func timestampFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/timestamps/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAppleTimestamp(t *testing.T) {
	data := timestampFile(t, "apple-rsa-arm64")
	r, err := InspectBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	sig := r.Architectures[0].Signature
	info, err := VerifyCMS(sig.find(SlotCMS)[8:], [][]byte{sig.Directories[0].Raw})
	if err != nil {
		t.Fatal(err)
	}
	if info.Timestamp == nil || info.Timestamp.Policy != "1.2.3.4.5.6" {
		t.Fatal("missing native timestamp")
	}
	root := [][]byte{chainFile(t, "developer-id-2")}
	now := info.Timestamp.Time.Add(time.Hour)
	_, err = VerifyBytes(context.Background(), data, VerifyOptions{TrustedCertificates: info.Certificates, TimestampRoots: root, CurrentTime: now})
	if err != nil {
		t.Fatal(err)
	}
	goSigned, err := SignBytes(context.Background(), fixture(t, "unsigned-arm64"), SignOptions{Identifier: "org.example.timestamp", Identity: testIdentity(t, "rsa"), SigningTime: info.SigningTime, Timestamp: &TimestampOptions{TrustedRoots: root, CurrentTime: now, Provider: func(context.Context, []byte) ([]byte, error) { return info.Timestamp.Token, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(goSigned, data) {
		t.Fatalf("native timestamp signature differs: Go %d, Apple %d bytes", len(goSigned), len(data))
	}
}

func FuzzTimestamp(f *testing.F) {
	data, err := os.ReadFile("../../testdata/timestamps/apple-rsa-arm64")
	if err != nil {
		f.Fatal(err)
	}
	r, err := InspectBytes(data)
	if err != nil {
		f.Fatal(err)
	}
	sig := r.Architectures[0].Signature
	sd, _, err := decodeCMS(sig.find(SlotCMS)[8:])
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sig.CertificateMetadata.Timestamp.Token)
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, token []byte) {
		if len(token) > maxTimestampSize+1 {
			return
		}
		_, _ = parseTimestampToken(token, sd.Signers[0].Signature)
	})
}
