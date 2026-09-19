package codesign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"os"
	"strconv"
	"strings"
	"testing"
)

func pfxOID(s string) asn1.ObjectIdentifier {
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		n, _ := strconv.Atoi(part)
		oid = append(oid, n)
	}
	return oid
}
func pfxExplicit(data []byte) asn1.RawValue {
	return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: data}
}
func testPFX(t *testing.T, contents []cmsContent, password string, absent bool) []byte {
	t.Helper()
	safe := testDER(t, contents)
	p := pfxArchive{Version: 3, Content: cmsContent{Type: oidData, Content: pfxExplicit(testDER(t, safe))}}
	p.MAC.Digest.Algorithm.Algorithm = oidSHA256
	p.MAC.Salt = []byte("test salt")
	p.MAC.Iterations = 2
	bmp := pfxPassword(password)
	if absent {
		bmp = nil
	}
	mac := hmac.New(sha256.New, pfxKDF(sha256.New, bmp, p.MAC.Salt, 2, 3, 32))
	_, _ = mac.Write(safe)
	p.MAC.Digest.Value = mac.Sum(nil)
	return testDER(t, p)
}
func testPFXBags(t *testing.T) []pfxBag {
	t.Helper()
	id := testIdentity(t, "rsa")
	key, err := x509.MarshalPKCS8PrivateKey(id.Signer)
	if err != nil {
		t.Fatal(err)
	}
	cert := struct {
		ID    asn1.ObjectIdentifier
		Value []byte `asn1:"explicit,tag:0"`
	}{pfxOID("1.2.840.113549.1.9.22.1"), id.Certificates[0]}
	return []pfxBag{{ID: pfxOID("1.2.840.113549.1.12.10.1.1"), Value: pfxExplicit(key)}, {ID: pfxOID("1.2.840.113549.1.12.10.1.3"), Value: pfxExplicit(testDER(t, cert))}}
}
func bagsContent(t *testing.T, bags []pfxBag) cmsContent {
	return cmsContent{Type: oidData, Content: pfxExplicit(testDER(t, testDER(t, bags)))}
}

func TestPKCS12AuthenticatedBoundaries(t *testing.T) {
	valid := testPFX(t, []cmsContent{bagsContent(t, testPFXBags(t))}, "", true)
	if _, err := LoadIdentityPKCS12(valid, ""); err != nil {
		t.Fatal("absent password:", err)
	}
	for _, password := range []string{string([]byte{0xff}), strings.Repeat("a", 1025)} {
		if _, err := LoadIdentityPKCS12(valid, password); err == nil {
			t.Fatal("password bounds")
		}
	}
	if _, err := LoadIdentityPKCS12([]byte{1}, ""); err == nil {
		t.Fatal("bad DER")
	}
	for _, mutate := range []func(*pfxArchive){
		func(p *pfxArchive) { p.Version = 4 }, func(p *pfxArchive) { p.Content.Type = oidSignedData }, func(p *pfxArchive) { p.Content.Content = pfxExplicit([]byte{1}) },
		func(p *pfxArchive) { p.MAC = pfxMAC{} }, func(p *pfxArchive) { p.MAC.Digest.Value = nil }, func(p *pfxArchive) { p.MAC.Iterations = 1000001 }, func(p *pfxArchive) { p.MAC.Salt = nil }, func(p *pfxArchive) { p.MAC.Digest.Algorithm.Parameters = asn1.RawValue{FullBytes: []byte{2, 1, 0}} },
	} {
		var p pfxArchive
		if err := decodeDER(valid, &p); err != nil {
			t.Fatal(err)
		}
		mutate(&p)
		if _, err := LoadIdentityPKCS12(testDER(t, p), "wrong"); err == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
	for _, tc := range []struct {
		name string
		make func() []cmsContent
	}{
		{"no-safes", func() []cmsContent { return nil }},
		{"many-safes", func() []cmsContent {
			out := make([]cmsContent, 33)
			for i := range out {
				out[i] = bagsContent(t, nil)
			}
			return out
		}},
		{"unknown-content", func() []cmsContent { return []cmsContent{{Type: oidSignedData}} }},
		{"bad-content", func() []cmsContent { return []cmsContent{{Type: oidData, Content: pfxExplicit([]byte{1})}} }},
		{"bad-bags", func() []cmsContent { return []cmsContent{{Type: oidData, Content: pfxExplicit(testDER(t, []byte{1}))}} }},
		{"many-bags", func() []cmsContent {
			b := testPFXBags(t)
			bags := make([]pfxBag, 65)
			for i := range bags {
				bags[i] = b[1]
			}
			return []cmsContent{bagsContent(t, bags)}
		}},
		{"unknown-bag", func() []cmsContent { b := testPFXBags(t); b[0].ID = oidData; return []cmsContent{bagsContent(t, b)} }},
		{"duplicate-key", func() []cmsContent { b := testPFXBags(t); return []cmsContent{bagsContent(t, append(b, b[0]))} }},
		{"duplicate-leaf", func() []cmsContent { b := testPFXBags(t); return []cmsContent{bagsContent(t, append(b, b[1]))} }},
		{"bad-cert", func() []cmsContent {
			b := testPFXBags(t)
			b[1].Value = pfxExplicit([]byte{1})
			return []cmsContent{bagsContent(t, b)}
		}},
		{"bad-key", func() []cmsContent {
			b := testPFXBags(t)
			b[0].Value = pfxExplicit([]byte{1})
			return []cmsContent{bagsContent(t, b)}
		}},
		{"bad-encrypted-key", func() []cmsContent {
			b := testPFXBags(t)
			b[0].ID = pfxOID("1.2.840.113549.1.12.10.1.2")
			b[0].Value = pfxExplicit([]byte{1})
			return []cmsContent{bagsContent(t, b)}
		}},
		{"unknown-encrypted-key", func() []cmsContent {
			b := testPFXBags(t)
			b[0].ID = pfxOID("1.2.840.113549.1.12.10.1.2")
			b[0].Value = pfxExplicit(testDER(t, encryptedPrivateKey{Algorithm: algorithmIdentifier{Algorithm: oidData}, Data: []byte{1}}))
			return []cmsContent{bagsContent(t, b)}
		}},
		{"no-key", func() []cmsContent { return []cmsContent{bagsContent(t, testPFXBags(t)[1:])} }},
		{"no-cert", func() []cmsContent { return []cmsContent{bagsContent(t, testPFXBags(t)[:1])} }},
		{"unmatched", func() []cmsContent {
			b := testPFXBags(t)
			key, _ := x509.MarshalPKCS8PrivateKey(testIdentity(t, "p256").Signer)
			b[0].Value = pfxExplicit(key)
			return []cmsContent{bagsContent(t, b)}
		}},
		{"encrypted-content-der", func() []cmsContent {
			return []cmsContent{{Type: pfxOID("1.2.840.113549.1.7.6"), Content: pfxExplicit([]byte{1})}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := testPFX(t, tc.make(), "pw", false)
			if _, err := LoadIdentityPKCS12(data, "pw"); err == nil {
				t.Fatal("invalid authenticated archive accepted")
			}
		})
	}
	for _, oid := range []string{"1.3.14.3.2.26", "2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3"} {
		if _, err := pfxHash(algorithmIdentifier{Algorithm: pfxOID(oid)}, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, oid := range []string{"1.2.840.113549.2.7", "1.2.840.113549.2.9", "1.2.840.113549.2.10", "1.2.840.113549.2.11"} {
		if _, err := pfxHash(algorithmIdentifier{Algorithm: pfxOID(oid)}, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pfxHash(algorithmIdentifier{Algorithm: oidData}, true); err == nil {
		t.Fatal("unknown PRF")
	}
	for _, salt := range [][]byte{nil, bytes.Repeat([]byte{1}, 1025)} {
		budget := 2000000
		if err := pfxWork(salt, 1, &budget); err == nil {
			t.Fatal("salt bounds")
		}
	}
	budget := 1
	if err := pfxWork([]byte{1}, 2, &budget); err == nil {
		t.Fatal("work bounds")
	}
}

func FuzzPKCS12(f *testing.F) {
	f.Add([]byte{0x30, 0}, "password")
	for _, name := range []string{"rsa-modern", "rsa-legacy"} {
		data, err := os.ReadFile("../../testdata/pkcs12/" + name + ".p12")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, "public-codesign-test-only")
	}
	f.Fuzz(func(t *testing.T, data []byte, password string) {
		if len(data) > 1<<20 || len(password) > 2048 {
			return
		}
		_, _ = LoadIdentityPKCS12(data, password)
	})
}
