package codesign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"
)

func chainFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/chains/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRealDeveloperChain(t *testing.T) {
	leaf, ca, root := chainFile(t, "developer-id-0"), chainFile(t, "developer-id-1"), chainFile(t, "developer-id-2")
	path, err := VerifyCertificateChain(leaf, [][]byte{root, ca}, [][]byte{root}, certificateTime)
	if err != nil {
		t.Fatal(err)
	}
	if path.TeamID != "UBF8T346G9" || len(path.Authorities) != 3 || path.Authorities[1].CommonName != "Developer ID Certification Authority" {
		t.Fatalf("%+v", path)
	}
	ordered, err := linkedCertificates(leaf, [][]byte{root, leaf, ca})
	if err != nil {
		t.Fatal(err)
	}
	for _, team := range []string{"UBF8T346G9", ""} {
		if err := checkTeamID(ordered, team); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkTeamID(ordered, "FORGEDTEAM"); err == nil {
		t.Fatal("mismatched Team ID accepted")
	}
	opts := SignOptions{Identity: &Identity{Certificates: [][]byte{leaf, ca, root}}, Identifier: "com.microsoft.VSCode", SigningTime: certificateTime}
	if err := prepareIdentity(&opts); err != nil || opts.teamID != "UBF8T346G9" {
		t.Fatal("Team ID preparation", opts.teamID, err)
	}
	req, err := defaultCertificateRequirement("com.microsoft.VSCode", ordered)
	if err != nil {
		t.Fatal(err)
	}
	d := Directory{Identifier: "com.microsoft.VSCode", chain: ordered}
	if err := checkDesignatedRequirement(req, d); err != nil {
		t.Fatal(err)
	}
	d.chain = nil
	if err := checkDesignatedRequirement(req, d); err == nil {
		t.Fatal("untrusted chain matched Apple anchor")
	}
	if _, err := VerifyCertificateChain(leaf, [][]byte{ca}, nil, certificateTime); err == nil {
		t.Fatal("missing anchor")
	}
	if _, err := VerifyCertificateChain(leaf, [][]byte{ca}, [][]byte{root}, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expired")
	}
}

func makeChain(t *testing.T, edit func(int, *x509.Certificate)) *Identity {
	t.Helper()
	signers := []crypto.Signer{testIdentity(t, "p256").Signer, testIdentity(t, "p384").Signer, testIdentity(t, "rsa").Signer}
	certs := make([][]byte, 3)
	var parent *x509.Certificate
	for i := 2; i >= 0; i-- {
		c := &x509.Certificate{SerialNumber: big.NewInt(int64(10 + i)), Subject: pkix.Name{CommonName: []string{"leaf", "intermediate", "root"}[i], Organization: []string{"Example"}, OrganizationalUnit: []string{"FAKETEAM00"}}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), BasicConstraintsValid: true, IsCA: i > 0, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
		if i > 0 {
			c.KeyUsage = x509.KeyUsageCertSign
			c.MaxPathLen = i - 1
			c.MaxPathLenZero = i == 1
		}
		if edit != nil {
			edit(i, c)
		}
		issuer, signer := parent, signers[min(i+1, 2)]
		if i == 2 {
			issuer = c
		}
		der, err := x509.CreateCertificate(rand.Reader, c, issuer, signers[i].Public(), signer)
		if err != nil {
			t.Fatal(err)
		}
		certs[i] = der
		parent, err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
	}
	return &Identity{Signer: signers[0], Certificates: certs}
}

func TestCertificateChainPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(int, *x509.Certificate)
		bad  bool
	}{
		{"valid", nil, false},
		{"non-ca", func(i int, c *x509.Certificate) {
			if i == 1 {
				c.IsCA = false
				c.MaxPathLen = -1
				c.MaxPathLenZero = false
			}
		}, true},
		{"wrong-usage", func(i int, c *x509.Certificate) {
			if i == 1 {
				c.KeyUsage = x509.KeyUsageDigitalSignature
			}
		}, true},
		{"path-length", func(i int, c *x509.Certificate) {
			if i == 2 {
				c.MaxPathLen = 0
				c.MaxPathLenZero = true
			}
		}, true},
		{"eku", func(i int, c *x509.Certificate) {
			if i == 1 {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
		}, true},
		{"critical", func(i int, c *x509.Certificate) {
			if i == 1 {
				c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
			}
		}, true},
		{"name-constraint", func(i int, c *x509.Certificate) {
			if i == 1 {
				c.PermittedDNSDomains = []string{"example.com"}
			}
		}, true},
		{"expired", func(i int, c *x509.Certificate) {
			if i == 1 {
				c.NotAfter = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
			}
		}, true},
		{"fake-apple", func(i int, c *x509.Certificate) {
			oid := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 13}
			if i == 1 {
				oid = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 6}
			}
			c.ExtraExtensions = []pkix.Extension{{Id: oid, Value: []byte{5, 0}}}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := makeChain(t, tc.edit)
			result, err := VerifyCertificateChain(id.Certificates[0], [][]byte{id.Certificates[1]}, [][]byte{id.Certificates[2]}, certificateTime)
			if (err != nil) != tc.bad {
				t.Fatalf("%+v %v", result, err)
			}
			if err == nil && result.TeamID != "" {
				t.Fatal("fake Team ID accepted")
			}
		})
	}
	id := makeChain(t, nil)
	signed, err := SignBytes(context.Background(), fixture(t, "unsigned-arm64"), SignOptions{Identifier: "chain", Identity: id, SigningTime: certificateTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []VerifyOptions{{TrustedRoots: [][]byte{id.Certificates[2]}, CurrentTime: certificateTime}, {TrustedCertificates: [][]byte{id.Certificates[0]}, CurrentTime: certificateTime}} {
		r, err := VerifyBytes(context.Background(), signed, opts)
		if err != nil || !r.Valid {
			t.Fatal(err)
		}
		if r.Architectures[0].Signature.Directories[0].TeamID != "" {
			t.Fatal("arbitrary OU became a Team ID")
		}
	}
	broken := bytes.Clone(id.Certificates[1])
	broken[len(broken)-1] ^= 1
	if _, err := VerifyCertificateChain(id.Certificates[0], [][]byte{broken}, [][]byte{id.Certificates[2]}, certificateTime); err == nil {
		t.Fatal("bad issuer signature")
	}
}

// Exercise Team ID wire storage independently of access to a Developer ID key.
// Real-chain eligibility is checked above; this is not a Developer ID signing test.
func TestTeamIDDirectoryStorage(t *testing.T) {
	c, err := parseContainer(fixture(t, "unsigned-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	id := testIdentity(t, "rsa")
	out, err := signImage(context.Background(), c.slices[0].image, SignOptions{Identity: id, Identifier: "team-storage", teamID: "TESTTEAM00", SigningTime: certificateTime})
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyBytes(context.Background(), out, VerifyOptions{TrustedCertificates: id.Certificates, CurrentTime: certificateTime})
	if err != nil {
		t.Fatal(err)
	}
	d := r.Architectures[0].Signature.Directories[0]
	if d.TeamID != "TESTTEAM00" || d.Identifier != "team-storage" {
		t.Fatalf("%+v", d)
	}
}
