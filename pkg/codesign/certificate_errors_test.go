package codesign

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertificateBoundaries(t *testing.T) {
	id := makeChain(t, nil)
	if _, err := VerifyCertificateChain(nil, nil, id.Certificates, certificateTime); err == nil {
		t.Fatal("bad leaf")
	}
	if _, err := VerifyCertificateChain(id.Certificates[0], nil, [][]byte{{1}}, certificateTime); err == nil {
		t.Fatal("bad root")
	}
	if _, err := VerifyCertificateChain(id.Certificates[0], make([][]byte, 65), id.Certificates, certificateTime); err == nil {
		t.Fatal("pool bounds")
	}
	if _, err := VerifyCertificateChain(id.Certificates[0], id.Certificates, id.Certificates[2:], time.Time{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		leaf  []byte
		certs [][]byte
	}{{nil, nil}, {id.Certificates[0], [][]byte{{1}}}, {id.Certificates[0], make([][]byte, 33)}} {
		if _, err := linkedCertificates(tc.leaf, tc.certs); err == nil {
			t.Fatal("bad linked certificates")
		}
	}
	path, err := linkedCertificates(id.Certificates[0], id.Certificates[:1])
	if err != nil || len(path) != 1 {
		t.Fatal(path, err)
	}
	for _, edit := range []func(*certificate){
		func(c *certificate) { c.tbs.Signature.Algorithm = oidData },
		func(c *certificate) { c.tbs.Signature.Parameters = asn1.RawValue{FullBytes: []byte{2, 1, 0}} },
		func(c *certificate) { c.signature = []byte{1} },
	} {
		child, _ := parseCertificate(id.Certificates[0])
		parent, _ := parseCertificate(id.Certificates[1])
		edit(child)
		if err := certificateSignature(child, parent); err == nil {
			t.Fatal("certificate signature accepted")
		}
	}
	for _, alg := range []x509.SignatureAlgorithm{x509.SHA384WithRSA, x509.SHA512WithRSA, x509.ECDSAWithSHA256, x509.ECDSAWithSHA512} {
		candidate := makeChain(t, func(i int, c *x509.Certificate) {
			if i == 1 && (alg == x509.SHA384WithRSA || alg == x509.SHA512WithRSA) || i == 0 && (alg == x509.ECDSAWithSHA256 || alg == x509.ECDSAWithSHA512) {
				c.SignatureAlgorithm = alg
			}
		})
		if _, err := VerifyCertificateChain(candidate.Certificates[0], candidate.Certificates, candidate.Certificates[2:], certificateTime); err != nil {
			t.Fatal(alg, err)
		}
	}
	bad, _ := parseCertificate(id.Certificates[0])
	bad.tbs.Subject = asn1.RawValue{FullBytes: []byte{1}}
	if _, err := certificateInfo(bad); err == nil {
		t.Fatal("bad subject")
	}
	if _, err := describeChain([]*certificate{bad}); err == nil {
		t.Fatal("bad subject metadata")
	}
	if _, err := InspectCertificateMetadata(nil); err == nil {
		t.Fatal("nil signature")
	}
	for _, certs := range [][][]byte{{id.Certificates[0], id.Certificates[2]}, {id.Certificates[0], id.Certificates[2], id.Certificates[1]}, {id.Certificates[0], {1}}} {
		copyID := *id
		copyID.Certificates = certs
		opts := SignOptions{Identity: &copyID, SigningTime: certificateTime}
		if err := prepareIdentity(&opts); err == nil {
			t.Fatal("identity ordering")
		}
	}
}

func TestCertificateFieldRequirements(t *testing.T) {
	id := makeChain(t, nil)
	path, err := linkedCertificates(id.Certificates[0], id.Certificates)
	if err != nil {
		t.Fatal(err)
	}
	d := Directory{chain: path}
	for _, expression := range []string{`certificate leaf[subject.CN] = "leaf"`, `certificate 0[subject.OU] = "FAKETEAM00"`, `certificate root[subject.O] = "Example"`, `certificate 1[subject.CN] = "intermediate"`} {
		b, err := CompileRequirement(expression)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := EvaluateRequirementBytes(b, d); err != nil || !ok {
			t.Fatal(expression, ok, err)
		}
		for n := 12; n < len(b); n++ {
			truncated := bytes.Clone(b[:n])
			be.PutUint32(truncated[4:], uint32(n))
			if _, err := decodeRequirement(truncated); err == nil {
				t.Fatalf("accepted truncated field %d", n)
			}
		}
	}
	for _, expression := range []string{`anchor test`, `anchor apple`, `certificate 32 = H"` + strings.Repeat("00", 20) + `"`, `certificate -1 = H"00"`, `certificate leaf[subject.OU`, `certificate leaf[subject.UID] = "x"`, `certificate leaf[subject.CN] exists`, `certificate leaf[subject.CN] = x`, `certificate leaf[field.1.no] exists`, `certificate leaf[field.9.2] exists`, `certificate leaf[field.1.2.3] = "x"`} {
		if _, err := CompileRequirement(expression); err == nil {
			t.Fatal(expression)
		}
	}
	for _, node := range []*requirementNode{{op: 11, slot: 31, field: "subject.CN"}, {op: 14, field: "\xff"}, {op: 4, slot: 31}, {op: 4, slot: -1}} {
		if node.matches(Directory{}) {
			t.Fatal("missing certificate matched")
		}
	}
	for _, node := range []*requirementNode{{op: 11, slot: 32, field: "subject.CN"}, {op: 11, field: "subject.UID"}, {op: 14, field: "\xff"}} {
		if _, err := decodeRequirement(blob(MagicRequirement, node.encode(append32(nil, 1)))); err == nil {
			t.Fatal("bad encoded field")
		}
	}
}

// Explicit regeneration only; normal tests never rewrite committed fixtures.
func TestExportChainFixtures(t *testing.T) {
	dir := os.Getenv("MACOSCODESIGN_CHAIN_EXPORT_DIR")
	if dir == "" {
		t.Skip("fixture export is opt-in")
	}
	for _, name := range []string{"root", "intermediate", "leaf"} {
		id := makeChain(t, func(i int, c *x509.Certificate) {
			if name == "intermediate" && i == 2 || name == "leaf" && i > 0 {
				c.Subject.Organization = []string{"Different"}
			}
		})
		var bundle []byte
		for i, der := range id.Certificates {
			p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			bundle = append(bundle, p...)
			if i == 2 {
				if err := os.WriteFile(filepath.Join(dir, name+"-root.pem"), p, 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
		key, err := x509.MarshalPKCS8PrivateKey(id.Signer)
		if err != nil {
			t.Fatal(err)
		}
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})...)
		if err := os.WriteFile(filepath.Join(dir, name+"-identity.pem"), bundle, 0644); err != nil {
			t.Fatal(err)
		}
	}
}
