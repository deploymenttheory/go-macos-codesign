package codesign

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCertificateMetadataDEROwnership(t *testing.T) {
	for _, kind := range []string{"rsa", "p256", "p384", "p521"} {
		t.Run(kind, func(t *testing.T) {
			data := readTestFile(t, "../../testdata/certificate-layout/"+kind+"-arm64")
			before := bytes.Clone(data)
			r, err := InspectBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			m := r.Architectures[0].Signature.CertificateMetadata
			certs, err := ParseCertificatesPEM(readTestFile(t, "../../testdata/identities/"+kind+"-cert.pem"))
			if err != nil || m == nil || len(m.Certificates) != 1 || len(m.Authorities) != 1 || !bytes.Equal(m.Certificates[0], certs[0]) {
				t.Fatal("certificate metadata", m, err)
			}
			encoded, err := json.Marshal(m)
			if err != nil || bytes.Contains(encoded, []byte(`"Certificates"`)) {
				t.Fatal("DER leaked into JSON", err)
			}
			m.Certificates[0][0] ^= 1
			if !bytes.Equal(data, before) {
				t.Fatal("metadata aliases input bytes")
			}
			fresh, err := InspectCertificateMetadata(r.Architectures[0].Signature)
			if err != nil || !bytes.Equal(fresh.Certificates[0], certs[0]) {
				t.Fatal("metadata aliases signature data", err)
			}
		})
	}
}
