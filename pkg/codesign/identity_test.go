package codesign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var certificateTime = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func identityFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../testdata/identities", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testIdentity(t *testing.T, kind string) *Identity {
	t.Helper()
	id, err := LoadIdentityPEM(identityFixture(t, kind+"-identity.pem"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func testDER(t *testing.T, value any) []byte {
	t.Helper()
	b, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func rawDER(t *testing.T, value any) asn1.RawValue {
	t.Helper()
	var raw asn1.RawValue
	if err := decodeDER(testDER(t, value), &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPortableIdentityDecoding(t *testing.T) {
	for _, kind := range []string{"rsa", "p256", "p384", "p521"} {
		t.Run(kind, func(t *testing.T) {
			id := testIdentity(t, kind)
			leaf, err := id.validate()
			if err != nil {
				t.Fatal(err)
			}
			independent, err := x509.ParseCertificate(id.Certificates[0])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(independent.RawIssuer, leaf.tbs.Issuer.FullBytes) || independent.SerialNumber.Cmp(leaf.tbs.Serial) != 0 {
				t.Fatal("certificate fields differ from independent parser")
			}
			if err := checkCertificatePurpose(leaf, certificateTime); err != nil {
				t.Fatal(err)
			}
			certs, err := ParseCertificatesPEM(identityFixture(t, kind+"-cert.pem"))
			if err != nil || !bytes.Equal(certs[0], id.Certificates[0]) {
				t.Fatal(err)
			}
			if _, err := LoadIdentityPEM(identityFixture(t, kind+"-cert.pem"), identityFixture(t, kind+"-key.pem")); err != nil {
				t.Fatal(err)
			}
			var der []byte
			var label string
			switch key := id.Signer.(type) {
			case *rsa.PrivateKey:
				der, label = x509.MarshalPKCS1PrivateKey(key), "RSA PRIVATE KEY"
			case *ecdsa.PrivateKey:
				der, err = x509.MarshalECPrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				label = "EC PRIVATE KEY"
			}
			parsed, err := LoadIdentityPEM(identityFixture(t, kind+"-cert.pem"), pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der}))
			if err != nil || parsed.Signer == nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMalformedPEMAndIdentity(t *testing.T) {
	good := identityFixture(t, "rsa-identity.pem")
	for name, data := range map[string][]byte{
		"garbage": []byte("hello"), "broken": []byte("-----BEGIN PRIVATE KEY-----\nbad"),
		"trailing": append(bytes.Clone(good), []byte("junk")...), "huge": make([]byte, 16<<20+1),
		"skipped": append([]byte("-----BEGIN PRIVATE KEY-----\n%%invalid%%\n-----END PRIVATE KEY-----\n"), good...),
		"headers": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pemBlocks(data); err == nil {
				t.Fatal("malformed PEM accepted")
			}
		})
	}
	for _, data := range [][]byte{nil, identityFixture(t, "rsa-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})} {
		if _, err := ParseCertificatesPEM(data); err == nil {
			t.Fatal("invalid certificate bundle")
		}
	}
	for _, tc := range []struct{ cert, key []byte }{
		{nil, nil}, {[]byte("bad"), nil}, {identityFixture(t, "rsa-cert.pem"), []byte("bad")},
		{good, identityFixture(t, "rsa-key.pem")}, {identityFixture(t, "rsa-cert.pem"), identityFixture(t, "p256-key.pem")},
		{pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}), nil},
		{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), identityFixture(t, "rsa-key.pem")},
	} {
		if _, err := LoadIdentityPEM(tc.cert, tc.key); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	id := testIdentity(t, "rsa")
	for _, certs := range [][][]byte{nil, {[]byte{1}}, {id.Certificates[0], id.Certificates[0]}, make([][]byte, 33)} {
		copyID := *id
		copyID.Certificates = certs
		if _, err := copyID.validate(); err == nil {
			t.Fatal("invalid chain accepted")
		}
	}
	// Additional certificates are embedded without assuming their trust.
	id.Certificates = append(id.Certificates, testIdentity(t, "p256").Certificates[0])
	if _, err := id.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedCertificates(t *testing.T) {
	der := testIdentity(t, "rsa").Certificates[0]
	for _, bad := range [][]byte{nil, {0x30, 0}, append(bytes.Clone(der), 0), make([]byte, 16<<20+1)} {
		if _, err := parseCertificate(bad); err == nil {
			t.Fatal("invalid certificate accepted")
		}
	}
	mutations := map[string]func(*certificateASN){
		"version":                func(c *certificateASN) { c.TBS.Version = 3 },
		"serial":                 func(c *certificateASN) { c.TBS.Serial = big.NewInt(-1) },
		"algorithm":              func(c *certificateASN) { c.Algorithm.Algorithm = oidEC },
		"validity":               func(c *certificateASN) { c.TBS.Validity.NotAfter = c.TBS.Validity.NotBefore.Add(-time.Hour) },
		"empty signature":        func(c *certificateASN) { c.Signature = asn1.BitString{} },
		"duplicate extension":    func(c *certificateASN) { c.TBS.Extensions = append(c.TBS.Extensions, c.TBS.Extensions[0]) },
		"unsupported public key": func(c *certificateASN) { c.TBS.PublicKey.Algorithm.Algorithm = oidP256 },
		"unaligned key":          func(c *certificateASN) { c.TBS.PublicKey.Key.BitLength-- },
		"RSA parameters":         func(c *certificateASN) { c.TBS.PublicKey.Algorithm.Parameters = rawDER(t, 1) },
		"RSA malformed":          func(c *certificateASN) { c.TBS.PublicKey.Key = asn1.BitString{Bytes: []byte{1}, BitLength: 8} },
		"RSA short": func(c *certificateASN) {
			b := testDER(t, rsa.PublicKey{N: big.NewInt(17), E: 3})
			c.TBS.PublicKey.Key = asn1.BitString{Bytes: b, BitLength: len(b) * 8}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var c certificateASN
			if err := decodeDER(der, &c); err != nil {
				t.Fatal(err)
			}
			c.TBS.Raw = nil
			mutate(&c)
			if _, err := parseCertificate(testDER(t, c)); err == nil {
				t.Fatal("bad certificate accepted")
			}
		})
	}
	ec, _ := testIdentity(t, "p256").validate()
	for _, mutate := range []func(*publicKeyInfo){
		func(p *publicKeyInfo) { p.Algorithm.Parameters = asn1.RawValue{} },
		func(p *publicKeyInfo) { p.Algorithm.Parameters = rawDER(t, oidRSA) },
		func(p *publicKeyInfo) { p.Key = asn1.BitString{Bytes: []byte{4}, BitLength: 8} },
	} {
		pub := ec.tbs.PublicKey
		mutate(&pub)
		if _, err := parsePublicKey(pub); err == nil {
			t.Fatal("invalid EC public key")
		}
	}
}

func TestCertificatePurpose(t *testing.T) {
	leaf, _ := testIdentity(t, "rsa").validate()
	if err := checkCertificatePurpose(leaf, time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("not-yet-valid certificate")
	}
	if err := checkCertificatePurpose(leaf, time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expired certificate")
	}
	for _, tc := range []struct {
		oid          asn1.ObjectIdentifier
		value        []byte
		critical, ok bool
	}{
		{asn1.ObjectIdentifier{2, 5, 29, 15}, []byte{1}, true, false},
		{asn1.ObjectIdentifier{2, 5, 29, 15}, testDER(t, asn1.BitString{Bytes: []byte{1}, BitLength: 8}), true, false},
		{asn1.ObjectIdentifier{2, 5, 29, 37}, []byte{1}, true, false},
		{asn1.ObjectIdentifier{2, 5, 29, 37}, testDER(t, []asn1.ObjectIdentifier{oidRSA}), true, false},
		{asn1.ObjectIdentifier{2, 5, 29, 37}, testDER(t, []asn1.ObjectIdentifier{{2, 5, 29, 37, 0}}), true, true},
		{asn1.ObjectIdentifier{2, 5, 29, 19}, []byte{1}, true, false},
		{asn1.ObjectIdentifier{1, 2, 3}, []byte{1}, true, false},
		{asn1.ObjectIdentifier{1, 2, 3}, []byte{1}, false, true},
	} {
		c := *leaf
		c.tbs.Extensions = []certificateExtension{{ID: tc.oid, Value: tc.value, Critical: tc.critical}}
		if err := checkCertificatePurpose(&c, certificateTime); (err == nil) != tc.ok {
			t.Fatalf("%v: %v", tc, err)
		}
	}
}

func TestPrivateKeyRejections(t *testing.T) {
	if _, err := parsePrivateKey("PRIVATE KEY", make([]byte, 64<<10+1)); err == nil {
		t.Fatal("oversized key")
	}
	for _, kind := range []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY", "UNKNOWN"} {
		if _, err := parsePrivateKey(kind, []byte{1}); err == nil {
			t.Fatal(kind)
		}
	}
	id := testIdentity(t, "rsa")
	key := id.Signer.(*rsa.PrivateKey)
	var rsaParts struct {
		Version               int
		N                     *big.Int
		E                     int
		D, P, Q, DP, DQ, QInv *big.Int
	}
	if err := decodeDER(x509.MarshalPKCS1PrivateKey(key), &rsaParts); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(){
		func() { rsaParts.Version = 1 }, func() { rsaParts.N = big.NewInt(17) },
		func() { rsaParts.D = big.NewInt(2) }, func() { rsaParts.DP = big.NewInt(2) },
	} {
		original := rsaParts
		mutate()
		if _, err := parsePrivateKey("RSA PRIVATE KEY", testDER(t, rsaParts)); err == nil {
			t.Fatal("bad RSA private key")
		}
		rsaParts = original
	}
	var pkcs8 struct {
		Version   int
		Algorithm algorithmIdentifier
		Key       []byte
	}
	block, _ := pem.Decode(identityFixture(t, "rsa-key.pem"))
	if err := decodeDER(block.Bytes, &pkcs8); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(){
		func() { pkcs8.Version = 1 }, func() { pkcs8.Algorithm.Algorithm = oidP256 },
		func() { pkcs8.Algorithm.Parameters = rawDER(t, 3) },
		func() { pkcs8.Algorithm.Algorithm = oidEC; pkcs8.Algorithm.Parameters = rawDER(t, 3) },
	} {
		original := pkcs8
		mutate()
		if _, err := parsePrivateKey("PRIVATE KEY", testDER(t, pkcs8)); err == nil {
			t.Fatal("bad PKCS#8")
		}
		pkcs8 = original
	}
	ec := testIdentity(t, "p256").Signer.(*ecdsa.PrivateKey)
	ecDER, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	var parts struct {
		Version int
		Key     []byte
		Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		Public  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	if err := decodeDER(ecDER, &parts); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(){
		func() { parts.Version = 0 }, func() { parts.Curve = oidRSA }, func() { parts.Curve = oidP384 },
		func() { parts.Key = []byte{0} }, func() { parts.Key = elliptic.P256().Params().N.Bytes() },
		func() { parts.Key = make([]byte, 33) },
		func() { parts.Public = asn1.BitString{Bytes: []byte{4}, BitLength: 8} },
	} {
		original := parts
		mutate()
		if _, err := parseECPrivateKey(testDER(t, parts), oidP256); err == nil {
			t.Fatal("bad EC private key")
		}
		parts = original
	}
	parts.Curve, parts.Public = nil, asn1.BitString{}
	if _, err := parseECPrivateKey(testDER(t, parts), oidP256); err != nil {
		t.Fatal(err)
	}
	if _, err := parseECPrivateKey(testDER(t, parts), nil); err == nil {
		t.Fatal("missing curve")
	}
}

func FuzzIdentity(f *testing.F) {
	seed, err := os.ReadFile("../../testdata/identities/rsa-identity.pem")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = LoadIdentityPEM(data, nil)
		_, _ = ParseCertificatesPEM(data)
		_, _ = parseCertificate(data)
	})
}
