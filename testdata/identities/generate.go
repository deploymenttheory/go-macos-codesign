//go:build ignore

// Generates public, self-signed test identities. These keys are intentionally
// published and must never be used to sign distributed software.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	keys := map[string]crypto.Signer{"rsa": rsaKey}
	for name, curve := range map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384(), "p521": elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		must(err)
		keys[name] = key
	}
	for name, key := range keys {
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		must(err)
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Public codesign test identity " + name}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, IsCA: true, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		must(err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		derKey, err := x509.MarshalPKCS8PrivateKey(key)
		must(err)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derKey})
		must(os.WriteFile(filepath.Join("testdata/identities", name+"-cert.pem"), certPEM, 0644))
		must(os.WriteFile(filepath.Join("testdata/identities", name+"-key.pem"), keyPEM, 0644))
		must(os.WriteFile(filepath.Join("testdata/identities", name+"-identity.pem"), append(certPEM, keyPEM...), 0644))
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
