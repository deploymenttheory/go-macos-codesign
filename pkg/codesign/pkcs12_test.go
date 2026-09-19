package codesign

import (
	"bytes"
	"os"
	"testing"
)

func TestPKCS12ReferenceImports(t *testing.T) {
	for _, algorithm := range []string{"rsa", "p256", "p384", "p521"} {
		for _, profile := range []string{"legacy", "modern", "empty", "unicode", "aes128", "aes192"} {
			if algorithm != "rsa" && profile != "legacy" && profile != "modern" {
				continue
			}
			t.Run(algorithm+"/"+profile, func(t *testing.T) {
				data, err := os.ReadFile("../../testdata/pkcs12/" + algorithm + "-" + profile + ".p12")
				if err != nil {
					t.Fatal(err)
				}
				password := "public-codesign-test-only"
				if profile == "empty" {
					password = ""
				}
				if profile == "unicode" {
					password = "café🔑"
				}
				id, err := LoadIdentityPKCS12(data, password)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(id.Certificates[0], testIdentity(t, algorithm).Certificates[0]) {
					t.Fatal("wrong certificate")
				}
				if _, err := LoadIdentityPKCS12(data, "incorrect"); err == nil {
					t.Fatal("wrong password accepted")
				}
				data[len(data)-1] ^= 1
				if _, err := LoadIdentityPKCS12(data, password); err == nil {
					t.Fatal("corruption accepted")
				}
			})
		}
	}
}
