package codesign

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/asn1"
	"testing"
)

func TestPKCS12CipherBounds(t *testing.T) {
	type kdfParams struct {
		Salt       []byte
		Iterations int
		Length     int                 `asn1:"optional"`
		PRF        algorithmIdentifier `asn1:"optional"`
	}
	type pbesParams struct {
		KDF    algorithmIdentifier
		Cipher algorithmIdentifier
	}
	kdf := kdfParams{Salt: []byte("salt"), Iterations: 2}
	params := pbesParams{KDF: algorithmIdentifier{Algorithm: pfxOID("1.2.840.113549.1.5.12"), Parameters: asn1.RawValue{FullBytes: testDER(t, kdf)}}, Cipher: algorithmIdentifier{Algorithm: pfxOID("2.16.840.1.101.3.4.1.42"), Parameters: asn1.RawValue{FullBytes: testDER(t, make([]byte, 16))}}}
	algorithm := func(p pbesParams) algorithmIdentifier {
		return algorithmIdentifier{Algorithm: pfxOID("1.2.840.113549.1.5.13"), Parameters: asn1.RawValue{FullBytes: testDER(t, p)}}
	}
	key, err := pbkdf2.Key(sha1.New, "password", kdf.Salt, kdf.Iterations, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	encrypt := func(plain []byte) []byte {
		out := make([]byte, len(plain))
		cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(out, plain)
		return out
	}
	data := encrypt(append([]byte("secret"), bytes.Repeat([]byte{10}, 10)...))
	budget := 100
	out, err := pfxDecrypt(algorithm(params), data, "password", nil, &budget)
	if err != nil || string(out) != "secret" {
		t.Fatal(string(out), err)
	}
	for _, tc := range []struct {
		name string
		edit func(*pbesParams)
	}{
		{"bad-kdf", func(p *pbesParams) { p.KDF.Algorithm = oidData }},
		{"kdf-der", func(p *pbesParams) { p.KDF.Parameters.FullBytes = []byte{1} }},
		{"iterations", func(p *pbesParams) { v := kdf; v.Iterations = 1000001; p.KDF.Parameters.FullBytes = testDER(t, v) }},
		{"prf", func(p *pbesParams) { v := kdf; v.PRF.Algorithm = oidData; p.KDF.Parameters.FullBytes = testDER(t, v) }},
		{"key-length", func(p *pbesParams) { v := kdf; v.Length = 16; p.KDF.Parameters.FullBytes = testDER(t, v) }},
		{"cipher", func(p *pbesParams) { p.Cipher.Algorithm = oidData }},
		{"iv-der", func(p *pbesParams) { p.Cipher.Parameters.FullBytes = []byte{1} }},
		{"iv-length", func(p *pbesParams) { p.Cipher.Parameters.FullBytes = testDER(t, []byte{1}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := params
			tc.edit(&p)
			budget := 100
			if _, err := pfxDecrypt(algorithm(p), data, "password", nil, &budget); err == nil {
				t.Fatal("bad cipher parameters accepted")
			}
		})
	}
	for _, bad := range [][]byte{nil, {1}, encrypt(make([]byte, 16)), encrypt(append(bytes.Repeat([]byte{1}, 15), 2))} {
		budget := 100
		if _, err := pfxDecrypt(algorithm(params), bad, "password", nil, &budget); err == nil {
			t.Fatal("bad ciphertext/padding")
		}
	}
	for _, oid := range []asn1.ObjectIdentifier{oidData, pfxOID("1.2.840.113549.1.5.13"), pfxOID("1.2.840.113549.1.12.1.3")} {
		budget := 100
		if _, err := pfxDecrypt(algorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{FullBytes: []byte{1}}}, data, "password", nil, &budget); err == nil {
			t.Fatal("bad encryption DER")
		}
	}
	budget = 2
	if _, err := pfxDecrypt(algorithm(params), data, "password", nil, &budget); err == nil {
		t.Fatal("PBKDF2 block budget")
	}
	legacy := algorithmIdentifier{Algorithm: pfxOID("1.2.840.113549.1.12.1.3"), Parameters: asn1.RawValue{FullBytes: testDER(t, struct {
		Salt       []byte
		Iterations int
	}{[]byte("salt"), 2})}}
	budget = 4
	if _, err := pfxDecrypt(legacy, data, "password", nil, &budget); err == nil {
		t.Fatal("legacy KDF budget")
	}
}
