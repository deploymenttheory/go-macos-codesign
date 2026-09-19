package codesign

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"hash"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deploymenttheory/go-macos-codesign/third_party/rc2"
)

type pfxMAC struct {
	Digest struct {
		Algorithm algorithmIdentifier
		Value     []byte
	}
	Salt       []byte
	Iterations int `asn1:"optional,default:1"`
}
type pfxArchive struct {
	Version int
	Content cmsContent
	MAC     pfxMAC `asn1:"optional"`
}
type pfxBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue   `asn1:"explicit,tag:0"`
	Attributes []asn1.RawValue `asn1:"optional,set"`
}
type encryptedPrivateKey struct {
	Algorithm algorithmIdentifier
	Data      []byte
}

// LoadIdentityPKCS12 imports a password-authenticated, single-key PFX. It accepts
// PBES2/PBKDF2 with AES-CBC and legacy PKCS#12 3DES/RC2-40 encryption. Missing MACs,
// unknown bags, multiple keys, invalid passwords and excessive KDF work fail
// closed. No system keychain or crypto/x509 dependency is used.
func LoadIdentityPKCS12(data []byte, password string) (*Identity, error) {
	if !utf8.ValidString(password) || len(password) > 1024 {
		return nil, malformed("PKCS#12 password encoding or length")
	}
	var pfx pfxArchive
	if err := decodeDER(data, &pfx); err != nil {
		return nil, err
	}
	if pfx.Version != 3 || !pfx.Content.Type.Equal(oidData) {
		return nil, unsupported("PKCS#12 version or public-key integrity")
	}
	var safe []byte
	if err := decodeDER(pfx.Content.Content.Bytes, &safe); err != nil {
		return nil, err
	}
	bmp := pfxPassword(password)
	budget := 2000000
	checkMAC := func(pass []byte) error {
		m := pfx.MAC
		h, err := pfxHash(m.Digest.Algorithm, false)
		if err != nil {
			return err
		}
		if len(m.Digest.Value) != h().Size() {
			return malformed("PKCS#12 MAC is required")
		}
		if err := pfxWork(m.Salt, m.Iterations, &budget); err != nil {
			return err
		}
		key := pfxKDF(h, pass, m.Salt, m.Iterations, 3, h().Size())
		mac := hmac.New(h, key)
		_, _ = mac.Write(safe)
		if !hmac.Equal(mac.Sum(nil), m.Digest.Value) {
			return invalid("PKCS#12 password or MAC")
		}
		return nil
	}
	if err := checkMAC(bmp); err != nil {
		// Historical encoders distinguish empty and absent passwords.
		if password != "" {
			return nil, err
		}
		if err := checkMAC(nil); err != nil {
			return nil, err
		}
		bmp = nil
	}
	var contents []cmsContent
	if err := decodeDER(safe, &contents); err != nil {
		return nil, err
	}
	if len(contents) == 0 || len(contents) > 32 {
		return nil, malformed("PKCS#12 safe count")
	}
	id := &Identity{}
	for _, content := range contents {
		var bagsDER []byte
		switch content.Type.String() {
		case "1.2.840.113549.1.7.1":
			if err := decodeDER(content.Content.Bytes, &bagsDER); err != nil {
				return nil, err
			}
		case "1.2.840.113549.1.7.6":
			var encrypted struct {
				Version int
				Content struct {
					Type      asn1.ObjectIdentifier
					Algorithm algorithmIdentifier
					Data      []byte `asn1:"tag:0"`
				}
			}
			if err := decodeDER(content.Content.Bytes, &encrypted); err != nil {
				return nil, err
			}
			if encrypted.Version != 0 || !encrypted.Content.Type.Equal(oidData) {
				return nil, unsupported("PKCS#12 encrypted content")
			}
			var err error
			bagsDER, err = pfxDecrypt(encrypted.Content.Algorithm, encrypted.Content.Data, password, bmp, &budget)
			if err != nil {
				return nil, err
			}
		default:
			return nil, unsupported("PKCS#12 content type")
		}
		var bags []pfxBag
		if err := decodeDER(bagsDER, &bags); err != nil {
			return nil, err
		}
		if len(bags) > 64 {
			return nil, malformed("PKCS#12 bag count")
		}
		for _, bag := range bags {
			switch bag.ID.String() {
			case "1.2.840.113549.1.12.10.1.3":
				var cert struct {
					ID    asn1.ObjectIdentifier
					Value []byte `asn1:"explicit,tag:0"`
				}
				if err := decodeDER(bag.Value.Bytes, &cert); err != nil {
					return nil, err
				}
				if cert.ID.String() != "1.2.840.113549.1.9.22.1" {
					return nil, unsupported("PKCS#12 certificate bag")
				}
				id.Certificates = append(id.Certificates, cert.Value)
			case "1.2.840.113549.1.12.10.1.1", "1.2.840.113549.1.12.10.1.2":
				if id.Signer != nil {
					return nil, malformed("multiple PKCS#12 private keys")
				}
				key := bag.Value.Bytes
				if bag.ID[len(bag.ID)-1] == 2 {
					var encrypted encryptedPrivateKey
					if err := decodeDER(key, &encrypted); err != nil {
						return nil, err
					}
					var err error
					key, err = pfxDecrypt(encrypted.Algorithm, encrypted.Data, password, bmp, &budget)
					if err != nil {
						return nil, err
					}
				}
				var err error
				id.Signer, err = parsePrivateKey("PRIVATE KEY", key)
				if err != nil {
					return nil, err
				}
			default:
				return nil, unsupported("PKCS#12 bag type " + bag.ID.String())
			}
		}
	}
	if id.Signer == nil || len(id.Certificates) == 0 || len(id.Certificates) > 32 {
		return nil, malformed("PKCS#12 requires one key and 1–32 certificates")
	}
	// Bag order and localKeyID are hints, never proof of key/certificate pairing.
	index := -1
	for i, der := range id.Certificates {
		candidate := &Identity{Signer: id.Signer, Certificates: [][]byte{der}}
		if _, err := candidate.validate(); err == nil {
			if index != -1 {
				return nil, malformed("ambiguous PKCS#12 signer certificate")
			}
			index = i
		}
	}
	if index < 0 {
		return nil, invalid("PKCS#12 key has no matching certificate")
	}
	path, err := linkedCertificates(id.Certificates[index], id.Certificates)
	if err != nil {
		return nil, err
	}
	if len(path) != len(id.Certificates) {
		return nil, malformed("PKCS#12 contains unrelated or duplicate certificates")
	}
	for i, c := range path {
		id.Certificates[i] = c.raw
	}
	return id, nil
}

func pfxPassword(password string) []byte {
	units := utf16.Encode([]rune(password))
	out := make([]byte, 2*(len(units)+1))
	for i, u := range units {
		be.PutUint16(out[i*2:], u)
	}
	return out
}

func pfxHash(alg algorithmIdentifier, prf bool) (func() hash.Hash, error) {
	if !nullOrAbsent(alg.Parameters) {
		return nil, malformed("PKCS#12 hash parameters")
	}
	if prf {
		switch alg.Algorithm.String() {
		case "1.2.840.113549.2.7":
			return sha1.New, nil
		case "1.2.840.113549.2.9":
			return sha256.New, nil
		case "1.2.840.113549.2.10":
			return sha512.New384, nil
		case "1.2.840.113549.2.11":
			return sha512.New, nil
		}
	} else {
		switch alg.Algorithm.String() {
		case "1.3.14.3.2.26":
			return sha1.New, nil
		case "2.16.840.1.101.3.4.2.1":
			return sha256.New, nil
		case "2.16.840.1.101.3.4.2.2":
			return sha512.New384, nil
		case "2.16.840.1.101.3.4.2.3":
			return sha512.New, nil
		}
	}
	return nil, unsupported("PKCS#12 hash algorithm")
}

func pfxWork(salt []byte, iterations int, budget *int) error {
	if len(salt) < 1 || len(salt) > 1024 || iterations < 1 || iterations > 1000000 || iterations > *budget {
		return malformed("PKCS#12 KDF bounds")
	}
	*budget -= iterations
	return nil
}

// RFC 7292 Appendix B. The caller validates all sizes and work factors.
func pfxKDF(newHash func() hash.Hash, password, salt []byte, iterations int, id byte, n int) []byte {
	h := newHash()
	v := h.BlockSize()
	d := bytes.Repeat([]byte{id}, v)
	expand := func(in []byte) []byte {
		if len(in) == 0 {
			return nil
		}
		out := make([]byte, v*((len(in)+v-1)/v))
		for i := range out {
			out[i] = in[i%len(in)]
		}
		return out
	}
	i := append(expand(salt), expand(password)...)
	var out []byte
	for len(out) < n {
		h.Reset()
		_, _ = h.Write(d)
		_, _ = h.Write(i)
		a := h.Sum(nil)
		for j := 1; j < iterations; j++ {
			h.Reset()
			_, _ = h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a...)
		b := make([]byte, v)
		for j := range b {
			b[j] = a[j%len(a)]
		}
		for j := 0; j < len(i); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				carry += int(i[j+k]) + int(b[k])
				i[j+k] = byte(carry)
				carry >>= 8
			}
		}
	}
	return out[:n]
}

func pfxDecrypt(alg algorithmIdentifier, data []byte, password string, bmp []byte, budget *int) ([]byte, error) {
	var block cipher.Block
	var iv []byte
	switch alg.Algorithm.String() {
	case "1.2.840.113549.1.5.13":
		var params struct {
			KDF    algorithmIdentifier
			Cipher algorithmIdentifier
		}
		if err := decodeDER(alg.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}
		if params.KDF.Algorithm.String() != "1.2.840.113549.1.5.12" {
			return nil, unsupported("PKCS#12 KDF")
		}
		var kdf struct {
			Salt       []byte
			Iterations int
			Length     int                 `asn1:"optional"`
			PRF        algorithmIdentifier `asn1:"optional"`
		}
		if err := decodeDER(params.KDF.Parameters.FullBytes, &kdf); err != nil {
			return nil, err
		}
		if err := pfxWork(kdf.Salt, kdf.Iterations, budget); err != nil {
			return nil, err
		}
		if len(kdf.PRF.Algorithm) == 0 {
			kdf.PRF.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
		}
		h, err := pfxHash(kdf.PRF, true)
		if err != nil {
			return nil, err
		}
		n := 0
		switch params.Cipher.Algorithm.String() {
		case "2.16.840.1.101.3.4.1.2":
			n = 16
		case "2.16.840.1.101.3.4.1.22":
			n = 24
		case "2.16.840.1.101.3.4.1.42":
			n = 32
		default:
			return nil, unsupported("PKCS#12 cipher")
		}
		if kdf.Length != 0 && kdf.Length != n {
			return nil, malformed("PKCS#12 key length")
		}
		for block := 1; block < (n+h().Size()-1)/h().Size(); block++ {
			if err := pfxWork(kdf.Salt, kdf.Iterations, budget); err != nil {
				return nil, err
			}
		}
		if err := decodeDER(params.Cipher.Parameters.FullBytes, &iv); err != nil {
			return nil, err
		}
		key, err := pbkdf2.Key(h, password, kdf.Salt, kdf.Iterations, n)
		if err != nil {
			return nil, err
		}
		block, _ = aes.NewCipher(key)
	case "1.2.840.113549.1.12.1.3", "1.2.840.113549.1.12.1.6":
		var params struct {
			Salt       []byte
			Iterations int
		}
		if err := decodeDER(alg.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}
		// A 3DES key needs two SHA-1 blocks, plus one IV block.
		for range 3 {
			if err := pfxWork(params.Salt, params.Iterations, budget); err != nil {
				return nil, err
			}
		}
		iv = pfxKDF(sha1.New, bmp, params.Salt, params.Iterations, 2, 8)
		if alg.Algorithm[len(alg.Algorithm)-1] == 3 {
			var err error
			block, err = des.NewTripleDESCipher(pfxKDF(sha1.New, bmp, params.Salt, params.Iterations, 1, 24))
			if err != nil {
				return nil, unsupported("legacy PKCS#12 cipher: " + err.Error())
			}
		} else {
			block, _ = rc2.New(pfxKDF(sha1.New, bmp, params.Salt, params.Iterations, 1, 5), 40)
		}
	default:
		return nil, unsupported("PKCS#12 encryption algorithm")
	}
	if len(iv) != block.BlockSize() || len(data) == 0 || len(data)%block.BlockSize() != 0 {
		return nil, malformed("PKCS#12 CBC length or IV")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	n := int(out[len(out)-1])
	if n < 1 || n > block.BlockSize() {
		return nil, invalid("PKCS#12 padding")
	}
	for _, b := range out[len(out)-n:] {
		if int(b) != n {
			return nil, invalid("PKCS#12 padding")
		}
	}
	return out[:len(out)-n], nil
}
