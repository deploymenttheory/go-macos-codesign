package codesign

// Certificate and key decoding deliberately uses ASN.1 and Go's cryptographic
// primitives without crypto/x509, which links Apple's trust bridge on Darwin.
// This is a bounded identity parser, not a replacement for PKIX path validation.
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

var (
	oidRSA  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidEC   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type certificateExtension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}
type publicKeyInfo struct {
	Algorithm algorithmIdentifier
	Key       asn1.BitString
}
type certificateTBS struct {
	Raw        asn1.RawContent
	Version    int `asn1:"optional,explicit,tag:0,default:0"`
	Serial     *big.Int
	Signature  algorithmIdentifier
	Issuer     asn1.RawValue
	Validity   struct{ NotBefore, NotAfter time.Time }
	Subject    asn1.RawValue
	PublicKey  publicKeyInfo
	IssuerID   asn1.BitString         `asn1:"optional,tag:1"`
	SubjectID  asn1.BitString         `asn1:"optional,tag:2"`
	Extensions []certificateExtension `asn1:"optional,explicit,tag:3"`
}
type certificateASN struct {
	TBS       certificateTBS
	Algorithm algorithmIdentifier
	Signature asn1.BitString
}

type certificate struct {
	raw       []byte
	tbs       certificateTBS
	public    crypto.PublicKey
	signature []byte
}

func decodeDER(data []byte, out any) error {
	if len(data) == 0 || len(data) > 16<<20 {
		return malformed("DER size")
	}
	rest, err := asn1.Unmarshal(data, out)
	if err != nil {
		return malformed("DER: %v", err)
	}
	if len(rest) != 0 {
		return malformed("trailing DER data")
	}
	return nil
}

func nullOrAbsent(p asn1.RawValue) bool {
	return len(p.FullBytes) == 0 || bytes.Equal(p.FullBytes, []byte{5, 0})
}

func namedCurve(oid asn1.ObjectIdentifier) (elliptic.Curve, error) {
	switch {
	case oid.Equal(oidP256):
		return elliptic.P256(), nil
	case oid.Equal(oidP384):
		return elliptic.P384(), nil
	case oid.Equal(oidP521):
		return elliptic.P521(), nil
	default:
		return nil, unsupported("elliptic curve " + oid.String())
	}
}

func parsePublicKey(info publicKeyInfo) (crypto.PublicKey, error) {
	if info.Key.BitLength != len(info.Key.Bytes)*8 {
		return nil, malformed("public key bit string")
	}
	switch {
	case info.Algorithm.Algorithm.Equal(oidRSA):
		if !nullOrAbsent(info.Algorithm.Parameters) {
			return nil, malformed("RSA parameters")
		}
		var key rsa.PublicKey
		if err := decodeDER(info.Key.Bytes, &key); err != nil {
			return nil, err
		}
		if key.N == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.N.Bit(0) == 0 || key.E < 3 || key.E > 1<<31-1 || key.E&1 == 0 {
			return nil, unsupported("RSA key must be 2048–8192 bits with a valid public exponent")
		}
		return &key, nil
	case info.Algorithm.Algorithm.Equal(oidEC):
		var oid asn1.ObjectIdentifier
		if err := decodeDER(info.Algorithm.Parameters.FullBytes, &oid); err != nil {
			return nil, err
		}
		curve, err := namedCurve(oid)
		if err != nil {
			return nil, err
		}
		key, err := ecdsa.ParseUncompressedPublicKey(curve, info.Key.Bytes)
		if err != nil {
			return nil, malformed("EC public point: %v", err)
		}
		return key, nil
	default:
		return nil, unsupported("certificate public key algorithm " + info.Algorithm.Algorithm.String())
	}
}

func parseCertificate(data []byte) (*certificate, error) {
	var value certificateASN
	if err := decodeDER(data, &value); err != nil {
		return nil, err
	}
	tbs := value.TBS
	if tbs.Version < 0 || tbs.Version > 2 || tbs.Serial == nil || tbs.Serial.Sign() <= 0 || !tbs.Signature.Algorithm.Equal(value.Algorithm.Algorithm) ||
		!bytes.Equal(tbs.Signature.Parameters.FullBytes, value.Algorithm.Parameters.FullBytes) || tbs.Issuer.Tag != asn1.TagSequence || tbs.Subject.Tag != asn1.TagSequence ||
		tbs.Validity.NotAfter.Before(tbs.Validity.NotBefore) || value.Signature.BitLength == 0 || value.Signature.BitLength != len(value.Signature.Bytes)*8 {
		return nil, malformed("certificate fields")
	}
	seen := map[string]bool{}
	for _, ext := range tbs.Extensions {
		if seen[ext.ID.String()] {
			return nil, malformed("duplicate certificate extension")
		}
		seen[ext.ID.String()] = true
	}
	pub, err := parsePublicKey(tbs.PublicKey)
	if err != nil {
		return nil, err
	}
	return &certificate{raw: bytes.Clone(data), tbs: tbs, public: pub, signature: value.Signature.Bytes}, nil
}

func checkCertificatePurpose(c *certificate, at time.Time) error {
	return certificatePolicy(c, at, false, 0)
}

func pemBlocks(data []byte) ([]*pem.Block, error) {
	if len(data) > 16<<20 {
		return nil, malformed("PEM size limit")
	}
	var blocks []*pem.Block
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return nil, malformed("text outside PEM block")
		}
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, malformed("PEM block")
		}
		// pem.Decode can skip a malformed block and find a later valid one.
		// Identity import must not silently discard the first block.
		if bytes.Count(data[:len(data)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return nil, malformed("skipped malformed PEM block")
		}
		if len(block.Headers) != 0 {
			return nil, unsupported("PEM encryption or headers")
		}
		blocks = append(blocks, block)
		data = rest
	}
	return blocks, nil
}

// ParseCertificatesPEM reads a certificate-only PEM bundle. Certificate trust
// and chain validation are not inferred from successful parsing.
func ParseCertificatesPEM(data []byte) ([][]byte, error) {
	blocks, err := pemBlocks(data)
	if err != nil {
		return nil, err
	}
	var certs [][]byte
	for _, block := range blocks {
		if block.Type != "CERTIFICATE" {
			return nil, malformed("expected CERTIFICATE PEM block")
		}
		if _, err := parseCertificate(block.Bytes); err != nil {
			return nil, err
		}
		certs = append(certs, block.Bytes)
	}
	if len(certs) == 0 {
		return nil, malformed("no PEM certificates")
	}
	return certs, nil
}

// LoadIdentityPEM loads a leaf-first certificate bundle and an unencrypted
// PKCS#1, SEC1, or PKCS#8 private key. Passing nil keyPEM loads a combined bundle.
func LoadIdentityPEM(certPEM, keyPEM []byte) (*Identity, error) {
	blocks, err := pemBlocks(certPEM)
	if err != nil {
		return nil, err
	}
	if len(keyPEM) > 0 {
		keys, err := pemBlocks(keyPEM)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, keys...)
	}
	id := &Identity{}
	for _, block := range blocks {
		if block.Type == "CERTIFICATE" {
			id.Certificates = append(id.Certificates, block.Bytes)
			continue
		}
		if id.Signer != nil {
			return nil, malformed("multiple private keys")
		}
		id.Signer, err = parsePrivateKey(block.Type, block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	_, err = id.validate()
	if err != nil {
		return nil, err
	}
	return id, nil
}

func (id *Identity) validate() (*certificate, error) {
	if id == nil || id.Signer == nil || len(id.Certificates) == 0 || len(id.Certificates) > 32 {
		return nil, malformed("identity requires a signer and 1–32 certificates")
	}
	var leaf *certificate
	seen := map[string]bool{}
	for _, der := range id.Certificates {
		if seen[string(der)] {
			return nil, malformed("duplicate identity certificate")
		}
		seen[string(der)] = true
		cert, err := parseCertificate(der)
		if err != nil {
			return nil, err
		}
		if leaf == nil {
			leaf = cert
		}
	}
	var equal bool
	switch pub := leaf.public.(type) {
	case *rsa.PublicKey:
		equal = pub.Equal(id.Signer.Public())
	case *ecdsa.PublicKey:
		equal = pub.Equal(id.Signer.Public())
	}
	if !equal {
		return nil, invalid("private key does not match leaf certificate")
	}
	return leaf, nil
}

func parsePrivateKey(kind string, data []byte) (crypto.Signer, error) {
	if len(data) > 64<<10 {
		return nil, malformed("private key size limit")
	}
	switch kind {
	case "RSA PRIVATE KEY":
		var p struct {
			Version               int
			N                     *big.Int
			E                     int
			D, P, Q, DP, DQ, QInv *big.Int
		}
		if err := decodeDER(data, &p); err != nil {
			return nil, err
		}
		if p.Version != 0 {
			return nil, unsupported("multi-prime RSA")
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: p.N, E: p.E}, D: p.D, Primes: []*big.Int{p.P, p.Q}}
		if p.N == nil || p.N.BitLen() < 2048 || p.N.BitLen() > 8192 || p.D == nil || p.P == nil || p.Q == nil || p.D.BitLen() > 8192 || p.P.BitLen() > 8192 || p.Q.BitLen() > 8192 {
			return nil, malformed("RSA private key bounds")
		}
		if err := key.Validate(); err != nil {
			return nil, malformed("RSA private key: %v", err)
		}
		key.Precompute()
		if p.DP == nil || p.DQ == nil || p.QInv == nil || p.DP.Cmp(key.Precomputed.Dp) != 0 || p.DQ.Cmp(key.Precomputed.Dq) != 0 || p.QInv.Cmp(key.Precomputed.Qinv) != 0 {
			return nil, malformed("RSA CRT parameters")
		}
		return key, nil
	case "EC PRIVATE KEY":
		return parseECPrivateKey(data, nil)
	case "PRIVATE KEY":
		var p struct {
			Version   int
			Algorithm algorithmIdentifier
			Key       []byte
		}
		if err := decodeDER(data, &p); err != nil {
			return nil, err
		}
		if p.Version != 0 {
			return nil, unsupported("PKCS#8 version")
		}
		if p.Algorithm.Algorithm.Equal(oidRSA) {
			if !nullOrAbsent(p.Algorithm.Parameters) {
				return nil, malformed("PKCS#8 RSA parameters")
			}
			return parsePrivateKey("RSA PRIVATE KEY", p.Key)
		}
		if p.Algorithm.Algorithm.Equal(oidEC) {
			var oid asn1.ObjectIdentifier
			if err := decodeDER(p.Algorithm.Parameters.FullBytes, &oid); err != nil {
				return nil, err
			}
			return parseECPrivateKey(p.Key, oid)
		}
		return nil, unsupported("PKCS#8 key algorithm")
	default:
		return nil, unsupported(fmt.Sprintf("PEM block %q", kind))
	}
}

func parseECPrivateKey(data []byte, outer asn1.ObjectIdentifier) (crypto.Signer, error) {
	var p struct {
		Version int
		Key     []byte
		Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		Public  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	if err := decodeDER(data, &p); err != nil {
		return nil, err
	}
	if p.Version != 1 {
		return nil, malformed("EC private key version")
	}
	if len(outer) > 0 && len(p.Curve) > 0 && !outer.Equal(p.Curve) {
		return nil, malformed("conflicting EC curves")
	}
	if len(p.Curve) == 0 {
		p.Curve = outer
	}
	curve, err := namedCurve(p.Curve)
	if err != nil {
		return nil, err
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(p.Key) > size {
		return nil, malformed("EC private scalar")
	}
	raw := make([]byte, size)
	copy(raw[size-len(p.Key):], p.Key)
	key, err := ecdsa.ParseRawPrivateKey(curve, raw)
	if err != nil {
		return nil, malformed("EC private scalar: %v", err)
	}
	pub, _ := key.PublicKey.Bytes() // ParseRawPrivateKey returned a valid NIST key.
	if p.Public.BitLength != 0 && (p.Public.BitLength != len(p.Public.Bytes)*8 || !bytes.Equal(p.Public.Bytes, pub)) {
		return nil, malformed("EC private/public key mismatch")
	}
	return key, nil
}
