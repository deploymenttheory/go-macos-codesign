package codesign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"howett.net/plist"
)

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidHashAgility   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
	oidHashAgilityV2 = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA256RSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA256ECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

type cmsContent struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"optional,explicit,tag:0"`
}
type cmsIssuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}
type cmsSigner struct {
	Version    int
	ID         cmsIssuerSerial
	Digest     algorithmIdentifier
	Attributes asn1.RawValue `asn1:"optional,tag:0"`
	Algorithm  algorithmIdentifier
	Signature  []byte
	Unsigned   asn1.RawValue `asn1:"optional,tag:1"`
}
type cmsSignedData struct {
	Version      int
	Digests      []algorithmIdentifier `asn1:"set"`
	Content      cmsContent
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	CRLs         asn1.RawValue `asn1:"optional,tag:1"`
	Signers      []cmsSigner   `asn1:"set"`
}
type cmsAttribute struct {
	ID     asn1.ObjectIdentifier
	Values asn1.RawValue
}
type cdHashPlist struct {
	CDHashes [][]byte `plist:"cdhashes"`
}

// CMSInfo describes a cryptographically verified signature, not certificate
// trust. SigningTime is an authenticated claim, not a trusted timestamp.
type CMSInfo struct {
	SignerCertificate []byte
	Certificates      [][]byte
	SigningTime       time.Time
	// Timestamp is cryptographically bound, but its CA trust is not asserted.
	Timestamp *TimestampInfo
}

func derSequence(parts ...[]byte) []byte { return derWrap(0x30, bytes.Join(parts, nil)) }
func derSet(parts ...[]byte) []byte {
	sort.Slice(parts, func(i, j int) bool { return bytes.Compare(parts[i], parts[j]) < 0 })
	return derWrap(0x31, bytes.Join(parts, nil))
}

// All callers pass constant, valid algorithm OIDs.
func derOID(oid asn1.ObjectIdentifier) []byte { out, _ := asn1.Marshal(oid); return out }
func derAlgorithm(oid asn1.ObjectIdentifier, null bool) []byte {
	params := []byte(nil)
	if null {
		params = []byte{5, 0}
	}
	return derSequence(derOID(oid), params)
}
func derPositive(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return derWrap(2, b)
}
func derAttribute(oid asn1.ObjectIdentifier, values ...[]byte) []byte {
	return derSequence(derOID(oid), derSet(values...))
}

func directoryHashes(directories [][]byte) (cdHashPlist, [][]byte, error) {
	var pl cdHashPlist
	var agility [][]byte
	if len(directories) == 0 || len(directories) > 5 {
		return pl, nil, malformed("CMS CodeDirectory count")
	}
	seen := map[string]bool{}
	for _, raw := range directories {
		d, err := parseDirectory(raw)
		if err != nil {
			return pl, nil, err
		}
		if len(raw) > 16<<20 || uint64(be.Uint32(raw[4:])) != uint64(len(raw)) {
			return pl, nil, malformed("CMS CodeDirectory length")
		}
		var oid asn1.ObjectIdentifier
		kind := d.HashType
		switch kind {
		case 1:
			oid = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
		case 2, 3:
			oid, kind = oidSHA256, 2
		case 4:
			oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
		}
		if seen[oid.String()] {
			return pl, nil, unsupported("multiple CodeDirectories using the same digest")
		}
		seen[oid.String()] = true
		h, _ := digest(kind, raw)
		pl.CDHashes = append(pl.CDHashes, h[:20])
		agility = append(agility, derSequence(derOID(oid), derWrap(4, h)))
	}
	return pl, agility, nil
}

// SignCMS creates detached SHA-256 CMS SignedData over the primary
// CodeDirectory, with Apple attributes binding every supplied CodeDirectory.
// The first certificate is the signer; the remaining certificates are embedded
// but are not trusted or path-validated. A zero signingTime uses the current time.
func SignCMS(ctx context.Context, id *Identity, directories [][]byte, signingTime time.Time) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	leaf, err := id.validate()
	if err != nil {
		return nil, err
	}
	if signingTime.IsZero() {
		signingTime = time.Now()
	}
	signingTime = signingTime.UTC().Truncate(time.Second)
	if err := checkCertificatePurpose(leaf, signingTime); err != nil {
		return nil, err
	}
	pl, agility, err := directoryHashes(directories)
	if err != nil {
		return nil, err
	}
	plistBytes := appleHashAgilityPlist(pl)
	date, err := asn1.Marshal(signingTime)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(directories[0])
	attrs := derSet(
		derAttribute(oidContentType, derOID(oidData)),
		derAttribute(oidMessageDigest, derWrap(4, digest[:])),
		derAttribute(oidSigningTime, date),
		derAttribute(oidHashAgility, derWrap(4, plistBytes)),
		derAttribute(oidHashAgilityV2, agility...),
	)
	toSign := sha256.Sum256(attrs)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sig, err := id.Signer.Sign(rand.Reader, toSign[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("CMS signing: %w", err)
	}
	sigOID, withNull := oidSHA256RSA, true
	if _, ok := leaf.public.(*ecdsa.PublicKey); ok {
		sigOID, withNull = oidSHA256ECDSA, false
	}
	alg := algorithmIdentifier{Algorithm: sigOID}
	// Check custom crypto.Signer implementations before publishing their output.
	if err := verifyCMSSignature(leaf.public, alg, toSign[:], sig); err != nil {
		return nil, err
	}
	serial := derSequence(leaf.tbs.Issuer.FullBytes, derPositive(leaf.tbs.Serial))
	attrs[0] = 0xa0 // Signed as SET OF, stored as [0] IMPLICIT (RFC 5652 §5.4).
	signer := derSequence([]byte{2, 1, 1}, serial, derAlgorithm(oidSHA256, true), attrs, derAlgorithm(sigOID, withNull), derWrap(4, sig))
	certs := append([][]byte(nil), id.Certificates...)
	set := derSet(certs...)
	set[0] = 0xa0
	signed := cmsBERWrap(0x30, []byte{2, 1, 1}, derSet(derAlgorithm(oidSHA256, true)), cmsBERWrap(0x30, derOID(oidData)), set, derSet(signer))
	return cmsBERWrap(0x30, derOID(oidSignedData), cmsBERWrap(0xa0, signed)), ctx.Err()
}

// CoreFoundation's XML representation is authenticated by the CMS signature.
// Hashes are 20-byte CDHashes, so each base64 value fits on a single line.
func appleHashAgilityPlist(pl cdHashPlist) []byte {
	var out strings.Builder
	out.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>cdhashes</key>\n\t<array>\n")
	for _, hash := range pl.CDHashes {
		out.WriteString("\t\t<data>\n\t\t" + base64.StdEncoding.EncodeToString(hash) + "\n\t\t</data>\n")
	}
	out.WriteString("\t</array>\n</dict>\n</plist>\n")
	return []byte(out.String())
}

func verifyCMSSignature(pub crypto.PublicKey, alg algorithmIdentifier, hashed, sig []byte) error {
	return verifyCMSDigestSignature(pub, alg, crypto.SHA256, hashed, sig)
}

func verifyCMSDigestSignature(pub crypto.PublicKey, alg algorithmIdentifier, h crypto.Hash, hashed, sig []byte) error {
	rsaOID, ecOID := "1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2"
	if h == crypto.SHA1 {
		rsaOID, ecOID = "1.2.840.113549.1.1.5", "1.2.840.10045.4.1"
	}
	if h == crypto.SHA384 {
		rsaOID, ecOID = "1.2.840.113549.1.1.12", "1.2.840.10045.4.3.3"
	}
	if h == crypto.SHA512 {
		rsaOID, ecOID = "1.2.840.113549.1.1.13", "1.2.840.10045.4.3.4"
	}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if !alg.Algorithm.Equal(oidRSA) && alg.Algorithm.String() != rsaOID || !nullOrAbsent(alg.Parameters) {
			return unsupported("CMS RSA signature algorithm")
		}
		if err := rsa.VerifyPKCS1v15(key, h, hashed, sig); err != nil {
			return invalid("CMS RSA signature: %v", err)
		}
	case *ecdsa.PublicKey:
		if alg.Algorithm.String() != ecOID || len(alg.Parameters.FullBytes) != 0 {
			return unsupported("CMS ECDSA signature algorithm")
		}
		if !ecdsa.VerifyASN1(key, hashed, sig) {
			return invalid("CMS ECDSA signature")
		}
	default:
		return unsupported("CMS public key")
	}
	return nil
}

func decodeCMS(der []byte) (*cmsSignedData, []*certificate, error) {
	sd, certs, err := decodeSignedData(der)
	if err != nil {
		return nil, nil, err
	}
	if sd.Version != 1 {
		return nil, nil, unsupported("CMS version")
	}
	if !sd.Digests[0].Algorithm.Equal(oidSHA256) || !nullOrAbsent(sd.Digests[0].Parameters) || !sd.Signers[0].Digest.Algorithm.Equal(oidSHA256) || !nullOrAbsent(sd.Signers[0].Digest.Parameters) {
		return nil, nil, unsupported("CMS digest algorithm")
	}
	if !sd.Content.Type.Equal(oidData) || len(sd.Content.Content.FullBytes) > 0 {
		return nil, nil, malformed("CMS requires detached data content")
	}
	return sd, certs, nil
}

func decodeSignedData(der []byte) (*cmsSignedData, []*certificate, error) {
	der, err := cmsEnvelopeDER(der)
	if err != nil {
		return nil, nil, err
	}
	var envelope cmsContent
	if err := decodeDER(der, &envelope); err != nil {
		return nil, nil, err
	}
	if !envelope.Type.Equal(oidSignedData) || envelope.Content.Class != 2 || envelope.Content.Tag != 0 || !envelope.Content.IsCompound {
		return nil, nil, malformed("CMS ContentInfo")
	}
	var sd cmsSignedData
	if err := decodeDER(envelope.Content.Bytes, &sd); err != nil {
		return nil, nil, err
	}
	if len(sd.Signers) != 1 || sd.Signers[0].Version != 1 || len(sd.Digests) != 1 || len(sd.CRLs.FullBytes) > 0 {
		return nil, nil, unsupported("CMS signer count, signer version, digest count, or CRLs")
	}
	if sd.Certificates.Class != 2 || sd.Certificates.Tag != 0 || !sd.Certificates.IsCompound {
		return nil, nil, malformed("CMS certificates")
	}
	var certs []*certificate
	data := sd.Certificates.Bytes
	for len(data) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(data, &raw)
		if err != nil {
			return nil, nil, malformed("CMS certificate encoding")
		}
		cert, err := parseCertificate(raw.FullBytes)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
		if len(certs) > 32 {
			return nil, nil, malformed("CMS certificate count")
		}
		data = rest
	}
	return &sd, certs, nil
}

func parseCMSAttributes(raw asn1.RawValue) (map[string]asn1.RawValue, []byte, error) {
	if raw.Class != 2 || raw.Tag != 0 || !raw.IsCompound || len(raw.Bytes) == 0 {
		return nil, nil, malformed("CMS signed attributes")
	}
	attrs := map[string]asn1.RawValue{}
	data := raw.Bytes
	var previous []byte
	for len(data) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(data, &value)
		if err != nil {
			return nil, nil, malformed("CMS attribute DER")
		}
		if previous != nil && bytes.Compare(previous, value.FullBytes) >= 0 {
			return nil, nil, malformed("CMS attributes are not in DER order")
		}
		previous = value.FullBytes
		var attr cmsAttribute
		if err := decodeDER(value.FullBytes, &attr); err != nil {
			return nil, nil, err
		}
		if attr.Values.Class != 0 || attr.Values.Tag != asn1.TagSet || !attr.Values.IsCompound {
			return nil, nil, malformed("CMS attribute values")
		}
		if _, exists := attrs[attr.ID.String()]; exists {
			return nil, nil, malformed("duplicate CMS attribute")
		}
		attrs[attr.ID.String()] = attr.Values
		data = rest
	}
	return attrs, derWrap(0x31, raw.Bytes), nil
}

// VerifyCMS verifies cryptographic integrity and Apple CodeDirectory bindings.
// It deliberately does not evaluate certificate trust, validity dates, a chain,
// revocation, or timestamp policy. VerifyBytes adds explicit leaf pins or CA
// paths and current-time purpose/validity checks before reporting Valid.
func VerifyCMS(der []byte, directories [][]byte) (*CMSInfo, error) {
	pl, agility, err := directoryHashes(directories)
	if err != nil {
		return nil, err
	}
	sd, certs, err := decodeCMS(der)
	if err != nil {
		return nil, err
	}
	si := sd.Signers[0]
	var signer *certificate
	info := &CMSInfo{}
	for _, cert := range certs {
		info.Certificates = append(info.Certificates, cert.raw)
		if si.ID.Serial != nil && cert.tbs.Serial.Cmp(si.ID.Serial) == 0 && bytes.Equal(cert.tbs.Issuer.FullBytes, si.ID.Issuer.FullBytes) {
			if signer != nil {
				return nil, malformed("ambiguous CMS signer certificate")
			}
			signer = cert
		}
	}
	if signer == nil {
		return nil, invalid("CMS signer certificate is missing")
	}
	attrs, signed, err := parseCMSAttributes(si.Attributes)
	if err != nil {
		return nil, err
	}
	var contentType asn1.ObjectIdentifier
	if err := decodeDER(attrs[oidContentType.String()].Bytes, &contentType); err != nil {
		return nil, err
	}
	if !contentType.Equal(oidData) {
		return nil, invalid("CMS content-type attribute")
	}
	var gotDigest []byte
	if err := decodeDER(attrs[oidMessageDigest.String()].Bytes, &gotDigest); err != nil {
		return nil, err
	}
	wantDigest := sha256.Sum256(directories[0])
	if !bytes.Equal(gotDigest, wantDigest[:]) {
		return nil, invalid("CMS message digest")
	}
	var plistData []byte
	if err := decodeDER(attrs[oidHashAgility.String()].Bytes, &plistData); err != nil {
		return nil, err
	}
	var gotPlist cdHashPlist
	if _, err := plist.Unmarshal(plistData, &gotPlist); err != nil {
		return nil, malformed("CMS hash-agility plist")
	}
	if len(pl.CDHashes) != len(gotPlist.CDHashes) {
		return nil, invalid("CMS hash-agility count")
	}
	for i, want := range pl.CDHashes {
		if !bytes.Equal(want, gotPlist.CDHashes[i]) {
			return nil, invalid("CMS hash-agility digest")
		}
	}
	if !bytes.Equal(attrs[oidHashAgilityV2.String()].FullBytes, derSet(agility...)) {
		return nil, invalid("CMS hash-agility-v2 digests")
	}
	if date, ok := attrs[oidSigningTime.String()]; ok {
		if err := decodeDER(date.Bytes, &info.SigningTime); err != nil {
			return nil, err
		}
	}
	hashed := sha256.Sum256(signed)
	if err := verifyCMSSignature(signer.public, si.Algorithm, hashed[:], si.Signature); err != nil {
		return nil, err
	}
	info.SignerCertificate = bytes.Clone(signer.raw)
	info.Timestamp, err = cmsTimestamp(si)
	if err != nil {
		return nil, err
	}
	return info, nil
}
