package codesign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1" // Legacy Apple TSA CMS/imprints and RFC 3161 ESSCertID.
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

var (
	oidTimestamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	oidTSTInfo   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidESSCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidESSCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

const timestampPurpose = "1.3.6.1.5.5.7.3.8"
const maxTimestampSize = 1 << 20

// TimestampInfo describes a token whose signature and message imprint have
// been checked. CA trust is asserted only by VerifyTimestampToken or VerifyBytes,
// never by VerifyCMS or inspection. No revocation or system trust is implied.
type TimestampInfo struct {
	Token             []byte `json:"-"`
	Time              time.Time
	Policy            string
	SerialNumber      string
	Authorities       []CertificateInfo
	SignerCertificate []byte   `json:"-"`
	Certificates      [][]byte `json:"-"`
	nonce             *big.Int
	imprintHash       crypto.Hash
}

// TimestampOptions supplies transport independently of the portable verifier.
// Provider receives a copy of the CMS signature octets and returns an RFC 3161
// ContentInfo token, not a TimeStampResp wrapper. It must check request/response
// nonces if it contacts a TSA. It may instead return a previously acquired token
// bound to this exact signature. It must honor ctx. No network I/O is built in.
type TimestampOptions struct {
	Provider     func(ctx context.Context, signature []byte) ([]byte, error)
	TrustedRoots [][]byte
	// CurrentTime bounds the claimed timestamp; zero uses the current time.
	CurrentTime time.Time
}

type timestampImprint struct {
	Algorithm algorithmIdentifier
	Digest    []byte
}
type timestampAccuracy struct {
	Seconds *big.Int `asn1:"optional"`
	Millis  int      `asn1:"optional,tag:0"`
	Micros  int      `asn1:"optional,tag:1"`
}
type timestampTSTInfo struct {
	Version    int
	Policy     asn1.ObjectIdentifier
	Imprint    timestampImprint
	Serial     *big.Int
	GenTime    asn1.RawValue
	Accuracy   timestampAccuracy `asn1:"optional"`
	Ordering   bool              `asn1:"optional"`
	Nonce      *big.Int          `asn1:"optional"`
	TSA        asn1.RawValue     `asn1:"optional,tag:0"`
	Extensions asn1.RawValue     `asn1:"optional,tag:1"`
}

// Round-tripping these schema-owned values also detects ignored trailing
// SEQUENCE fields and explicitly encoded defaults that encoding/asn1 accepts.
func decodeTimestampDER[T any](data []byte) (T, error) {
	var value T
	if err := decodeDER(data, &value); err != nil {
		return value, err
	}
	encoded, err := asn1.Marshal(value)
	if err != nil || !bytes.Equal(encoded, data) {
		return value, malformed("noncanonical timestamp DER (%T)", value)
	}
	return value, nil
}

func timestampHash(alg algorithmIdentifier) (crypto.Hash, error) {
	if !nullOrAbsent(alg.Parameters) {
		return 0, malformed("timestamp digest parameters")
	}
	switch alg.Algorithm.String() {
	case "1.3.14.3.2.26":
		return crypto.SHA1, nil // Apple's TSA currently emits this legacy CMS digest.
	case "2.16.840.1.101.3.4.2.1":
		return crypto.SHA256, nil
	case "2.16.840.1.101.3.4.2.2":
		return crypto.SHA384, nil
	case "2.16.840.1.101.3.4.2.3":
		return crypto.SHA512, nil
	default:
		return 0, unsupported("timestamp digest " + alg.Algorithm.String())
	}
}

func timestampDigest(h crypto.Hash, data []byte) []byte {
	d := h.New()
	_, _ = d.Write(data)
	return d.Sum(nil)
}

func timestampCertificate(c *certificate) error {
	for _, e := range c.tbs.Extensions {
		if e.ID.String() != "2.5.29.37" {
			continue
		}
		purposes, err := decodeTimestampDER[[]asn1.ObjectIdentifier](e.Value)
		if err != nil {
			return err
		}
		if e.Critical && len(purposes) == 1 && purposes[0].String() == timestampPurpose {
			return nil
		}
		return invalid("timestamp certificate requires critical, exclusive timeStamping EKU")
	}
	return invalid("timestamp certificate lacks timeStamping EKU")
}

func timestampName(raw asn1.RawValue, name []byte) bool {
	return raw.Class == 2 && raw.Tag == 4 && raw.IsCompound && bytes.Equal(raw.Bytes, name)
}

func checkTimestampESS(attrs map[string]asn1.RawValue, cert *certificate) error {
	first, v1 := attrs[oidESSCert.String()]
	second, v2 := attrs[oidESSCertV2.String()]
	if !v1 && !v2 {
		return invalid("timestamp lacks ESS signing-certificate binding")
	}
	for _, entry := range []struct {
		raw asn1.RawValue
		v2  bool
	}{{first, false}, {second, true}} {
		if len(entry.raw.FullBytes) == 0 {
			continue
		}
		value, err := decodeTimestampDER[struct {
			Certs    []asn1.RawValue
			Policies asn1.RawValue `asn1:"optional"`
		}](entry.raw.Bytes)
		if err != nil {
			return err
		}
		if len(value.Certs) != 1 || len(value.Policies.FullBytes) > 0 {
			return unsupported("timestamp ESS certificate count or policies")
		}
		var hash []byte
		var issuer asn1.RawValue
		want := []byte(nil)
		if entry.v2 {
			id, err := decodeTimestampDER[struct {
				Algorithm algorithmIdentifier `asn1:"optional"`
				Hash      []byte
				Issuer    asn1.RawValue `asn1:"optional"`
			}](value.Certs[0].FullBytes)
			if err != nil {
				return err
			}
			alg := id.Algorithm
			if len(alg.Algorithm) == 0 {
				alg.Algorithm = oidSHA256
			}
			h, err := timestampHash(alg)
			if err != nil {
				return err
			}
			hash, issuer, want = id.Hash, id.Issuer, timestampDigest(h, cert.raw)
		} else {
			id, err := decodeTimestampDER[struct {
				Hash   []byte
				Issuer asn1.RawValue `asn1:"optional"`
			}](value.Certs[0].FullBytes)
			if err != nil {
				return err
			}
			d := sha1.Sum(cert.raw)
			hash, issuer, want = id.Hash, id.Issuer, d[:]
		}
		if !bytes.Equal(hash, want) {
			return invalid("timestamp ESS certificate digest")
		}
		if len(issuer.FullBytes) > 0 {
			id, err := decodeTimestampDER[struct {
				Names  []asn1.RawValue
				Serial *big.Int
			}](issuer.FullBytes)
			if err != nil {
				return err
			}
			if len(id.Names) != 1 || !timestampName(id.Names[0], cert.tbs.Issuer.FullBytes) || id.Serial.Cmp(cert.tbs.Serial) != 0 {
				return invalid("timestamp ESS issuer/serial")
			}
		}
	}
	return nil
}

func parseTimestampToken(token, signature []byte) (*TimestampInfo, error) {
	if len(token) > maxTimestampSize || len(signature) == 0 || len(signature) > 8192 {
		return nil, malformed("timestamp input size")
	}
	sd, certs, err := decodeSignedData(token)
	if err != nil {
		return nil, err
	}
	si := sd.Signers[0]
	if sd.Version != 3 || !sd.Content.Type.Equal(oidTSTInfo) || len(si.Unsigned.FullBytes) != 0 {
		return nil, unsupported("timestamp CMS version, content type or nested attributes")
	}
	h, err := timestampHash(sd.Digests[0])
	if err != nil {
		return nil, err
	}
	sh, err := timestampHash(si.Digest)
	if err != nil {
		return nil, err
	}
	if h != sh {
		return nil, invalid("timestamp signer digest mismatch")
	}
	content := sd.Content.Content
	if content.Class != 2 || content.Tag != 0 || !content.IsCompound {
		return nil, malformed("timestamp encapsulated content")
	}
	tstBytes, err := decodeTimestampDER[[]byte](content.Bytes)
	if err != nil {
		return nil, err
	}
	tst, err := decodeTimestampDER[timestampTSTInfo](tstBytes)
	if err != nil {
		return nil, err
	}
	if tst.Version != 1 || tst.Serial.Sign() <= 0 || tst.Serial.BitLen() > 160 || tst.Nonce != nil && (tst.Nonce.Sign() < 0 || tst.Nonce.BitLen() > 160) {
		return nil, malformed("timestamp version, serial or nonce")
	}
	if tst.GenTime.Class != 0 || tst.GenTime.Tag != asn1.TagGeneralizedTime || !bytes.HasSuffix(tst.GenTime.Bytes, []byte("Z")) {
		return nil, malformed("timestamp requires UTC GeneralizedTime")
	}
	var at time.Time
	if err := decodeDER(tst.GenTime.FullBytes, &at); err != nil {
		return nil, err
	}
	if tst.Accuracy.Seconds != nil && (tst.Accuracy.Seconds.Sign() < 0 || tst.Accuracy.Seconds.BitLen() > 31) || tst.Accuracy.Millis < 0 || tst.Accuracy.Millis > 999 || tst.Accuracy.Micros < 0 || tst.Accuracy.Micros > 999 {
		return nil, malformed("timestamp accuracy")
	}
	if len(tst.Extensions.FullBytes) > 0 {
		return nil, unsupported("timestamp extensions")
	}
	ih, err := timestampHash(tst.Imprint.Algorithm)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tst.Imprint.Digest, timestampDigest(ih, signature)) {
		return nil, invalid("timestamp message imprint does not match CMS signature")
	}
	var signer *certificate
	info := &TimestampInfo{Token: bytes.Clone(token), Time: at, Policy: tst.Policy.String(), SerialNumber: tst.Serial.Text(16), nonce: tst.Nonce, imprintHash: ih}
	for _, cert := range certs {
		info.Certificates = append(info.Certificates, bytes.Clone(cert.raw))
		if si.ID.Serial != nil && cert.tbs.Serial.Cmp(si.ID.Serial) == 0 && bytes.Equal(cert.tbs.Issuer.FullBytes, si.ID.Issuer.FullBytes) {
			if signer != nil {
				return nil, malformed("ambiguous timestamp signer")
			}
			signer = cert
		}
	}
	if signer == nil {
		return nil, invalid("timestamp signer certificate missing")
	}
	if err := timestampCertificate(signer); err != nil {
		return nil, err
	}
	if len(tst.TSA.FullBytes) > 0 {
		name, err := decodeTimestampDER[asn1.RawValue](tst.TSA.Bytes)
		if err != nil {
			return nil, err
		}
		if !tst.TSA.IsCompound || !timestampName(name, signer.tbs.Subject.FullBytes) {
			return nil, unsupported("timestamp TSA name must match certificate directoryName")
		}
	}
	attrs, signed, err := parseCMSAttributes(si.Attributes)
	if err != nil {
		return nil, err
	}
	ct, err := decodeTimestampDER[asn1.ObjectIdentifier](attrs[oidContentType.String()].Bytes)
	if err != nil {
		return nil, err
	}
	if !ct.Equal(oidTSTInfo) {
		return nil, invalid("timestamp content-type attribute")
	}
	digest, err := decodeTimestampDER[[]byte](attrs[oidMessageDigest.String()].Bytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digest, timestampDigest(h, tstBytes)) {
		return nil, invalid("timestamp content digest")
	}
	if err := checkTimestampESS(attrs, signer); err != nil {
		return nil, err
	}
	if err := verifyCMSDigestSignature(signer.public, si.Algorithm, h, timestampDigest(h, signed), si.Signature); err != nil {
		return nil, err
	}
	info.SignerCertificate = bytes.Clone(signer.raw)
	// Descriptive signer information is available before any trust evaluation.
	ci, err := certificateInfo(signer)
	if err != nil {
		return nil, err
	}
	info.Authorities = []CertificateInfo{ci}
	return info, nil
}

func cmsTimestamp(si cmsSigner) (*TimestampInfo, error) {
	if len(si.Unsigned.FullBytes) == 0 {
		return nil, nil
	}
	raw := si.Unsigned
	if raw.Class != 2 || raw.Tag != 1 {
		return nil, malformed("CMS unsigned attributes tag")
	}
	raw.Tag = 0
	attrs, _, err := parseCMSAttributes(raw)
	if err != nil {
		return nil, err
	}
	value, ok := attrs[oidTimestamp.String()]
	if !ok || len(attrs) != 1 {
		return nil, unsupported("CMS unsigned attributes other than one RFC 3161 timestamp")
	}
	return parseTimestampToken(value.Bytes, si.Signature)
}

func verifyTimestampTrust(info *TimestampInfo, roots [][]byte, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	if info.Time.After(now) {
		return invalid("timestamp is in the future")
	}
	chain, err := verifyCertificateChainFor(info.SignerCertificate, info.Certificates, roots, info.Time, timestampPurpose)
	if err != nil {
		return fmt.Errorf("timestamp authority: %w", err)
	}
	info.Authorities = chain.Authorities
	info.Certificates = chain.Certificates
	return nil
}

func checkTimestampApplePolicy(codePath []*certificate, info *TimestampInfo) error {
	if !appleAnchor(codePath) {
		return nil
	}
	root, err := parseCertificate(info.Certificates[len(info.Certificates)-1]) // Previously path-validated.
	if err != nil {
		return err
	}
	if !appleAnchor([]*certificate{root}) {
		return invalid("Apple code signature requires an Apple-anchored timestamp")
	}
	return nil
}

// VerifyTimestampToken checks a DER/outer-BER RFC 3161 token against CMS signature
// octets and an explicit TSA CA path at genTime. now bounds future timestamps;
// zero uses time.Now. It never treats a code-signing leaf pin as TSA trust.
func VerifyTimestampToken(token, signature []byte, roots [][]byte, now time.Time) (*TimestampInfo, error) {
	info, err := parseTimestampToken(token, signature)
	if err != nil {
		return nil, err
	}
	if err := verifyTimestampTrust(info, roots, now); err != nil {
		return nil, err
	}
	return info, nil
}

// TimestampCMS attaches a verified token as the sole unsigned attribute. The
// signed attributes and signature are preserved. A timestamp already present
// is rejected rather than silently replaced. The returned envelope uses Apple's
// outer BER form. Provider/network errors never return partial output.
func TimestampCMS(ctx context.Context, cms []byte, directories [][]byte, opts TimestampOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.Provider == nil || len(opts.TrustedRoots) == 0 {
		return nil, invalid("timestamp provider and explicit TSA roots required")
	}
	original, err := VerifyCMS(cms, directories)
	if err != nil {
		return nil, err
	}
	if original.Timestamp != nil {
		return nil, invalid("CMS already has a timestamp")
	}
	sd, _, _ := decodeCMS(cms) // VerifyCMS checked the same bytes.
	token, err := opts.Provider(ctx, bytes.Clone(sd.Signers[0].Signature))
	if err != nil {
		return nil, fmt.Errorf("timestamp provider: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := VerifyTimestampToken(token, sd.Signers[0].Signature, opts.TrustedRoots, opts.CurrentTime)
	if err != nil {
		return nil, err
	}
	path, err := linkedCertificates(original.SignerCertificate, original.Certificates)
	if err != nil {
		return nil, err
	}
	for i, c := range path {
		if err := certificatePolicy(c, info.Time, i > 0, max(0, i-1)); err != nil {
			return nil, err
		}
	}
	if err := checkTimestampApplePolicy(path, info); err != nil {
		return nil, err
	}
	// Normalize only the token's BER envelope; signed content is untouched.
	token, _ = cmsEnvelopeDER(token)
	sd.Signers[0].Unsigned = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: derAttribute(oidTimestamp, token)}
	signer, err := asn1.Marshal(sd.Signers[0])
	if err != nil {
		return nil, err
	}
	digests := derSet(derAlgorithm(oidSHA256, true))
	signed := cmsBERWrap(0x30, []byte{2, 1, 1}, digests, cmsBERWrap(0x30, derOID(oidData)), sd.Certificates.FullBytes, derSet(signer))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cmsBERWrap(0x30, derOID(oidSignedData), cmsBERWrap(0xa0, signed)), nil
}
