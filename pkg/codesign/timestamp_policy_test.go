package codesign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func timestampIdentity(t *testing.T, kind string, edit func(int, *x509.Certificate)) *Identity {
	t.Helper()
	id := makeChain(t, func(i int, c *x509.Certificate) {
		c.ExtKeyUsage = nil
		if i == 0 {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: testDER(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})}}
		}
		if edit != nil {
			edit(i, c)
		}
	})
	if kind != "p256" {
		leaf, _ := x509.ParseCertificate(id.Certificates[0])
		parent, _ := x509.ParseCertificate(id.Certificates[1])
		leaf.ExtraExtensions = leaf.Extensions
		id.Signer = testIdentity(t, kind).Signer
		der, err := x509.CreateCertificate(rand.Reader, leaf, parent, id.Signer.Public(), testIdentity(t, "p384").Signer)
		if err != nil {
			t.Fatal(err)
		}
		id.Certificates[0] = der
	}
	return id
}

type testTimestamp struct {
	tsa          *Identity
	hash         crypto.Hash
	v2           bool
	essAlgorithm bool
	issuer       bool
	editInfo     func(*timestampTSTInfo)
	editAttrs    func(map[string][]byte)
	editCMS      func(*cmsSignedData)
}

func hashOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA1:
		return asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	case crypto.SHA384:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	case crypto.SHA512:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	default:
		return oidSHA256
	}
}

// Independent test token issuer: standard-library X.509 creates certificates;
// crypto.Signer signs DER attributes. The production parser is not used to issue.
func (v testTimestamp) token(t *testing.T, signature []byte) []byte {
	t.Helper()
	leaf, err := x509.ParseCertificate(v.tsa.Certificates[0])
	if err != nil {
		t.Fatal(err)
	}
	info := timestampTSTInfo{Version: 1, Policy: asn1.ObjectIdentifier{1, 2, 3, 4}, Imprint: timestampImprint{algorithmIdentifier{Algorithm: hashOID(v.hash)}, timestampDigest(v.hash, signature)}, Serial: big.NewInt(1), GenTime: rawASN1(t, derWrap(24, []byte(certificateTime.Format("20060102150405Z")))), Accuracy: timestampAccuracy{Seconds: big.NewInt(1), Millis: 1, Micros: 999}, Ordering: true, TSA: rawASN1(t, derWrap(0xa0, derWrap(0xa4, leaf.RawSubject)))}
	if v.editInfo != nil {
		v.editInfo(&info)
	}
	content := testDER(t, info)
	var issuer []byte
	if v.issuer {
		issuer = derSequence(derSequence(derWrap(0xa4, leaf.RawIssuer)), derPositive(leaf.SerialNumber))
	}
	essOID := oidESSCert
	d := sha1.Sum(leaf.Raw)
	ess := derSequence(derWrap(4, d[:]), issuer)
	if v.v2 {
		essOID = oidESSCertV2
		var alg []byte
		h := crypto.SHA256
		if v.essAlgorithm {
			h = v.hash
			alg = derAlgorithm(hashOID(h), true)
		}
		ess = derSequence(alg, derWrap(4, timestampDigest(h, leaf.Raw)), issuer)
	}
	attrs := map[string][]byte{
		oidContentType.String():   derAttribute(oidContentType, derOID(oidTSTInfo)),
		oidMessageDigest.String(): derAttribute(oidMessageDigest, derWrap(4, timestampDigest(v.hash, content))),
		essOID.String():           derAttribute(essOID, derSequence(derSequence(ess))),
	}
	if v.editAttrs != nil {
		v.editAttrs(attrs)
	}
	var attrValues [][]byte
	for _, a := range attrs {
		attrValues = append(attrValues, a)
	}
	signed := derSet(attrValues...)
	sig, err := v.tsa.Signer.Sign(rand.Reader, timestampDigest(v.hash, signed), v.hash)
	if err != nil {
		t.Fatal(err)
	}
	alg := oidRSA
	if _, ok := v.tsa.Signer.Public().(*ecdsa.PublicKey); ok {
		alg = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
		if v.hash == crypto.SHA1 {
			alg = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
		}
		if v.hash == crypto.SHA384 {
			alg[len(alg)-1] = 3
		}
		if v.hash == crypto.SHA512 {
			alg[len(alg)-1] = 4
		}
	}
	signed[0] = 0xa0
	certs := derSet(append([][]byte(nil), v.tsa.Certificates...)...)
	certs[0] = 0xa0
	sd := cmsSignedData{Version: 3, Digests: []algorithmIdentifier{{Algorithm: hashOID(v.hash)}}, Content: cmsContent{Type: oidTSTInfo, Content: rawASN1(t, derWrap(0xa0, derWrap(4, content)))}, Certificates: rawASN1(t, certs), Signers: []cmsSigner{{Version: 1, ID: cmsIssuerSerial{Issuer: rawASN1(t, leaf.RawIssuer), Serial: leaf.SerialNumber}, Digest: algorithmIdentifier{Algorithm: hashOID(v.hash)}, Attributes: rawASN1(t, signed), Algorithm: algorithmIdentifier{Algorithm: alg}, Signature: sig}}}
	if v.editCMS != nil {
		v.editCMS(&sd)
	}
	return encodeCMSForTest(t, &sd)
}

func rawASN1(t *testing.T, data []byte) asn1.RawValue {
	t.Helper()
	var r asn1.RawValue
	if err := decodeDER(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTimestampAlgorithmsAndTrust(t *testing.T) {
	for _, kind := range []string{"rsa", "p256", "p384", "p521"} {
		tsa := timestampIdentity(t, kind, nil)
		for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			for _, v2 := range []bool{false, true} {
				t.Run(kind+"/"+h.String()+"/"+map[bool]string{false: "v1", true: "v2"}[v2], func(t *testing.T) {
					v := testTimestamp{tsa: tsa, hash: h, v2: v2, essAlgorithm: h != crypto.SHA256, issuer: true}
					token := v.token(t, []byte("signature"))
					roots := [][]byte{tsa.Certificates[2]}
					info, err := VerifyTimestampToken(token, []byte("signature"), roots, certificateTime.Add(time.Hour))
					if err != nil || !info.Time.Equal(certificateTime) || len(info.Authorities) != 3 {
						t.Fatalf("verify token: %v", err)
					}
					if _, err := VerifyTimestampToken(token, []byte("wrong signature"), roots, certificateTime); !errors.Is(err, ErrInvalid) {
						t.Fatal(err)
					}
					if _, err := VerifyTimestampToken(token, []byte("signature"), nil, certificateTime); !errors.Is(err, ErrUntrusted) {
						t.Fatal(err)
					}
					if _, err := VerifyTimestampToken(token, []byte("signature"), roots, certificateTime.Add(-time.Second)); !errors.Is(err, ErrInvalid) {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestTimestampExpiryAndSigning(t *testing.T) {
	tsa := timestampIdentity(t, "p256", nil)
	code := makeChain(t, func(i int, c *x509.Certificate) { c.NotAfter = certificateTime.Add(time.Hour) })
	provider := func(_ context.Context, signature []byte) ([]byte, error) {
		return (testTimestamp{tsa: tsa, hash: crypto.SHA256, v2: true}).token(t, signature), nil
	}
	opts := SignOptions{Identifier: "timestamp", Identity: code, SigningTime: certificateTime, Timestamp: &TimestampOptions{Provider: provider, TrustedRoots: [][]byte{tsa.Certificates[2]}, CurrentTime: certificateTime}}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		signed, err := SignBytes(context.Background(), fixture(t, "unsigned-"+arch), opts)
		if err != nil {
			t.Fatal(err)
		}
		vo := VerifyOptions{TrustedRoots: [][]byte{code.Certificates[2]}, TimestampRoots: opts.Timestamp.TrustedRoots, CurrentTime: certificateTime.Add(24 * time.Hour)}
		r, err := VerifyBytes(context.Background(), signed, vo)
		if err != nil || !r.Valid {
			t.Fatal(err)
		}
		// A signer pin cannot supply timestamp authority trust.
		vo.TrustedCertificates, vo.TimestampRoots = code.Certificates[:1], nil
		if r, err = VerifyBytes(context.Background(), signed, vo); !errors.Is(err, ErrUntrusted) || r.Valid {
			t.Fatal("timestamp trusted through code pin", err)
		}
	}
	opts.Timestamp = nil
	plain, err := SignBytes(context.Background(), fixture(t, "unsigned-arm64"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBytes(context.Background(), plain, VerifyOptions{TrustedRoots: [][]byte{code.Certificates[2]}, CurrentTime: certificateTime.Add(24 * time.Hour)}); err == nil {
		t.Fatal("signingTime claim bypassed expiry")
	}
}

func TestTimestampPurpose(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(int, *x509.Certificate)
	}{
		{"missing", func(i int, c *x509.Certificate) {
			if i == 0 {
				c.ExtraExtensions = nil
			}
		}},
		{"noncritical", func(i int, c *x509.Certificate) {
			if i == 0 {
				c.ExtraExtensions[0].Critical = false
			}
		}},
		{"codesigning", func(i int, c *x509.Certificate) {
			if i == 0 {
				c.ExtraExtensions[0].Value = testDER(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 3}})
			}
		}},
		{"mixed", func(i int, c *x509.Certificate) {
			if i == 0 {
				c.ExtraExtensions[0].Value = testDER(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}, {1, 3, 6, 1, 5, 5, 7, 3, 3}})
			}
		}},
		{"intermediate-code-only", func(i int, c *x509.Certificate) {
			if i == 1 {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
			}
		}},
		{"expired-at-timestamp", func(i int, c *x509.Certificate) {
			if i == 0 {
				c.NotAfter = certificateTime.Add(-time.Hour)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tsa := timestampIdentity(t, "p256", tc.edit)
			token := (testTimestamp{tsa: tsa, hash: crypto.SHA256}).token(t, []byte("signature"))
			if _, err := VerifyTimestampToken(token, []byte("signature"), [][]byte{tsa.Certificates[2]}, certificateTime); err == nil {
				t.Fatal("bad TSA policy accepted")
			}
		})
	}
}

func TestTimestampAcquireNonce(t *testing.T) {
	tsa := timestampIdentity(t, "p256", nil)
	var prior []byte
	for _, mode := range []string{"granted", "mods", "utf8-text", "wrong-text-tag", "bad-utf8", "missing", "wrong", "replayed", "imprint", "algorithm", "denied", "missing-token", "malformed", "oversize", "cancel", "transport", "future", "empty-response", "bad-status", "extra-response-field"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exchange := func(_ context.Context, request []byte) ([]byte, error) {
				var req struct {
					Version int
					Imprint timestampImprint
					Nonce   *big.Int
					CertReq bool
				}
				if err := decodeDER(request, &req); err != nil {
					t.Fatal(err)
				}
				if req.Version != 1 || !req.CertReq || req.Nonce.BitLen() != 129 || !bytes.Equal(req.Imprint.Digest, timestampDigest(crypto.SHA256, []byte("signature"))) {
					t.Fatal("wrong request")
				}
				v := testTimestamp{tsa: tsa, hash: crypto.SHA256, v2: true, editInfo: func(info *timestampTSTInfo) { info.Nonce = req.Nonce }}
				switch mode {
				case "algorithm":
					v.hash = crypto.SHA1
				case "empty-response":
					return derSequence(), nil
				case "bad-status":
					return derSequence([]byte{5, 0}), nil
				case "extra-response-field":
					return derSequence([]byte{5, 0}, []byte{5, 0}, []byte{5, 0}), nil
				case "missing":
					v.editInfo = nil
				case "wrong":
					v.editInfo = func(info *timestampTSTInfo) { info.Nonce = big.NewInt(99) }
				case "replayed":
					return prior, nil
				case "imprint":
					v.editInfo = func(info *timestampTSTInfo) { info.Nonce = req.Nonce; info.Imprint.Digest[0] ^= 1 }
				case "denied":
					return derSequence(derSequence([]byte{2, 1, 2})), nil
				case "missing-token":
					return derSequence(derSequence([]byte{2, 1, 0})), nil
				case "malformed":
					return []byte{1}, nil
				case "oversize":
					return make([]byte, maxTimestampSize+1), nil
				case "cancel":
					cancel()
					return nil, nil
				case "transport":
					return nil, errors.New("offline")
				case "future":
					v.editInfo = func(info *timestampTSTInfo) {
						info.Nonce = req.Nonce
						info.GenTime = rawASN1(t, derWrap(24, []byte("21990101000000Z")))
					}
				}
				status := byte(0)
				if mode == "mods" {
					status = 1
				}
				var statusText []byte
				if mode == "utf8-text" {
					statusText = derSequence(derWrap(12, []byte("Operation Okay")))
				}
				if mode == "wrong-text-tag" {
					statusText = derSequence(derWrap(19, []byte("Operation Okay")))
				}
				if mode == "bad-utf8" {
					statusText = derSequence(derWrap(12, []byte{255}))
				}
				result := derSequence(derSequence([]byte{2, 1, status}, statusText), v.token(t, []byte("signature")))
				if mode == "granted" {
					prior = bytes.Clone(result)
				}
				return result, nil
			}
			token, err := AcquireTimestamp(ctx, []byte("signature"), exchange, [][]byte{tsa.Certificates[2]}, certificateTime)
			good := mode == "granted" || mode == "mods" || mode == "utf8-text"
			if (err == nil) != good || good && len(token) == 0 {
				t.Fatalf("%s: %v", mode, err)
			}
		})
	}
}
