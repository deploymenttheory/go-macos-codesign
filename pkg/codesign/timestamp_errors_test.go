package codesign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestTimestampMalformedInfo(t *testing.T) {
	tsa := timestampIdentity(t, "p256", nil)
	for name, edit := range map[string]func(*timestampTSTInfo){
		"version":            func(v *timestampTSTInfo) { v.Version = 2 },
		"zero-serial":        func(v *timestampTSTInfo) { v.Serial = big.NewInt(0) },
		"long-serial":        func(v *timestampTSTInfo) { v.Serial = new(big.Int).Lsh(big.NewInt(1), 160) },
		"negative-nonce":     func(v *timestampTSTInfo) { v.Nonce = big.NewInt(-1) },
		"long-nonce":         func(v *timestampTSTInfo) { v.Nonce = new(big.Int).Lsh(big.NewInt(1), 160) },
		"utc-time":           func(v *timestampTSTInfo) { v.GenTime = rawASN1(t, testDER(t, certificateTime)) },
		"time-zone":          func(v *timestampTSTInfo) { v.GenTime = rawASN1(t, derWrap(24, []byte("20260919120000+0100"))) },
		"invalid-time":       func(v *timestampTSTInfo) { v.GenTime = rawASN1(t, derWrap(24, []byte("invalidZ"))) },
		"negative-seconds":   func(v *timestampTSTInfo) { v.Accuracy.Seconds = big.NewInt(-1) },
		"long-seconds":       func(v *timestampTSTInfo) { v.Accuracy.Seconds = new(big.Int).Lsh(big.NewInt(1), 32) },
		"millis":             func(v *timestampTSTInfo) { v.Accuracy.Millis = 1000 },
		"micros":             func(v *timestampTSTInfo) { v.Accuracy.Micros = -1 },
		"extensions":         func(v *timestampTSTInfo) { v.Extensions = rawASN1(t, derWrap(0xa1, []byte{5, 0})) },
		"imprint-algorithm":  func(v *timestampTSTInfo) { v.Imprint.Algorithm.Algorithm = oidRSA },
		"imprint-parameters": func(v *timestampTSTInfo) { v.Imprint.Algorithm.Parameters = rawASN1(t, []byte{2, 1, 1}) },
		"imprint-digest":     func(v *timestampTSTInfo) { v.Imprint.Digest[0] ^= 1 },
		"tsa-empty":          func(v *timestampTSTInfo) { v.TSA = rawASN1(t, derWrap(0xa0, nil)) },
		"tsa-name":           func(v *timestampTSTInfo) { v.TSA = rawASN1(t, derWrap(0xa0, derWrap(0x82, []byte("other")))) },
	} {
		t.Run(name, func(t *testing.T) {
			token := (testTimestamp{tsa: tsa, hash: crypto.SHA256, editInfo: edit}).token(t, []byte("s"))
			if _, err := parseTimestampToken(token, []byte("s")); err == nil {
				t.Fatal("bad TSTInfo accepted")
			}
		})
	}
}

func TestTimestampMalformedCMS(t *testing.T) {
	tsa := timestampIdentity(t, "p256", nil)
	for name, edit := range map[string]func(*cmsSignedData){
		"version":           func(v *cmsSignedData) { v.Version = 1 },
		"content-type":      func(v *cmsSignedData) { v.Content.Type = oidData },
		"unsigned":          func(v *cmsSignedData) { v.Signers[0].Unsigned = rawASN1(t, derWrap(0xa1, []byte{5, 0})) },
		"digest":            func(v *cmsSignedData) { v.Digests[0].Algorithm = oidRSA },
		"signer-digest":     func(v *cmsSignedData) { v.Signers[0].Digest.Algorithm = oidRSA },
		"digest-mismatch":   func(v *cmsSignedData) { v.Signers[0].Digest.Algorithm = hashOID(crypto.SHA384) },
		"missing-content":   func(v *cmsSignedData) { v.Content.Content = asn1.RawValue{} },
		"primitive-content": func(v *cmsSignedData) { v.Content.Content = rawASN1(t, derWrap(0x80, []byte{5, 0})) },
		"bad-octets":        func(v *cmsSignedData) { v.Content.Content = rawASN1(t, derWrap(0xa0, []byte{5, 0})) },
		"bad-tst":           func(v *cmsSignedData) { v.Content.Content = rawASN1(t, derWrap(0xa0, derWrap(4, []byte{5, 0}))) },
		"missing-signer":    func(v *cmsSignedData) { v.Signers[0].ID.Serial = big.NewInt(9999) },
		"duplicate-signer": func(v *cmsSignedData) {
			v.Certificates = rawASN1(t, derWrap(0xa0, bytes.Join(append(vCerts(tsa), tsa.Certificates[0]), nil)))
		},
		"attributes":          func(v *cmsSignedData) { v.Signers[0].Attributes = asn1.RawValue{} },
		"signature":           func(v *cmsSignedData) { v.Signers[0].Signature[0] ^= 1 },
		"signature-algorithm": func(v *cmsSignedData) { v.Signers[0].Algorithm.Algorithm = oidRSA },
	} {
		t.Run(name, func(t *testing.T) {
			token := (testTimestamp{tsa: tsa, hash: crypto.SHA256, editCMS: edit}).token(t, []byte("s"))
			if _, err := parseTimestampToken(token, []byte("s")); err == nil {
				t.Fatal("bad timestamp CMS accepted")
			}
		})
	}
	valid := (testTimestamp{tsa: tsa, hash: crypto.SHA256}).token(t, []byte("s"))
	for _, input := range [][]byte{nil, {1}, make([]byte, maxTimestampSize+1), append(bytes.Clone(valid), 0)} {
		if _, err := parseTimestampToken(input, []byte("s")); err == nil {
			t.Fatal("malformed token")
		}
	}
	for _, sig := range [][]byte{nil, make([]byte, 8193)} {
		if _, err := parseTimestampToken(valid, sig); err == nil {
			t.Fatal("bad signature size")
		}
	}
}

func vCerts(id *Identity) [][]byte { return append([][]byte(nil), id.Certificates...) }

func TestTimestampMalformedAttributes(t *testing.T) {
	tsa := timestampIdentity(t, "p256", nil)
	for name, edit := range map[string]func(map[string][]byte){
		"missing-type":   func(a map[string][]byte) { delete(a, oidContentType.String()) },
		"wrong-type":     func(a map[string][]byte) { a[oidContentType.String()] = derAttribute(oidContentType, derOID(oidData)) },
		"missing-digest": func(a map[string][]byte) { delete(a, oidMessageDigest.String()) },
		"wrong-digest": func(a map[string][]byte) {
			a[oidMessageDigest.String()] = derAttribute(oidMessageDigest, derWrap(4, []byte{1}))
		},
		"missing-ess": func(a map[string][]byte) { delete(a, oidESSCert.String()) },
		"bad-ess":     func(a map[string][]byte) { a[oidESSCert.String()] = derAttribute(oidESSCert, []byte{5, 0}) },
		"empty-ess": func(a map[string][]byte) {
			a[oidESSCert.String()] = derAttribute(oidESSCert, derSequence(derSequence()))
		},
		"bad-v1-id": func(a map[string][]byte) {
			a[oidESSCert.String()] = derAttribute(oidESSCert, derSequence(derSequence([]byte{5, 0})))
		},
		"wrong-v1-hash": func(a map[string][]byte) {
			a[oidESSCert.String()] = derAttribute(oidESSCert, derSequence(derSequence(derSequence(derWrap(4, []byte{1})))))
		},
		"bad-v2-id": func(a map[string][]byte) {
			a[oidESSCertV2.String()] = derAttribute(oidESSCertV2, derSequence(derSequence([]byte{5, 0})))
		},
		"bad-v2-algorithm": func(a map[string][]byte) {
			a[oidESSCertV2.String()] = derAttribute(oidESSCertV2, derSequence(derSequence(derSequence(derAlgorithm(oidRSA, true), derWrap(4, []byte{1})))))
		},
		"bad-v2-issuer": func(a map[string][]byte) {
			a[oidESSCertV2.String()] = derAttribute(oidESSCertV2, derSequence(derSequence(derSequence(derWrap(4, timestampDigest(crypto.SHA256, tsa.Certificates[0])), []byte{5, 0}))))
		},
		"wrong-v2-issuer": func(a map[string][]byte) {
			a[oidESSCertV2.String()] = derAttribute(oidESSCertV2, derSequence(derSequence(derSequence(derWrap(4, timestampDigest(crypto.SHA256, tsa.Certificates[0])), derSequence(derSequence(), derPositive(big.NewInt(1)))))))
		},
	} {
		t.Run(name, func(t *testing.T) {
			token := (testTimestamp{tsa: tsa, hash: crypto.SHA256, editAttrs: edit}).token(t, []byte("s"))
			if _, err := parseTimestampToken(token, []byte("s")); err == nil {
				t.Fatal("bad attributes accepted")
			}
		})
	}
}

func TestTimestampAttachmentFailures(t *testing.T) {
	tsa := timestampIdentity(t, "p256", nil)
	cms, dirs := testCMS(t)
	v := testTimestamp{tsa: tsa, hash: crypto.SHA256}
	good := TimestampOptions{TrustedRoots: [][]byte{tsa.Certificates[2]}, CurrentTime: certificateTime, Provider: func(_ context.Context, s []byte) ([]byte, error) { return v.token(t, s), nil }}
	for _, mode := range []string{"nil-provider", "nil-roots", "bad-cms", "already-stamped", "provider-error", "cancel-before", "cancel-provider", "wrong-token", "invalid-code-time"} {
		t.Run(mode, func(t *testing.T) {
			opts := good
			input := cms
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "nil-provider":
				opts.Provider = nil
			case "nil-roots":
				opts.TrustedRoots = nil
			case "bad-cms":
				input = []byte{1}
			case "already-stamped":
				var err error
				input, err = TimestampCMS(ctx, cms, dirs, opts)
				if err != nil {
					t.Fatal(err)
				}
			case "provider-error":
				opts.Provider = func(context.Context, []byte) ([]byte, error) { return nil, errors.New("offline") }
			case "cancel-before":
				cancel()
			case "cancel-provider":
				opts.Provider = func(context.Context, []byte) ([]byte, error) { cancel(); return nil, nil }
			case "wrong-token":
				opts.Provider = func(context.Context, []byte) ([]byte, error) { return v.token(t, []byte("wrong")), nil }
			case "invalid-code-time":
				id := makeChain(t, func(i int, c *x509.Certificate) {
					if i == 0 {
						c.NotBefore = certificateTime.Add(time.Hour)
					}
				})
				var err error
				input, err = SignCMS(ctx, id, dirs, certificateTime.Add(2*time.Hour))
				if err != nil {
					t.Fatal(err)
				}
			}
			if out, err := TimestampCMS(ctx, input, dirs, opts); err == nil || out != nil {
				t.Fatal("failed attachment returned output", err)
			}
		})
	}
	if _, err := SignBytes(context.Background(), fixture(t, "unsigned-arm64"), SignOptions{Identifier: "id", Timestamp: &good}); err == nil {
		t.Fatal("ad-hoc timestamp")
	}
	bad := good
	bad.Provider = nil
	if _, err := SignBytes(context.Background(), fixture(t, "unsigned-arm64"), SignOptions{Identifier: "id", Identity: testIdentity(t, "rsa"), Timestamp: &bad}); err == nil {
		t.Fatal("missing provider")
	}
	bad = good
	bad.Provider = func(context.Context, []byte) ([]byte, error) { return nil, errors.New("offline") }
	if _, err := SignBytes(context.Background(), fixture(t, "unsigned-arm64"), SignOptions{Identifier: "id", Identity: testIdentity(t, "rsa"), Timestamp: &bad}); err == nil {
		t.Fatal("provider error")
	}
}

func TestTimestampPolicyErrors(t *testing.T) {
	tsa := timestampIdentity(t, "p256", nil)
	c, _ := parseCertificate(tsa.Certificates[0])
	c.tbs.Extensions = []certificateExtension{{ID: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: []byte{5, 0}}}
	if err := timestampCertificate(c); err == nil {
		t.Fatal("malformed EKU")
	}
	code, err := linkedCertificates(chainFile(t, "developer-id-0"), [][]byte{chainFile(t, "developer-id-1"), chainFile(t, "developer-id-2")})
	if err != nil {
		t.Fatal(err)
	}
	if err := checkTimestampApplePolicy(code, &TimestampInfo{Certificates: [][]byte{tsa.Certificates[2]}}); err == nil {
		t.Fatal("Apple code with private TSA")
	}
	if err := checkTimestampApplePolicy(code, &TimestampInfo{Certificates: [][]byte{chainFile(t, "developer-id-2")}}); err != nil {
		t.Fatal(err)
	}
	if err := checkTimestampApplePolicy(code, &TimestampInfo{Certificates: [][]byte{{1}}}); err == nil {
		t.Fatal("bad root")
	}
	if _, err := decodeTimestampDER[struct{ A int }]([]byte{48, 6, 2, 1, 1, 2, 1, 2}); err == nil {
		t.Fatal("trailing sequence field")
	}
	if _, err := AcquireTimestamp(context.Background(), []byte("s"), nil, tsa.Certificates, time.Time{}); err == nil {
		t.Fatal("nil exchange")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AcquireTimestamp(ctx, []byte("s"), nil, nil, time.Time{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
