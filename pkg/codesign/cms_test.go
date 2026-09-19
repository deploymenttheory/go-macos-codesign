package codesign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func testDirectories(t *testing.T) [][]byte {
	t.Helper()
	r, err := InspectBytes(fixture(t, "adhoc-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{r.Architectures[0].Signature.find(SlotDirectory)}
}
func testCMS(t *testing.T) ([]byte, [][]byte) {
	t.Helper()
	dirs := testDirectories(t)
	der, err := SignCMS(context.Background(), testIdentity(t, "rsa"), dirs, certificateTime)
	if err != nil {
		t.Fatal(err)
	}
	return der, dirs
}
func encodeCMSForTest(t *testing.T, sd *cmsSignedData) []byte {
	t.Helper()
	return derSequence(derOID(oidSignedData), derWrap(0xa0, testDER(t, *sd)))
}

func TestCMSIndependentVerification(t *testing.T) {
	for _, kind := range []string{"rsa", "p256", "p384", "p521"} {
		t.Run(kind, func(t *testing.T) {
			id := testIdentity(t, kind)
			dirs := testDirectories(t)
			der, err := SignCMS(context.Background(), id, dirs, certificateTime)
			if err != nil {
				t.Fatal(err)
			}
			info, err := VerifyCMS(der, dirs)
			if err != nil || !bytes.Equal(info.SignerCertificate, id.Certificates[0]) || !info.SigningTime.Equal(certificateTime) {
				t.Fatalf("%+v %v", info, err)
			}
			sd, _, err := decodeCMS(der)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(id.Certificates[0])
			if err != nil {
				t.Fatal(err)
			}
			algorithm := x509.SHA256WithRSA
			if kind != "rsa" {
				algorithm = x509.ECDSAWithSHA256
			}
			if err := cert.CheckSignature(algorithm, derWrap(0x31, sd.Signers[0].Attributes.Bytes), sd.Signers[0].Signature); err != nil {
				t.Fatal("independent verifier:", err)
			}
			if kind == "rsa" {
				again, err := SignCMS(context.Background(), id, dirs, certificateTime)
				if err != nil || !bytes.Equal(der, again) {
					t.Fatal("RSA CMS is not reproducible with a fixed signing time", err)
				}
			}
		})
	}
	if _, err := SignCMS(context.Background(), testIdentity(t, "rsa"), testDirectories(t), time.Time{}); err != nil {
		t.Fatal(err)
	}
}

type failureSigner struct {
	crypto.Signer
	err    error
	bad    bool
	cancel context.CancelFunc
}

func (s failureSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.cancel != nil {
		s.cancel()
	}
	if s.bad {
		return []byte{1}, nil
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.Signer.Sign(r, digest, opts)
}

func TestCMSFailureBoundaries(t *testing.T) {
	id := testIdentity(t, "rsa")
	dirs := testDirectories(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SignCMS(ctx, id, dirs, certificateTime); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := SignCMS(context.Background(), nil, dirs, certificateTime); err == nil {
		t.Fatal("nil identity")
	}
	if _, err := SignCMS(context.Background(), id, dirs, time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expired certificate")
	}
	for _, bad := range [][][]byte{nil, {[]byte{1}}, make([][]byte, 6), {dirs[0], dirs[0]}} {
		if _, err := SignCMS(context.Background(), id, bad, certificateTime); err == nil {
			t.Fatal("bad directories")
		}
	}
	badLength := bytes.Clone(dirs[0])
	be.PutUint32(badLength[4:], 0)
	if _, _, err := directoryHashes([][]byte{badLength}); err == nil {
		t.Fatal("bad CodeDirectory length")
	}
	for _, signer := range []failureSigner{{Signer: id.Signer, err: io.ErrClosedPipe}, {Signer: id.Signer, bad: true}} {
		copyID := *id
		copyID.Signer = signer
		if _, err := SignCMS(context.Background(), &copyID, dirs, certificateTime); err == nil {
			t.Fatal("bad signer")
		}
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	copyID := *id
	copyID.Signer = failureSigner{Signer: id.Signer, cancel: cancel}
	if _, err := SignCMS(ctx, &copyID, dirs, certificateTime); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := verifyCMSSignature(nil, algorithmIdentifier{}, nil, nil); err == nil {
		t.Fatal("unknown key")
	}
	if err := verifyCMSSignature(id.Signer.Public(), algorithmIdentifier{Algorithm: oidEC}, nil, nil); err == nil {
		t.Fatal("wrong RSA algorithm")
	}
	ec := testIdentity(t, "p256").Signer.Public()
	if err := verifyCMSSignature(ec, algorithmIdentifier{Algorithm: oidRSA}, nil, nil); err == nil {
		t.Fatal("wrong EC algorithm")
	}
	if err := verifyCMSSignature(ec, algorithmIdentifier{Algorithm: oidSHA256ECDSA}, make([]byte, 32), nil); err == nil {
		t.Fatal("bad ECDSA signature")
	}
	if !bytes.Equal(derPositive(new(big.Int)), []byte{2, 1, 0}) {
		t.Fatal("zero integer encoding")
	}
}

func TestCMSEnvelopeRejections(t *testing.T) {
	der, dirs := testCMS(t)
	for _, bad := range [][]byte{nil, {0x30, 0}, append(bytes.Clone(der), 0), derSequence(derOID(oidData), derWrap(0xa0, []byte{0x30, 0})), derSequence(derOID(oidSignedData), derWrap(0xa0, []byte{1}))} {
		if _, err := VerifyCMS(bad, dirs); err == nil {
			t.Fatal("malformed CMS")
		}
	}
	mutations := map[string]func(*cmsSignedData){
		"version":           func(s *cmsSignedData) { s.Version = 3 },
		"signers":           func(s *cmsSignedData) { s.Signers = nil },
		"digest":            func(s *cmsSignedData) { s.Digests[0].Algorithm = oidRSA },
		"digest parameters": func(s *cmsSignedData) { s.Signers[0].Digest.Parameters = rawDER(t, 42) },
		"encapsulated": func(s *cmsSignedData) {
			s.Content.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{4, 0}}
		},
		"content type": func(s *cmsSignedData) { s.Content.Type = oidSignedData },
		"no certs":     func(s *cmsSignedData) { s.Certificates = asn1.RawValue{} },
		"bad cert tag": func(s *cmsSignedData) { s.Certificates = asn1.RawValue{Class: 2, Tag: 0, Bytes: []byte{1}} },
		"bad cert der": func(s *cmsSignedData) {
			s.Certificates = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{1}}
		},
		"bad cert": func(s *cmsSignedData) {
			s.Certificates = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0x30, 0}}
		},
		"no matching cert": func(s *cmsSignedData) { s.Signers[0].ID.Serial = big.NewInt(1) },
		"duplicate signer cert": func(s *cmsSignedData) {
			s.Certificates = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: bytes.Repeat(s.Certificates.Bytes, 2)}
		},
		"too many certs": func(s *cmsSignedData) {
			s.Certificates = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: bytes.Repeat(s.Certificates.Bytes, 33)}
		},
		"no attributes": func(s *cmsSignedData) { s.Signers[0].Attributes = asn1.RawValue{} },
		"bad attribute der": func(s *cmsSignedData) {
			s.Signers[0].Attributes = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{1}}
		},
		"bad signature": func(s *cmsSignedData) { s.Signers[0].Signature[0] ^= 1 },
		"unsigned timestamp": func(s *cmsSignedData) {
			s.Signers[0].Unsigned = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: []byte{0x30, 0}}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			sd, _, err := decodeCMS(der)
			if err != nil {
				t.Fatal(err)
			}
			mutate(sd)
			if _, err := VerifyCMS(encodeCMSForTest(t, sd), dirs); err == nil {
				t.Fatal("malformed CMS accepted")
			}
		})
	}
	if _, err := VerifyCMS(der, nil); err == nil {
		t.Fatal("missing content")
	}
}

func TestCMSAttributeRejections(t *testing.T) {
	der, dirs := testCMS(t)
	for _, tc := range []struct {
		name   string
		oid    asn1.ObjectIdentifier
		value  []byte
		remove bool
	}{
		{"missing type", oidContentType, nil, true}, {"wrong type", oidContentType, derOID(oidSignedData), false},
		{"missing digest", oidMessageDigest, nil, true}, {"wrong digest", oidMessageDigest, derWrap(4, []byte{1}), false},
		{"missing agility", oidHashAgility, nil, true}, {"bad plist", oidHashAgility, derWrap(4, []byte("bad")), false},
		{"empty hashes", oidHashAgility, derWrap(4, []byte(`<plist><dict><key>cdhashes</key><array/></dict></plist>`)), false},
		{"wrong hashes", oidHashAgility, derWrap(4, []byte(`<plist><dict><key>cdhashes</key><array><data>YQ==</data></array></dict></plist>`)), false},
		{"missing v2", oidHashAgilityV2, nil, true}, {"wrong v2", oidHashAgilityV2, derWrap(4, []byte{1}), false},
		{"bad time", oidSigningTime, derWrap(4, []byte{1}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, _, err := decodeCMS(der)
			if err != nil {
				t.Fatal(err)
			}
			attrs, _, err := parseCMSAttributes(sd.Signers[0].Attributes)
			if err != nil {
				t.Fatal(err)
			}
			var encoded [][]byte
			for oid, values := range attrs {
				var id asn1.ObjectIdentifier
				for _, known := range []asn1.ObjectIdentifier{oidContentType, oidMessageDigest, oidHashAgility, oidHashAgilityV2, oidSigningTime} {
					if known.String() == oid {
						id = known
					}
				}
				if id.Equal(tc.oid) {
					if !tc.remove {
						encoded = append(encoded, derAttribute(id, tc.value))
					}
				} else {
					encoded = append(encoded, derSequence(derOID(id), values.FullBytes))
				}
			}
			set := derSet(encoded...)
			set[0] = 0xa0
			sd.Signers[0].Attributes = asn1.RawValue{FullBytes: set}
			if _, err := VerifyCMS(encodeCMSForTest(t, sd), dirs); err == nil {
				t.Fatal("bad authenticated attribute")
			}
		})
	}
	for _, encoded := range [][]byte{
		derWrap(0xa0, derWrap(4, []byte{1})),
		derWrap(0xa0, derSequence(derOID(oidData), derWrap(4, []byte{1}))),
		derWrap(0xa0, bytes.Join([][]byte{derAttribute(oidData, derWrap(4, nil)), derAttribute(oidData, derWrap(4, nil))}, nil)),
	} {
		var raw asn1.RawValue
		if err := decodeDER(encoded, &raw); err != nil {
			t.Fatal(err)
		}
		if _, _, err := parseCMSAttributes(raw); err == nil {
			t.Fatal("bad attribute set")
		}
	}
	dup := derSet(derAttribute(oidData, derWrap(4, []byte{1})), derAttribute(oidData, derWrap(4, []byte{2})))
	dup[0] = 0xa0
	var raw asn1.RawValue
	if err := decodeDER(dup, &raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseCMSAttributes(raw); err == nil {
		t.Fatal("duplicate OID")
	}
}

func TestCertificateMachOSigning(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"rsa", "p256", "p384", "p521"} {
		id := testIdentity(t, kind)
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			original := fixture(t, "unsigned-"+arch)
			out, err := SignBytes(ctx, original, SignOptions{Identifier: "org.example.cert", Identity: id, SigningTime: certificateTime})
			if err != nil {
				t.Fatal(err)
			}
			opts := VerifyOptions{TrustedCertificates: id.Certificates, CurrentTime: certificateTime}
			report, err := VerifyBytes(ctx, out, opts)
			if err != nil || !report.Valid {
				t.Fatal(err)
			}
			if _, err := VerifyBytes(ctx, out, VerifyOptions{}); !errors.Is(err, ErrUntrusted) {
				t.Fatal(err)
			}
			if _, err := VerifyBytes(ctx, out, VerifyOptions{TrustedCertificates: [][]byte{[]byte("wrong")}}); !errors.Is(err, ErrUntrusted) {
				t.Fatal(err)
			}
			expired := opts
			expired.CurrentTime = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
			if _, err := VerifyBytes(ctx, out, expired); !errors.Is(err, ErrInvalid) {
				t.Fatal(err)
			}
			// Locate actual code and signature bytes independently through the report.
			a := report.Architectures[0]
			tampered := bytes.Clone(out)
			tampered[a.Offset+4096] ^= 1
			if _, err := VerifyBytes(ctx, tampered, opts); !errors.Is(err, ErrInvalid) {
				t.Fatal(err)
			}
			cms := a.Signature.find(SlotCMS)
			at := bytes.Index(out, cms)
			tampered = bytes.Clone(out)
			tampered[at+len(cms)-1] ^= 1
			if _, err := VerifyBytes(ctx, tampered, opts); err == nil {
				t.Fatal("CMS tampering accepted")
			}
			if len(original) >= len(out) {
				t.Fatal("missing certificate allocation")
			}
		}
	}
	id := testIdentity(t, "rsa")
	if _, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), SignOptions{Identifier: "x", Identity: id, Flags: FlagAdhoc}); err == nil {
		t.Fatal("ad-hoc certificate signature")
	}
	req, err := CompileRequirements(`identifier "wrong"`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), SignOptions{Identifier: "x", Identity: id, Requirements: req})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBytes(ctx, out, VerifyOptions{TrustedCertificates: id.Certificates}); !errors.Is(err, ErrDesignatedRequirement) {
		t.Fatal(err)
	}
	id.Signer = failureSigner{Signer: id.Signer, err: io.ErrClosedPipe}
	if _, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), SignOptions{Identifier: "x", Identity: id}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestCertificateRequirementErrors(t *testing.T) {
	for _, text := range []string{`certificate root = H"abc"`, `certificate leaf H"abc"`, `certificate leaf = "abc"`, `certificate leaf = H abc`, `certificate leaf = H"zz"`, `certificate leaf = H"\q"`} {
		if _, err := CompileRequirement(text); err == nil {
			t.Fatal(text)
		}
	}
	valid := `certificate leaf = H"` + strings.Repeat("00", 20) + `"`
	b, err := CompileRequirement(valid)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := EvaluateRequirementBytes(b, Directory{}); err != nil || ok {
		t.Fatal("ad-hoc matched certificate", err)
	}
	for _, bad := range [][]byte{b[:16], bytes.Clone(b), bytes.Clone(b)} {
		be.PutUint32(bad[4:], uint32(len(bad)))
		if len(bad) > 16 {
			be.PutUint32(bad[16:], 1)
		}
		if _, err := decodeRequirement(bad); err == nil {
			t.Fatal("bad certificate opcode")
		}
	}
}

func FuzzCMS(f *testing.F) {
	seed, err := os.ReadFile("../../testdata/macho/adhoc-arm64")
	if err != nil {
		f.Fatal(err)
	}
	r, err := InspectBytes(seed)
	if err != nil {
		f.Fatal(err)
	}
	dirs := [][]byte{r.Architectures[0].Signature.find(SlotDirectory)}
	identity, err := os.ReadFile("../../testdata/identities/rsa-identity.pem")
	if err != nil {
		f.Fatal(err)
	}
	id, err := LoadIdentityPEM(identity, nil)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := SignCMS(context.Background(), id, dirs, certificateTime)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = VerifyCMS(data, dirs)
	})
}

func TestCMSBindsAlternateDirectories(t *testing.T) {
	// Independently construct small SHA-1/SHA-256/SHA-384 directories. The CMS
	// binds their complete bytes, including directories not used as content.
	var dirs [][]byte
	for _, kind := range []uint8{2, 1, 4} {
		raw := make([]byte, 45)
		be.PutUint32(raw, MagicDirectory)
		be.PutUint32(raw[4:], uint32(len(raw)))
		be.PutUint32(raw[8:], 0x20001)
		be.PutUint32(raw[16:], 45)
		be.PutUint32(raw[20:], 44)
		h, err := digest(kind, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw[36], raw[37] = byte(len(h)), kind
		dirs = append(dirs, raw)
	}
	id := testIdentity(t, "rsa")
	der, err := SignCMS(context.Background(), id, dirs, certificateTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCMS(der, dirs); err != nil {
		t.Fatal(err)
	}
	dirs[1][12] ^= 1
	if _, err := VerifyCMS(der, dirs); err == nil {
		t.Fatal("unauthenticated alternate CodeDirectory")
	}
}
