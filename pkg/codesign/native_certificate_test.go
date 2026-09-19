package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAppleNativeCertificateFixtures(t *testing.T) {
	for _, algorithm := range []string{"rsa", "p256", "p384", "p521"} {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			t.Run(algorithm+"/"+arch, func(t *testing.T) {
				path := filepath.Join("../../testdata/certificate-layout", algorithm+"-"+arch)
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				metadata, err := os.ReadFile(path + ".json")
				if err != nil {
					t.Fatal(err)
				}
				var recorded struct {
					SHA256 string `json:"sha256"`
				}
				if err := json.Unmarshal(metadata, &recorded); err != nil {
					t.Fatal(err)
				}
				h := sha256.Sum256(want)
				if hex.EncodeToString(h[:]) != recorded.SHA256 {
					t.Fatal("native fixture hash changed")
				}
				id := testIdentity(t, algorithm)
				wn, err := VerifyBytes(context.Background(), want, VerifyOptions{TrustedCertificates: id.Certificates})
				if err != nil {
					t.Fatal("Apple signature rejected:", err)
				}
				for i, a := range wn.Architectures {
					cms := a.Signature.find(SlotCMS)[8:]
					info, err := VerifyCMS(cms, [][]byte{a.Signature.Directories[0].Raw})
					if err != nil {
						t.Fatal(err)
					}
					got, err := SignBytes(context.Background(), fixture(t, "unsigned-"+arch), SignOptions{Identifier: "org.example.certificate", Identity: id, SigningTime: info.SigningTime})
					if err != nil {
						t.Fatal(err)
					}
					gn, err := InspectBytes(got)
					if err != nil {
						t.Fatal(err)
					}
					g := gn.Architectures[i]
					if a.Offset != g.Offset || a.Size != g.Size || a.SignatureOffset != g.SignatureOffset || a.SignatureSize != g.SignatureSize {
						t.Fatal("native allocation mismatch")
					}
					assertAppleBytes(t, got[a.Offset:a.Offset+a.SignatureOffset], want[a.Offset:a.Offset+a.SignatureOffset])
					for _, b := range a.Signature.Blobs {
						if b.Slot != SlotCMS {
							assertAppleBytes(t, g.Signature.find(b.Slot), b.Data)
						}
					}
					if algorithm == "rsa" {
						assertAppleBytes(t, got[a.Offset:a.Offset+a.Size], want[a.Offset:a.Offset+a.Size])
						if i == 0 {
							assertAppleBytes(t, got[:a.Offset], want[:a.Offset])
						}
					}
					nativeCMS, _, err := decodeCMS(cms)
					if err != nil {
						t.Fatal(err)
					}
					goCMS, _, err := decodeCMS(g.Signature.find(SlotCMS)[8:])
					if err != nil {
						t.Fatal(err)
					}
					// ECDSA is randomized, but all authenticated metadata and
					// algorithm identifiers must still match the native encoding.
					assertAppleBytes(t, goCMS.Signers[0].Attributes.FullBytes, nativeCMS.Signers[0].Attributes.FullBytes)
					assertAppleBytes(t, testDER(t, goCMS.Signers[0].Algorithm), testDER(t, nativeCMS.Signers[0].Algorithm))
					assertAppleBytes(t, testDER(t, goCMS.Digests), testDER(t, nativeCMS.Digests))
				}
			})
		}
	}
}

func TestAppleCMSAllocationAST(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		Targets map[string]struct {
			CMSSize int `json:"default_cms_blob_size"`
		}
	}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	if len(facts.Targets) != 2 {
		t.Fatal("both Clang targets are required")
	}
	for target, fact := range facts.Targets {
		if fact.CMSSize != defaultCMSSize {
			t.Fatalf("%s: Go=%d Clang=%d", target, defaultCMSSize, fact.CMSSize)
		}
	}
}

func TestCMSEnvelopeBoundaries(t *testing.T) {
	valid, dirs := testCMS(t)
	original := bytes.Clone(valid)
	der, err := cmsEnvelopeDER(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCMS(der, dirs); err != nil {
		t.Fatal("DER remains supported:", err)
	}
	if !bytes.Equal(valid, original) {
		t.Fatal("BER input mutated")
	}
	for n := range len(valid) {
		if _, err := VerifyCMS(valid[:n], dirs); err == nil {
			t.Fatalf("accepted truncated CMS at %d", n)
		}
	}
	deep := []byte{5, 0}
	for i := 0; i < 34; i++ {
		deep = cmsBERWrap(0x30, deep)
	}
	for _, bad := range [][]byte{
		make([]byte, 16<<20+1), {4, 128, 0, 0}, {0x3f, 0}, {0x30, 0x85, 1, 0, 0, 0, 0}, {0x30, 0x82, 0, 128},
		{0x30, 0x81, 1, 0}, {0x30, 0x82, 1}, {0x30, 0x81, 128}, {0x30, 0},
		derSequence([]byte{0}), append(bytes.Clone(valid), 0), deep,
		cmsBERWrap(0x30, bytes.Repeat([]byte{5, 0}, 4097)),
		derSequence(derOID(oidSignedData), derWrap(0xa0, nil)),
		derSequence(derOID(oidSignedData), derWrap(0xa0, derSequence())),
		derSequence(derOID(oidSignedData), derWrap(0xa0, derWrap(4, nil))),
		derSequence(derOID(oidSignedData), derWrap(0xa0, derSequence(bytes.Repeat([]byte{5, 0}, 7)))),
	} {
		if _, err := cmsEnvelopeDER(bad); err == nil {
			t.Fatalf("accepted malformed CMS envelope: %x", bad[:min(len(bad), 32)])
		}
	}
	// Re-encoding must never repair BER inside the DER-protected fields.
	for _, field := range []string{"attributes", "certificates", "signers"} {
		sd, _, err := decodeCMS(valid)
		if err != nil {
			t.Fatal(err)
		}
		switch field {
		case "attributes":
			sd.Signers[0].Attributes.FullBytes = cmsBERWrap(0xa0, sd.Signers[0].Attributes.Bytes)
		case "certificates":
			sd.Certificates.FullBytes = cmsBERWrap(0xa0, sd.Certificates.Bytes)
		}
		bad := encodeCMSForTest(t, sd)
		if field == "signers" {
			set := derSet(testDER(t, sd.Signers[0]))
			bad = bytes.Replace(bad, set, cmsBERWrap(0x31, testDER(t, sd.Signers[0])), 1)
		}
		if _, err := VerifyCMS(bad, dirs); err == nil {
			t.Fatal("accepted non-DER", field)
		}
	}
}
