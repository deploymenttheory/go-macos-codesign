package acceptance

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestAppleCertificateRequirementParity(t *testing.T) {
	apple(t)
	certPEM, err := os.ReadFile(filepath.Join(root, "testdata/identities/rsa-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pem.Decode(certPEM)
	if cert == nil {
		t.Fatal("missing test certificate")
	}
	hash := sha1.Sum(cert.Bytes)
	predicate := `certificate leaf = H"` + hex.EncodeToString(hash[:]) + `"`
	for _, expression := range []string{predicate, `identifier "org.example.certificate" and ` + predicate} {
		out := filepath.Join(t.TempDir(), "requirement.bin")
		mustRun(t, "/usr/bin/csreq", "-r", "="+expression, "-b", out)
		want, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		got, err := codesign.CompileRequirement(expression)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("requirement differs from Apple: %x != %x", got, want)
		}
	}
	attest(t, map[string]any{"leaf_certificate_requirement_byte_equal": true, "cases": 2})
}

func TestPortableCertificateCLI(t *testing.T) {
	for _, identity := range []string{"rsa", "p256", "p384", "p521"} {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			t.Run(identity+"/"+arch, func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, "signed")
				copyFixture(t, "unsigned-"+arch, target)
				bundle := filepath.Join(root, "testdata/identities", identity+"-identity.pem")
				cert := filepath.Join(root, "testdata/identities", identity+"-cert.pem")
				mustRun(t, binaryPath, "-s", bundle, "-i", "org.example.certificate", "--timestamp=none", target)
				mustRun(t, binaryPath, "--verify", "--trust", cert, target)
				_, stderr, code := run(t, binaryPath, "--verify", target)
				if code != 1 || !strings.Contains(stderr, "not explicitly trusted") {
					t.Fatalf("unpinned signer accepted: %d %s", code, stderr)
				}
				mustRun(t, binaryPath, "-dvvvv", target)
				if runtime.GOOS == "darwin" {
					mustRun(t, apple(t), "--verify", "--strict", "--verbose=4", target)
					verifyCMSWithOpenSSL(t, target, dir)
					verifyCertificateTampering(t, target, cert, dir)
				}
				if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
					if err := os.MkdirAll(export, 0755); err != nil {
						t.Fatal(err)
					}
					data, err := os.ReadFile(target)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(export, "signed-cert-"+identity+"-"+arch), data, 0755); err != nil {
						t.Fatal(err)
					}
				}
				attest(t, map[string]any{"algorithm": identity, "architecture": arch, "portable_verified": true, "apple_verified": runtime.GOOS == "darwin", "openssl_verified": runtime.GOOS == "darwin", "apple_and_go_reject_code_and_cms_tampering": runtime.GOOS == "darwin", "comparison": "cryptographic integrity and native acceptance; native byte comparisons are recorded by TestAppleNativeCertificateLayout"})
			})
		}
	}
}

func TestPortableAppleCertificateCLI(t *testing.T) {
	for _, algorithm := range []string{"rsa", "p256", "p384", "p521"} {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			t.Run(algorithm+"/"+arch, func(t *testing.T) {
				path := filepath.Join(root, "testdata/certificate-layout", algorithm+"-"+arch)
				cert := filepath.Join(root, "testdata/identities", algorithm+"-cert.pem")
				mustRun(t, binaryPath, "--verify", "--trust", cert, path)
				attest(t, map[string]any{"algorithm": algorithm, "architecture": arch, "apple_created_signature_verified_by_portable_cli": true})
			})
		}
	}
}

func verifyCertificateTampering(t *testing.T, target, cert, dir string) {
	t.Helper()
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	report, err := codesign.InspectBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	a := report.Architectures[0]
	offsets := map[string]int{"code": int(a.Offset) + 4096}
	for _, blob := range a.Signature.Blobs {
		if blob.Slot == codesign.SlotCMS {
			// Skip the six EOC bytes terminating the three BER envelopes;
			// mutate the signature itself, not its unsigned framing.
			offsets["cms"] = bytes.Index(data, blob.Data) + len(blob.Data) - 7
		}
	}
	for name, offset := range offsets {
		changed := bytes.Clone(data)
		changed[offset] ^= 1
		path := filepath.Join(dir, "tampered-"+name)
		if err := os.WriteFile(path, changed, 0755); err != nil {
			t.Fatal(err)
		}
		if _, _, code := run(t, binaryPath, "--verify", "--trust", cert, path); code == 0 {
			t.Fatal("Go accepted", name, "tampering")
		}
		if _, _, code := run(t, apple(t), "--verify", "--strict", path); code == 0 {
			t.Fatal("Apple accepted", name, "tampering")
		}
	}
}

func verifyCMSWithOpenSSL(t *testing.T, path, dir string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := codesign.InspectBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range report.Architectures {
		var cms, cd []byte
		for _, blob := range arch.Signature.Blobs {
			if blob.Slot == codesign.SlotCMS {
				cms = blob.Data[8:]
			}
			if blob.Slot == codesign.SlotDirectory {
				cd = blob.Data
			}
		}
		cmsPath, cdPath := filepath.Join(dir, "cms.der"), filepath.Join(dir, "directory.der")
		if err := os.WriteFile(cmsPath, cms, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cdPath, cd, 0600); err != nil {
			t.Fatal(err)
		}
		out, stderr, code := run(t, "/usr/bin/openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", cmsPath, "-content", cdPath, "-noverify")
		if code != 0 || !bytes.Equal([]byte(out), cd) {
			t.Fatalf("OpenSSL CMS verification: %d %s", code, stderr)
		}
	}
}
