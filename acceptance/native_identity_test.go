package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

// Only public test credentials are imported. Existing keychain contents and
// trust settings are unchanged; the temporary keychain is deleted on cleanup.
func nativeTestKeychain(t *testing.T, algorithm string) string {
	t.Helper()
	apple(t)
	dir := t.TempDir()
	keychain, pfx := filepath.Join(dir, "test.keychain-db"), filepath.Join(dir, "identity.p12")
	const password = "public-codesign-test-only"
	mustRun(t, "/usr/bin/openssl", "pkcs12", "-export", "-in", filepath.Join(root, "testdata/identities", algorithm+"-cert.pem"), "-inkey", filepath.Join(root, "testdata/identities", algorithm+"-key.pem"), "-out", pfx, "-passout", "pass:"+password)
	mustRun(t, "/usr/bin/security", "create-keychain", "-p", password, keychain)
	t.Cleanup(func() { mustRun(t, "/usr/bin/security", "delete-keychain", keychain) })
	mustRun(t, "/usr/bin/security", "unlock-keychain", "-p", password, keychain)
	mustRun(t, "/usr/bin/security", "import", pfx, "-k", keychain, "-P", password, "-T", "/usr/bin/codesign")
	mustRun(t, "/usr/bin/security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", password, keychain)
	return keychain
}

func nativeRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func nativeEqual(t *testing.T, label string, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	offset := 0
	for offset < min(len(got), len(want)) && got[offset] == want[offset] {
		offset++
	}
	t.Fatalf("%s: first difference %#x; Go length=%d sha256=%s; Apple length=%d sha256=%s", label, offset, len(got), hash(got), len(want), hash(want))
}

func TestAppleNativeCertificateLayout(t *testing.T) {
	apple(t)
	for _, algorithm := range []string{"rsa", "p256", "p384", "p521"} {
		t.Run(algorithm, func(t *testing.T) {
			keychain := nativeTestKeychain(t, algorithm)
			id, err := codesign.LoadIdentityPEM(nativeRead(t, filepath.Join(root, "testdata/identities", algorithm+"-identity.pem")), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, arch := range []string{"arm64", "x86_64", "universal"} {
				modes := []string{"default", "runtime", "entitlements", "requirement", "requirement-set"}
				modes = append(modes, "default-empty", "default-host", "default-partial", "default-unordered")
				if algorithm == "rsa" && arch == "arm64" {
					for n := 1; n <= 16; n++ {
						modes = append(modes, fmt.Sprintf("identifier-%d", n))
					}
				}
				for _, mode := range modes {
					t.Run(arch+"/"+mode, func(t *testing.T) {
						dir := t.TempDir()
						native, portable := filepath.Join(dir, "apple"), filepath.Join(dir, "go")
						copyFixture(t, "unsigned-"+arch, native)
						opts := codesign.SignOptions{Identifier: "org.example.certificate", Identity: id}
						var extra []string
						switch mode {
						case "runtime":
							opts.Flags = codesign.FlagRuntime
							extra = []string{"-o", "runtime"}
						case "entitlements":
							opts.Entitlements = nativeRead(t, filepath.Join(root, "testdata/entitlements.plist"))
							extra = []string{"--entitlements", filepath.Join(root, "testdata/entitlements.plist")}
						case "requirement", "requirement-set":
							expression := `designated => identifier "org.example.certificate"`
							if mode == "requirement-set" {
								expression = "host => never guest => never library => always plugin => never " + expression
							}
							opts.Requirements, err = codesign.CompileRequirements(expression)
							if err != nil {
								t.Fatal(err)
							}
							extra = []string{"-r=" + expression}
						default:
							if strings.HasPrefix(mode, "default-") {
								opts.Requirements, _, _ = defaultRequirementInput(t, strings.TrimPrefix(mode, "default-"))
								source := filepath.Join(dir, "requirements.bin")
								if err := os.WriteFile(source, opts.Requirements, 0644); err != nil {
									t.Fatal(err)
								}
								extra = []string{"-r", source}
							}
							if strings.HasPrefix(mode, "identifier-") {
								var n int
								if _, err := fmt.Sscanf(mode, "identifier-%d", &n); err != nil {
									t.Fatal(err)
								}
								opts.Identifier = "org.example." + strings.Repeat("x", n)
							}
						}
						args := append([]string{"--keychain", keychain, "-s", "Public codesign test identity " + algorithm, "-i", opts.Identifier, "--timestamp=none"}, extra...)
						mustRun(t, apple(t), append(args, native)...)
						mustRun(t, apple(t), "--verify", "--strict", native)
						want := nativeRead(t, native)
						wn, err := codesign.VerifyBytes(context.Background(), want, codesign.VerifyOptions{TrustedCertificates: id.Certificates})
						if err != nil {
							t.Fatal("portable verification of Apple signature:", err)
						}
						unsigned := nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+arch))
						for i, a := range wn.Architectures {
							info, err := codesign.VerifyCMS(signatureBlob(a.Signature, codesign.SlotCMS)[8:], [][]byte{a.Signature.Directories[0].Raw})
							if err != nil {
								t.Fatal(err)
							}
							// Signing can cross a second between native fat slices.
							// Match each authenticated time without a timing assumption.
							opts.SigningTime = info.SigningTime
							got, err := codesign.SignBytes(context.Background(), unsigned, opts)
							if err != nil {
								t.Fatal(err)
							}
							gn, err := codesign.VerifyBytes(context.Background(), got, codesign.VerifyOptions{TrustedCertificates: id.Certificates})
							if err != nil {
								t.Fatal(err)
							}
							g := gn.Architectures[i]
							if len(got) != len(want) || a.Offset != g.Offset || a.Size != g.Size || a.SignatureOffset != g.SignatureOffset || a.SignatureSize != g.SignatureSize {
								t.Fatalf("layout: Apple offset=%d signature=%d/%d total=%d; Go offset=%d signature=%d/%d total=%d", a.Offset, a.SignatureOffset, a.SignatureSize, len(want), g.Offset, g.SignatureOffset, g.SignatureSize, len(got))
							}
							nativeEqual(t, "Mach-O and code pages", got[a.Offset:a.Offset+a.SignatureOffset], want[a.Offset:a.Offset+a.SignatureOffset])
							for _, b := range a.Signature.Blobs {
								if b.Slot != codesign.SlotCMS {
									nativeEqual(t, fmt.Sprintf("signature slot %#x", b.Slot), signatureBlob(g.Signature, b.Slot), b.Data)
								}
							}
							if algorithm == "rsa" {
								nativeEqual(t, "complete RSA slice", got[a.Offset:a.Offset+a.Size], want[a.Offset:a.Offset+a.Size])
								if i == 0 {
									nativeEqual(t, "universal header", got[:a.Offset], want[:a.Offset])
								}
							}
							if err := os.WriteFile(portable, got, 0755); err != nil {
								t.Fatal(err)
							}
							mustRun(t, apple(t), "--verify", "--strict", portable)
						}
						attest(t, map[string]any{"algorithm": algorithm, "architecture": arch, "mode": mode, "layout_and_non_cms_bytes_equal": true, "rsa_slice_bytes_equal_at_same_signing_time": algorithm == "rsa", "apple_and_go_verified": true})
						if mode == "default" {
							exportNativeCertificate(t, algorithm, arch, want, args)
						}
					})
				}
			}
		})
	}
}

// Generation is opt-in. Ordinary test runs never rewrite reference fixtures.
func exportNativeCertificate(t *testing.T, algorithm, arch string, data []byte, args []string) {
	t.Helper()
	dir := os.Getenv("MACOSCODESIGN_NATIVE_EXPORT_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	name := algorithm + "-" + arch
	if err := os.WriteFile(filepath.Join(dir, name), data, 0755); err != nil {
		t.Fatal(err)
	}
	mac, _, code := run(t, "/usr/bin/sw_vers")
	if code != 0 {
		t.Fatal("sw_vers failed")
	}
	args = append([]string(nil), args...)
	args[1] = "<temporary-test-keychain>"
	metadata := map[string]any{"sha256": hash(data), "macos": mac, "codesign_sha256": hash(nativeRead(t, apple(t))), "argv": append(args, "<unsigned-"+arch+">"), "apple_strict_verified": true}
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func signatureBlob(s *codesign.Signature, slot uint32) []byte {
	for _, b := range s.Blobs {
		if b.Slot == slot {
			return b.Data
		}
	}
	return nil
}
