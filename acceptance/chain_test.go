package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestPortablePKCS12(t *testing.T) {
	for _, algorithm := range []string{"rsa", "p256", "p384", "p521"} {
		for _, profile := range []string{"legacy", "modern"} {
			t.Run(algorithm+"/"+profile, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "signed")
				copyFixture(t, "unsigned-arm64", path)
				password := filepath.Join(t.TempDir(), "password")
				if err := os.WriteFile(password, []byte("public-codesign-test-only\n"), 0600); err != nil {
					t.Fatal(err)
				}
				mustRun(t, binaryPath, "-s", filepath.Join(root, "testdata/pkcs12", algorithm+"-"+profile+".p12"), "--password-file", password, "-i", "org.example.pfx", path)
				mustRun(t, binaryPath, "--verify", "--trust", filepath.Join(root, "testdata/identities", algorithm+"-cert.pem"), path)
				_, display, status := run(t, binaryPath, "-dvv", path)
				if status != 0 || !strings.Contains(display, "Authority=Public codesign test identity "+algorithm) || !strings.Contains(display, "Signed Time=") {
					t.Fatal(status, display)
				}
				attest(t, map[string]any{"algorithm": algorithm, "profile": profile, "portable_sign_and_verify": true})
			})
		}
	}
}

func TestApplePKCS12(t *testing.T) {
	apple(t)
	for _, algorithm := range []string{"rsa", "p256", "p384", "p521"} {
		for _, profile := range []string{"legacy", "modern"} {
			t.Run(algorithm+"/"+profile, func(t *testing.T) {
				id, err := codesign.LoadIdentityPKCS12(nativeRead(t, filepath.Join(root, "testdata/pkcs12", algorithm+"-"+profile+".p12")), "public-codesign-test-only")
				if err != nil {
					t.Fatal(err)
				}
				for _, arch := range []string{"arm64", "x86_64", "universal"} {
					path := filepath.Join(t.TempDir(), "signed")
					copyFixture(t, "unsigned-"+arch, path)
					if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Identity: id, Identifier: "org.example.pfx"}); err != nil {
						t.Fatal(err)
					}
					mustRun(t, apple(t), "--verify", "--strict", path)
				}
				attest(t, map[string]any{"algorithm": algorithm, "profile": profile, "apple_verified_architectures": 3})
			})
		}
	}
}

func TestPortableCAChains(t *testing.T) {
	for _, name := range []string{"root", "intermediate", "leaf"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signed")
			copyFixture(t, "unsigned-universal", path)
			mustRun(t, binaryPath, "-s", filepath.Join(root, "testdata/chains", name+"-identity.pem"), "-i", "org.example.chain", path)
			mustRun(t, binaryPath, "--verify", "--trust-root", filepath.Join(root, "testdata/chains", name+"-root.pem"), path)
			_, display, status := run(t, binaryPath, "-dvv", path)
			if status != 0 || strings.Count(display, "Authority=") != 3 || !strings.Contains(display, "TeamIdentifier=not set") {
				t.Fatal(status, display)
			}
		})
	}
}

func TestAppleChainRequirements(t *testing.T) {
	apple(t)
	for _, name := range []string{"root", "intermediate", "leaf"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			pfx := filepath.Join(dir, "chain.p12")
			keychain := filepath.Join(dir, "test.keychain-db")
			const password = "public-codesign-test-only"
			bundle := filepath.Join(root, "testdata/chains", name+"-identity.pem")
			mustRun(t, "/usr/bin/openssl", "pkcs12", "-export", "-in", bundle, "-out", pfx, "-passout", "pass:"+password)
			exported, err := codesign.LoadIdentityPKCS12(nativeRead(t, pfx), password)
			if err != nil {
				t.Fatal("native PFX import", err)
			}
			t.Logf("Native export contains %d certificates", len(exported.Certificates))
			mustRun(t, "/usr/bin/security", "create-keychain", "-p", password, keychain)
			t.Cleanup(func() { mustRun(t, "/usr/bin/security", "delete-keychain", keychain) })
			mustRun(t, "/usr/bin/security", "unlock-keychain", "-p", password, keychain)
			mustRun(t, "/usr/bin/security", "import", pfx, "-k", keychain, "-P", password, "-T", "/usr/bin/codesign")
			certOutput, certErr, certStatus := run(t, "/usr/bin/security", "find-certificate", "-a", keychain)
			t.Logf("Imported certificates (status %d): %s %s", certStatus, certOutput, certErr)
			mustRun(t, "/usr/bin/security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", password, keychain)
			// --keychain selects an identity, but Apple's chain builder still
			// searches the user search list. Append only our disposable keychain
			// and restore the exact original list before deleting it.
			listing, listErr, listStatus := run(t, "/usr/bin/security", "list-keychains", "-d", "user")
			if listStatus != 0 {
				t.Fatal(listErr)
			}
			original := []string{"list-keychains", "-d", "user", "-s"}
			for _, line := range strings.Split(strings.TrimSpace(listing), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				name, err := strconv.Unquote(strings.TrimSpace(line))
				if err != nil {
					t.Fatal(err)
				}
				original = append(original, name)
			}
			t.Cleanup(func() { mustRun(t, "/usr/bin/security", original...) })
			mustRun(t, "/usr/bin/security", append(append([]string(nil), original...), keychain)...)
			native := filepath.Join(dir, "apple")
			copyFixture(t, "unsigned-arm64", native)
			mustRun(t, apple(t), "--keychain", keychain, "-s", "leaf", "-i", "org.example.chain", "--timestamp=none", native)
			id, err := codesign.LoadIdentityPEM(nativeRead(t, bundle), nil)
			if err != nil {
				t.Fatal(err)
			}
			r, err := codesign.Verify(context.Background(), native, codesign.VerifyOptions{TrustedRoots: id.Certificates[2:]})
			if err != nil {
				t.Fatal(err)
			}
			metadata := r.Architectures[0].Signature.CertificateMetadata
			if metadata == nil {
				t.Fatal("missing metadata")
			}
			portable := filepath.Join(dir, "go")
			copyFixture(t, "unsigned-arm64", portable)
			if err := codesign.Sign(context.Background(), portable, codesign.SignOptions{Identity: id, Identifier: "org.example.chain", SigningTime: metadata.SigningTime}); err != nil {
				t.Fatal(err)
			}
			g, err := codesign.Inspect(context.Background(), portable)
			if err != nil {
				t.Fatal(err)
			}
			for _, slot := range []uint32{codesign.SlotDirectory, codesign.SlotRequirements} {
				nativeEqual(t, "chain directory/requirements", signatureBlob(g.Architectures[0].Signature, slot), signatureBlob(r.Architectures[0].Signature, slot))
			}
			mustRun(t, apple(t), "--verify", "--strict", portable)
			_, nativeDisplay, nativeStatus := run(t, apple(t), "-dvv", portable)
			_, portableDisplay, portableStatus := run(t, binaryPath, "-dvv", portable)
			if nativeStatus != 0 || portableStatus != 0 {
				t.Fatal(nativeDisplay, portableDisplay)
			}
			for _, line := range strings.Split(nativeDisplay, "\n") {
				if strings.HasPrefix(line, "Authority=") || strings.HasPrefix(line, "TeamIdentifier=") {
					if !strings.Contains(portableDisplay, line+"\n") {
						t.Fatal("display metadata mismatch", nativeDisplay, portableDisplay)
					}
				}
			}
			attest(t, map[string]any{"organization_anchor": name, "directory_and_requirement_bytes_equal": true, "authority_and_team_display_equal": true, "apple_strict_verified": true, "signing_time": metadata.SigningTime.Format(time.RFC3339)})
		})
	}
}

func TestAppleDeveloperRequirement(t *testing.T) {
	apple(t)
	expression := `identifier "com.microsoft.VSCode" and (anchor apple generic and (certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "UBF8T346G9")))`
	want := filepath.Join(t.TempDir(), "requirement")
	mustRun(t, "/usr/bin/csreq", "-r="+expression, "-b", want)
	got, err := codesign.CompileRequirement(expression)
	if err != nil {
		t.Fatal(err)
	}
	nativeEqual(t, "Developer ID requirement", got, nativeRead(t, want))
}
