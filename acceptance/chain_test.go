package acceptance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
				exportChainArtifact(t, "signed-pfx-"+algorithm+"-"+profile, path)
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
			exportChainArtifact(t, "signed-chain-"+name, path)
		})
	}
}

func exportChainArtifact(t *testing.T, name, path string) {
	t.Helper()
	dir := os.Getenv("MACOSCODESIGN_EXPORT_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), nativeRead(t, path), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestAppleChainRequirements(t *testing.T) {
	apple(t)
	keychain := nativeChainKeychain(t)
	for _, name := range []string{"root", "intermediate", "leaf"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			bundle := filepath.Join(root, "testdata/chains", name+"-identity.pem")
			native := filepath.Join(dir, "apple")
			copyFixture(t, "unsigned-arm64", native)
			mustRun(t, apple(t), "--keychain", keychain, "-s", "leaf-"+name, "-i", "org.example.chain", "--timestamp=none", native)
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

// Tests are serial. Keep one imported chain set alive until TestMain cleanup:
// recreating identical issuers in successive keychains can leave native trust
// evaluation referring to the already-deleted fixture keychain.
var nativeChainPath string
var nativeChainCleanup func() error

func nativeChainKeychain(t *testing.T) string {
	t.Helper()
	if nativeChainPath != "" {
		return nativeChainPath
	}
	if nativeChainCleanup != nil {
		t.Fatal("previous native chain fixture setup failed")
	}
	dir, err := os.MkdirTemp(filepath.Dir(binaryPath), "chains-")
	if err != nil {
		t.Fatal(err)
	}
	keychain := filepath.Join(dir, "chains.keychain-db")
	listing, listErr, status := run(t, "/usr/bin/security", "list-keychains", "-d", "user")
	if status != 0 {
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
	created, changed := false, false
	nativeChainCleanup = func() error {
		var failures []error
		cleanup := func(args ...string) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, "/usr/bin/security", args...).CombinedOutput(); err != nil {
				failures = append(failures, fmt.Errorf("%s: %w: %s", args[0], err, out))
			}
		}
		if changed {
			cleanup(original...)
		}
		if created {
			cleanup("delete-keychain", keychain)
		}
		return errors.Join(failures...)
	}
	const password = "public-codesign-test-only"
	mustRun(t, "/usr/bin/security", "create-keychain", "-p", password, keychain)
	created = true
	mustRun(t, "/usr/bin/security", "unlock-keychain", "-p", password, keychain)
	// All profiles reuse the same public test signing key. Import it once,
	// then import every certificate before any native trust evaluation.
	for _, name := range []string{"root", "intermediate", "leaf"} {
		bundle := filepath.Join(root, "testdata/chains", name+"-identity.pem")
		pfx := filepath.Join(dir, name+".p12")
		mustRun(t, "/usr/bin/openssl", "pkcs12", "-export", "-in", bundle, "-out", pfx, "-passout", "pass:"+password)
		id, err := codesign.LoadIdentityPKCS12(nativeRead(t, pfx), password)
		if err != nil || len(id.Certificates) != 3 {
			t.Fatal("native PFX chain", err)
		}
		if name == "root" {
			mustRun(t, "/usr/bin/security", "import", pfx, "-k", keychain, "-P", password, "-T", "/usr/bin/codesign")
			continue
		}
		for i, der := range id.Certificates {
			path := filepath.Join(dir, name+"-"+strconv.Itoa(i)+".der")
			if err := os.WriteFile(path, der, 0600); err != nil {
				t.Fatal(err)
			}
			mustRun(t, "/usr/bin/security", "import", path, "-k", keychain)
		}
	}
	mustRun(t, "/usr/bin/security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", password, keychain)
	// --keychain selects the identity; SecTrust uses the user search list.
	// Restore the pre-fixture search list before deletion at suite exit, including
	// after a later setup/test failure. No trust settings are installed.
	changed = true
	mustRun(t, "/usr/bin/security", append(append([]string(nil), original...), keychain)...)
	certs, certErr, certStatus := run(t, "/usr/bin/security", "find-certificate", "-a", keychain)
	t.Logf("Native chain search list %s; imported certificates (status %d): %s %s", listing, certStatus, certs, certErr)
	nativeChainPath = keychain
	return keychain
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
