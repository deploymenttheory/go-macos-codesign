package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func dmgFixture(t *testing.T, profile string) []byte {
	t.Helper()
	if profile == "apfs" {
		return nativeRead(t, filepath.Join(root, "testdata/dmg/apfs.dmg"))
	}
	if profile == "lzma" {
		return nativeRead(t, filepath.Join(root, "testdata/dmg/hfs-lzma.dmg"))
	}
	compression := map[string]disk.Compression{"raw": disk.CompressionNone, "zlib": disk.CompressionZlib, "lzfse": disk.CompressionLZFSE}[profile]
	data := bytes.Repeat([]byte("public UDIF fixture payload\n"), 200)
	data = append(data, make([]byte, 8192-len(data))...)
	var out bytes.Buffer
	if err := disk.EncodeUDIF(&out, []disk.SourceBlock{{Name: "fixture", Data: data, SectorCount: 16}}, &disk.EncodeOptions{Compression: compression}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestDMGNativeParity(t *testing.T) {
	reference := apple(t)
	for _, profile := range []string{"raw", "zlib", "lzfse", "lzma", "apfs"} {
		t.Run(profile, func(t *testing.T) {
			for _, mode := range []string{"default", "pages", "runtime", "runtime-version", "entitlements", "force-entitlements", "runtime-entitlements", "requirement"} {
				t.Run(mode, func(t *testing.T) {
					dir := t.TempDir()
					native, portable := filepath.Join(dir, "Apple.dmg"), filepath.Join(dir, "Go.dmg")
					for _, path := range []string{native, portable} {
						if err := os.WriteFile(path, dmgFixture(t, profile), 0644); err != nil {
							t.Fatal(err)
						}
					}
					args := []string{"-s", "-", "-i", "org.example.dmg", "--timestamp=none"}
					switch mode {
					case "pages":
						args = append(args, "--pagesize", "4096")
					case "runtime":
						args = append(args, "--options", "runtime")
					case "runtime-version":
						args = append(args, "--options", "runtime", "--runtime-version", "13.0")
					case "runtime-entitlements":
						args = append(args, "--options", "runtime", "--runtime-version", "13.0", "--force-library-entitlements", "--entitlements", filepath.Join(root, "testdata/entitlements.plist"))
					case "entitlements", "force-entitlements":
						args = append(args, "--entitlements", filepath.Join(root, "testdata/entitlements.plist"))
						if mode == "force-entitlements" {
							args = append(args, "--force-library-entitlements")
						}
					case "requirement":
						args = append(args, `-r=designated => identifier "org.example.dmg"`)
					}
					mustRun(t, reference, append(args, native)...)
					mustRun(t, binaryPath, append(args, portable)...)
					nativeEqual(t, "native DMG signature", nativeRead(t, portable), nativeRead(t, native))
					mustRun(t, reference, "--verify", "--strict", portable)
					mustRun(t, binaryPath, "--verify", native)
					for v := 0; v <= 4; v++ {
						option := "-d" + strings.Repeat("v", v)
						_, want, wantCode := run(t, reference, option, native)
						_, got, gotCode := run(t, binaryPath, option, portable)
						resolved, err := filepath.EvalSymlinks(native)
						if err != nil {
							t.Fatal(err)
						}
						want = strings.ReplaceAll(want, resolved, "<image>")
						got = strings.ReplaceAll(got, portable, "<image>")
						if wantCode != gotCode || want != got {
							t.Fatalf("display %s: Go %d:\n%s\nApple %d:\n%s", option, gotCode, got, wantCode, want)
						}
					}
					attest(t, map[string]any{"profile": profile, "mode": mode, "byte_equal": true, "native_strict_verified": true, "display_levels": 5})
				})
			}
		})
	}
}

func TestPortableDMG(t *testing.T) {
	for _, profile := range []string{"raw", "zlib", "lzfse", "lzma", "apfs"} {
		for _, identity := range []string{"adhoc", "rsa", "p256"} {
			t.Run(profile+"/"+identity, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "Example.dmg")
				data := dmgFixture(t, profile)
				if err := os.WriteFile(path, data, 0644); err != nil {
					t.Fatal(err)
				}
				id := "-"
				verify := []string{"--verify"}
				if identity != "adhoc" {
					id = filepath.Join(root, "testdata/identities/"+identity+"-identity.pem")
					verify = append(verify, "--trust", filepath.Join(root, "testdata/identities/"+identity+"-cert.pem"))
				}
				mustRun(t, binaryPath, "-s", id, "--timestamp=none", "-i", "org.example.dmg", path)
				mustRun(t, binaryPath, append(verify, path)...)
				if runtime.GOOS == "darwin" {
					mustRun(t, apple(t), "--verify", "--strict", path)
					mustRun(t, "/usr/bin/hdiutil", "verify", path)
				}
				signed := nativeRead(t, path)
				// The entire compressed payload/plist prefix is unchanged.
				nativeEqual(t, "preserved UDIF payload", signed[:len(data)-512], data[:len(data)-512])
				if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
					if err := os.MkdirAll(export, 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(export, "signed-dmg-"+profile+"-"+identity+".dmg"), signed, 0644); err != nil {
						t.Fatal(err)
					}
				}
				attest(t, map[string]any{"profile": profile, "identity": identity, "payload_preserved": true, "sha256": hash(signed), "native_checked": runtime.GOOS == "darwin"})
			})
		}
	}
}

func TestDMGNativeIdentifier(t *testing.T) {
	reference := apple(t)
	for _, name := range []string{"Example.dmg", "org.example.dmg", "Example.2.3.dmg", "123.dmg", "Example3.2.dmg"} {
		t.Run(name, func(t *testing.T) {
			native, portable := filepath.Join(t.TempDir(), name), filepath.Join(t.TempDir(), name)
			for _, path := range []string{native, portable} {
				if err := os.WriteFile(path, dmgFixture(t, "zlib"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			mustRun(t, reference, "-s", "-", "--timestamp=none", native)
			mustRun(t, binaryPath, "-s", "-", "--timestamp=none", portable)
			nativeEqual(t, "default identifier", nativeRead(t, portable), nativeRead(t, native))
		})
	}
}

func TestDMGNativeRemoval(t *testing.T) {
	for _, signed := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "Example.dmg")
		data := dmgFixture(t, "zlib")
		if signed {
			var err error
			data, err = codesign.SignBytes(context.Background(), data, codesign.SignOptions{Identifier: "org.example.dmg"})
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
		_, stderr, code := run(t, binaryPath, "--remove-signature", path)
		if code != 1 {
			t.Fatal(code, stderr)
		}
		nativeEqual(t, "removal preserves image", nativeRead(t, path), data)
		if runtime.GOOS == "darwin" {
			_, stderr, code = run(t, apple(t), "--remove-signature", path)
			if code != 1 {
				t.Fatal(code, stderr)
			}
			nativeEqual(t, "native removal preserves image", nativeRead(t, path), data)
		}
	}
}

func TestDMGTimestamp(t *testing.T) {
	server, ca, requests, mode := localTimestampAuthority(t)
	defer server.Close()
	path := filepath.Join(t.TempDir(), "Timestamp.dmg")
	if err := os.WriteFile(path, dmgFixture(t, "zlib"), 0644); err != nil {
		t.Fatal(err)
	}
	id := filepath.Join(root, "testdata/identities/rsa-identity.pem")
	cert := filepath.Join(root, "testdata/identities/rsa-cert.pem")
	mustRun(t, binaryPath, "-s", id, "--timestamp="+server.URL, "--timestamp-root", ca, path)
	mustRun(t, binaryPath, "--verify", "--trust", cert, "--timestamp-root", ca, path)
	if requests.Load() != 1 {
		t.Fatal("expected one timestamp for architecture-free image")
	}
	before := nativeRead(t, path)
	mode.Store("status")
	if _, _, code := run(t, binaryPath, "-fs", id, "--timestamp="+server.URL, "--timestamp-root", ca, path); code == 0 {
		t.Fatal("TSA failure accepted")
	}
	nativeEqual(t, "timestamp failure preserves signed image", nativeRead(t, path), before)
	attest(t, map[string]any{"local_tsa_verified": true, "failure_preserved": true})
}

func TestDMGLiveAppleTimestamp(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_LIVE_TIMESTAMP") != "1" {
		t.Skip("opt-in Apple TSA request")
	}
	reference := apple(t)
	path := filepath.Join(t.TempDir(), "Timestamp.dmg")
	if err := os.WriteFile(path, dmgFixture(t, "apfs"), 0644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, binaryPath, "-s", filepath.Join(root, "testdata/identities/rsa-identity.pem"), "--timestamp", path)
	mustRun(t, binaryPath, "--verify", "--trust", filepath.Join(root, "testdata/identities/rsa-cert.pem"), "--timestamp-root", "apple", path)
	mustRun(t, reference, "--verify", "--strict", path)
	r, err := codesign.Inspect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	ts := r.Architectures[0].Signature.CertificateMetadata.Timestamp
	if ts == nil {
		t.Fatal("missing timestamp")
	}
	attest(t, map[string]any{"native_strict_verified": true, "timestamp": ts.Time, "sha256": hash(nativeRead(t, path))})
}

func TestRecordNativeDMGFixtures(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_RECORD_DMG") != "1" {
		t.Skip("opt-in native DMG recording")
	}
	reference := apple(t)
	host, stderr, code := run(t, "/usr/bin/sw_vers")
	if code != 0 {
		t.Fatal(stderr)
	}
	hashes := map[string]string{}
	for _, name := range []string{"apfs.dmg", "hfs-lzma.dmg", "APFS-LICENSE", "apfs-source-manifest.json", "hfs-source-manifest.json"} {
		hashes[name] = hash(nativeRead(t, filepath.Join(root, "testdata/dmg", name)))
	}
	for _, identity := range []string{"adhoc", "rsa", "p256"} {
		profiles := []string{"zlib"}
		keychain := ""
		if identity == "adhoc" {
			profiles = []string{"raw", "zlib", "lzfse"}
		} else {
			keychain = nativeTestKeychain(t, identity)
		}
		for _, profile := range profiles {
			path := filepath.Join(t.TempDir(), "Example.dmg")
			if err := os.WriteFile(path, dmgFixture(t, profile), 0644); err != nil {
				t.Fatal(err)
			}
			args := []string{"-s", "-", "-i", "org.example.dmg", "--timestamp=none"}
			if identity != "adhoc" {
				args[1] = "Public codesign test identity " + identity
				args = append(args, "--keychain", keychain)
			}
			mustRun(t, reference, append(args, path)...)
			mustRun(t, reference, "--verify", "--strict", path)
			name := "native-" + identity + "-" + profile + ".dmg"
			data := nativeRead(t, path)
			f, err := os.OpenFile(filepath.Join(root, "testdata/dmg", name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.Write(data)
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			hashes[name] = hash(data)
		}
	}
	manifest := map[string]any{"schema": 1, "files": hashes, "host": strings.TrimSpace(host), "codesign_sha256": hash(nativeRead(t, reference)), "apfs_revision": "a4b437d9dd8e62e3781004edc44be462793c883e", "native_strict_verified": true, "source": "acceptance/dmg_test.go: dmgFixture and TestRecordNativeDMGFixtures", "sign_arguments": []string{"-s", "<public-test-identity-or-dash>", "-i", "org.example.dmg", "--timestamp=none", "<image>"}}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "testdata/dmg/manifest.json"), append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDMGFixtures(t *testing.T) {
	for _, identity := range []string{"adhoc", "rsa", "p256"} {
		profiles := []string{"zlib"}
		if identity == "adhoc" {
			profiles = []string{"raw", "zlib", "lzfse"}
		}
		for _, profile := range profiles {
			t.Run(identity+"/"+profile, func(t *testing.T) {
				path := filepath.Join(root, "testdata/dmg/native-"+identity+"-"+profile+".dmg")
				want := nativeRead(t, path)
				opts := codesign.SignOptions{Identifier: "org.example.dmg"}
				verify := codesign.VerifyOptions{}
				args := []string{"--verify"}
				if identity != "adhoc" {
					var err error
					opts.Identity, err = codesign.LoadIdentityPEM(nativeRead(t, filepath.Join(root, "testdata/identities/"+identity+"-identity.pem")), nil)
					if err != nil {
						t.Fatal(err)
					}
					verify.TrustedCertificates = opts.Identity.Certificates
					args = append(args, "--trust", filepath.Join(root, "testdata/identities/"+identity+"-cert.pem"))
				}
				mustRun(t, binaryPath, append(args, path)...)
				r, err := codesign.VerifyBytes(context.Background(), want, verify)
				if err != nil {
					t.Fatal(err)
				}
				if metadata := r.Architectures[0].Signature.CertificateMetadata; metadata != nil {
					opts.SigningTime = metadata.SigningTime
				}
				got, err := codesign.SignBytes(context.Background(), dmgFixture(t, profile), opts)
				if err != nil {
					t.Fatal(err)
				}
				if identity != "p256" {
					nativeEqual(t, "native DMG fixture", got, want)
				} else {
					other, err := codesign.VerifyBytes(context.Background(), got, verify)
					if err != nil {
						t.Fatal(err)
					}
					nativeEqual(t, "ECDSA CodeDirectory", other.Architectures[0].Signature.Directories[0].Raw, r.Architectures[0].Signature.Directories[0].Raw)
				}
				attest(t, map[string]any{"identity": identity, "profile": profile, "native_fixture_verified": true, "byte_equal": identity != "p256", "directory_equal": true})
			})
		}
	}
}
