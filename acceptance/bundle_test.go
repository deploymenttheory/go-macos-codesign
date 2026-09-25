package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

const bundleInfo = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>hello</string><key>CFBundleIdentifier</key><string>org.example.bundle</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleName</key><string>Example</string></dict></plist>
`

func bundleWrite(t *testing.T, app, name string, data []byte) {
	t.Helper()
	path := filepath.Join(app, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}
func bundleFixture(t *testing.T, app, arch string) {
	t.Helper()
	bundleWrite(t, app, "Contents/Info.plist", []byte(bundleInfo))
	bundleWrite(t, app, "Contents/Resources/message.txt", []byte("hello\n"))
	bundleWrite(t, app, "Contents/Resources/Base.lproj/hello.txt", []byte("base\n"))
	bundleWrite(t, app, "Contents/Resources/fr.lproj/hello.txt", []byte("local\n"))
	bundleWrite(t, app, "Contents/Resources/fr.lproj/locversion.plist", []byte("ignored version\n"))
	bundleWrite(t, app, "Contents/Resources/.DS_Store", []byte("ignored modern metadata\n"))
	bundleWrite(t, app, "Contents/version.plist", []byte("sealed version\n"))
	bundleWrite(t, app, "Contents/PkgInfo", []byte("APPL????"))
	bundleWrite(t, app, "Contents/MacOS/hello", nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+arch)))
	if err := os.Chmod(filepath.Join(app, "Contents/MacOS/hello"), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestPortableAppBundles(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, identity := range []string{"adhoc", "rsa"} {
			t.Run(arch+"/"+identity, func(t *testing.T) {
				app := filepath.Join(t.TempDir(), "Example.app")
				bundleFixture(t, app, arch)
				id := "-"
				verify := []string{"--verify"}
				if identity == "rsa" {
					id = filepath.Join(root, "testdata/identities/rsa-identity.pem")
					verify = append(verify, "--trust", filepath.Join(root, "testdata/identities/rsa-cert.pem"))
				}
				mustRun(t, binaryPath, "-s", id, "--timestamp=none", app)
				mustRun(t, binaryPath, append(verify, app)...)
				out, stderr, code := run(t, binaryPath, "-d", "--json", app)
				if code != 0 || !json.Valid([]byte(out)) {
					t.Fatal(code, stderr)
				}
				var report codesign.Report
				if err := json.Unmarshal([]byte(out), &report); err != nil {
					t.Fatal(err)
				}
				if report.Bundle == nil || report.Bundle.ResourceFiles != 4 || report.Format != "app bundle with Mach-O "+map[bool]string{true: "universal", false: "thin"}[arch == "universal"] {
					t.Fatalf("bundle report %+v", report)
				}
				if runtime.GOOS == "darwin" {
					mustRun(t, apple(t), "--verify", "--strict", app)
				}
				if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
					destination := filepath.Join(export, "signed-bundle-"+identity+"-"+arch+".app")
					if err := os.CopyFS(destination, os.DirFS(app)); err != nil {
						t.Fatal(err)
					}
				}
				attest(t, map[string]any{"architecture": arch, "identity": identity, "main_sha256": hash(nativeRead(t, filepath.Join(app, "Contents/MacOS/hello"))), "resources_sha256": hash(nativeRead(t, filepath.Join(app, "Contents/_CodeSignature/CodeResources"))), "native_strict_verified": runtime.GOOS == "darwin"})
			})
		}
	}
}

func TestAppleAppBundleParity(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			native, portable := filepath.Join(dir, "Native.app"), filepath.Join(dir, "Go.app")
			bundleFixture(t, native, arch)
			bundleFixture(t, portable, arch)
			mustRun(t, reference, "-s", "-", "--timestamp=none", native)
			mustRun(t, binaryPath, "-s", "-", "--timestamp=none", portable)
			for _, name := range []string{"Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources"} {
				nativeEqual(t, name, nativeRead(t, filepath.Join(portable, name)), nativeRead(t, filepath.Join(native, name)))
			}
			for v := 0; v <= 4; v++ {
				option := "-d" + strings.Repeat("v", v)
				_, want, wantCode := run(t, reference, option, native)
				_, got, gotCode := run(t, binaryPath, option, portable)
				if wantCode != gotCode {
					t.Fatal(wantCode, gotCode)
				}
				// The executable's absolute path is the only intentional display difference.
				nativePath, err := filepath.EvalSymlinks(filepath.Join(native, "Contents/MacOS/hello"))
				if err != nil {
					t.Fatal(err)
				}
				portablePath, err := filepath.EvalSymlinks(filepath.Join(portable, "Contents/MacOS/hello"))
				if err != nil {
					t.Fatal(err)
				}
				got = strings.ReplaceAll(got, portablePath, "<executable>")
				want = strings.ReplaceAll(want, nativePath, "<executable>")
				if got != want {
					t.Fatalf("display %s\nGo:\n%s\nApple:\n%s", option, got, want)
				}
			}
			mustRun(t, reference, "--verify", "--strict", portable)
			mustRun(t, binaryPath, "--verify", native)
			attest(t, map[string]any{"architecture": arch, "executable_byte_equal": true, "resource_envelope_byte_equal": true, "display_levels": 5, "native_strict_verified": true})
		})
	}
}

func TestAppBundleMutationParity(t *testing.T) {
	for _, change := range []string{"added", "altered", "missing", "info", "main", "optional-missing", "optional-added", "optional-altered", "base-missing", "ignored", "envelope"} {
		t.Run(change, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "Example.app")
			bundleFixture(t, app, "arm64")
			mustRun(t, binaryPath, "-s", "-", app)
			valid := false
			remove := func(name string) {
				if err := os.Remove(filepath.Join(app, name)); err != nil {
					t.Fatal(err)
				}
			}
			switch change {
			case "added":
				bundleWrite(t, app, "Contents/Resources/new", []byte("new"))
			case "altered":
				bundleWrite(t, app, "Contents/Resources/message.txt", []byte("tampered"))
			case "missing":
				remove("Contents/Resources/message.txt")
			case "info":
				bundleWrite(t, app, "Contents/Info.plist", []byte(strings.Replace(bundleInfo, "Example", "Tampered", 1)))
			case "main":
				p := filepath.Join(app, "Contents/MacOS/hello")
				b := nativeRead(t, p)
				b[4096] ^= 1
				bundleWrite(t, app, "Contents/MacOS/hello", b)
			case "optional-missing":
				remove("Contents/Resources/fr.lproj/hello.txt")
				valid = true
			case "optional-added":
				bundleWrite(t, app, "Contents/Resources/fr.lproj/new", []byte("new"))
			case "optional-altered":
				bundleWrite(t, app, "Contents/Resources/fr.lproj/hello.txt", []byte("tampered"))
			case "base-missing":
				remove("Contents/Resources/Base.lproj/hello.txt")
			case "ignored":
				bundleWrite(t, app, "Contents/Resources/fr.lproj/locversion.plist", []byte("changed"))
				bundleWrite(t, app, "Contents/PkgInfo", []byte("changed"))
				bundleWrite(t, app, "Contents/Resources/.DS_Store", []byte("changed"))
				valid = true
			case "envelope":
				p := filepath.Join(app, "Contents/_CodeSignature/CodeResources")
				b := bytes.Replace(nativeRead(t, p), []byte("message.txt"), []byte("another.txt"), 1)
				bundleWrite(t, app, "Contents/_CodeSignature/CodeResources", b)
			}
			_, stderr, code := run(t, binaryPath, "--verify", app)
			if (code == 0) != valid {
				t.Fatalf("Go: %d %s", code, stderr)
			}
			if runtime.GOOS == "darwin" {
				_, stderr, code = run(t, apple(t), "--verify", "--strict", app)
				if (code == 0) != valid {
					t.Fatalf("Apple: %d %s", code, stderr)
				}
			}
			attest(t, map[string]any{"mutation": change, "valid": valid, "native_checked": runtime.GOOS == "darwin"})
		})
	}
}

func TestAppBundleDryRunAndRemoval(t *testing.T) {
	app := filepath.Join(t.TempDir(), "Example.app")
	bundleFixture(t, app, "arm64")
	original := nativeRead(t, filepath.Join(app, "Contents/MacOS/hello"))
	mustRun(t, binaryPath, "-s", "-", "--dryrun", app)
	nativeEqual(t, "dryrun executable", nativeRead(t, filepath.Join(app, "Contents/MacOS/hello")), original)
	if _, err := os.Stat(filepath.Join(app, "Contents/_CodeSignature")); !os.IsNotExist(err) {
		t.Fatal("dryrun wrote signature directory", err)
	}
	mustRun(t, binaryPath, "-s", "-", app)
	_, _, code := run(t, binaryPath, "-s", "-", app)
	if code != 1 {
		t.Fatal("replaced without force")
	}
	mustRun(t, binaryPath, "-fs", "-", app)
	mustRun(t, binaryPath, "--remove-signature", app)
	_, _, code = run(t, binaryPath, "--verify", app)
	if code != 1 {
		t.Fatal("removed bundle verified")
	}
	mustRun(t, binaryPath, "--remove-signature", app)
	attest(t, map[string]any{"dryrun_preserved": true, "force_required": true, "removed": true})
}

func TestRecordAppleBundleFixtures(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_RECORD_BUNDLES") != "1" {
		t.Skip("opt-in native bundle recording")
	}
	reference := apple(t)
	manifest := map[string]any{"schema": 1, "files": map[string]string{}, "codesign_sha256": hash(nativeRead(t, reference)), "source": "acceptance/bundle_test.go: bundleFixture"}
	host, stderr, code := run(t, "/usr/bin/sw_vers")
	if code != 0 {
		t.Fatal(stderr)
	}
	manifest["host"] = strings.TrimSpace(host)
	manifest["sign_arguments"] = []string{"-s", "-", "--timestamp=none", "<bundle>"}
	manifest["verify_arguments"] = []string{"--verify", "--strict", "<bundle>"}
	manifest["native_strict_verified"] = true
	hashes := manifest["files"].(map[string]string)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		app := filepath.Join(t.TempDir(), "Example.app")
		bundleFixture(t, app, arch)
		mustRun(t, reference, "-s", "-", "--timestamp=none", app)
		mustRun(t, reference, "--verify", "--strict", app)
		dest := filepath.Join(root, "testdata/bundles", arch+".app")
		if err := os.CopyFS(dest, os.DirFS(app)); err != nil {
			t.Fatal(err)
		}
		err := filepath.WalkDir(dest, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				rel, err := filepath.Rel(filepath.Join(root, "testdata/bundles"), path)
				if err != nil {
					return err
				}
				hashes[filepath.ToSlash(rel)] = hash(nativeRead(t, path))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "testdata/bundles/manifest.json"), append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	fmt.Println("Recorded three native app bundle fixtures")
}

func TestNativeBundleFixtures(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			fixtureApp := filepath.Join(root, "testdata/bundles", arch+".app")
			mustRun(t, binaryPath, "--verify", fixtureApp)
			app := filepath.Join(t.TempDir(), "Example.app")
			bundleFixture(t, app, arch)
			mustRun(t, binaryPath, "-s", "-", app)
			for _, name := range []string{"Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources"} {
				nativeEqual(t, "native bundle fixture "+name, nativeRead(t, filepath.Join(app, name)), nativeRead(t, filepath.Join(fixtureApp, name)))
			}
			attest(t, map[string]any{"architecture": arch, "native_fixture_byte_equal": true})
		})
	}
}
