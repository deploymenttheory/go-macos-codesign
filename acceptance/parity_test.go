package acceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"howett.net/plist"
)

const entitlementXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/><key>test-array</key><array><string>one</string><false/></array><key>test-int</key><integer>42</integer><key>test-string</key><string>hello</string></dict></plist>
`

func TestAppleByteParity(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mode := range []string{"adhoc", "entitlements", "exec-flags", "runtime", "requirement", "pagesize", "flags"} {
			t.Run(arch+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				expected, actual := filepath.Join(dir, "apple"), filepath.Join(dir, "go")
				copyFixture(t, "unsigned-"+arch, expected)
				copyFixture(t, "unsigned-"+arch, actual)
				args := []string{"-s", "-", "-i", "org.example.fixture", "--timestamp=none"}
				switch mode {
				case "entitlements", "exec-flags":
					ent := filepath.Join(dir, "entitlements.plist")
					data := []byte(entitlementXML)
					if mode == "exec-flags" {
						data = []byte(`<plist version="1.0"><dict><key>get-task-allow</key><true/><key>dynamic-codesigning</key><true/></dict></plist>`)
					}
					if err := os.WriteFile(ent, data, 0600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "--entitlements", ent)
				case "runtime":
					args = append(args, "-o", "runtime")
				case "requirement":
					args = append(args, `-r=designated => identifier "org.example.fixture"`)
				case "pagesize":
					args = append(args, "-P", "4096")
				case "flags":
					args = append(args, "-o", "hard,kill,library")
				}
				mustRun(t, reference, append(args, expected)...)
				mustRun(t, binaryPath, append(args, actual)...)
				want, err := os.ReadFile(expected)
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(actual)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(want, got) {
					for i := range min(len(want), len(got)) {
						if want[i] != got[i] {
							t.Fatalf("first difference at %#x: Apple=%02x Go=%02x sizes=%d/%d", i, want[i], got[i], len(want), len(got))
						}
					}
					t.Fatal("different sizes", len(want), len(got))
				}
				mustRun(t, reference, "--verify", "--strict", "--verbose=4", actual)
				mustRun(t, binaryPath, "--verify", actual)
				attest(t, map[string]any{"architecture": arch, "mode": mode, "byte_equal": true, "sha256": hash(got), "apple_verified": true})
			})
		}
	}
}

func TestAppleDisplayParity(t *testing.T) {
	reference := apple(t)
	path := filepath.Join(root, "testdata", "macho", "adhoc-arm64")
	for _, v := range []string{"-d", "-dv", "-dvv", "-dvvv", "-dvvvv"} {
		t.Run(v, func(t *testing.T) {
			ao, ae, ac := run(t, reference, v, path)
			goout, ge, gc := run(t, binaryPath, v, path)
			if ao != goout || ae != ge || ac != gc {
				t.Fatalf("Apple (%d): %s%s\nGo (%d): %s%s", ac, ao, ae, gc, goout, ge)
			}
		})
	}
}

func TestAppleRejectsBinaryEntitlements(t *testing.T) {
	reference := apple(t)
	dir := t.TempDir()
	path, ent := filepath.Join(dir, "hello"), filepath.Join(dir, "binary.plist")
	copyFixture(t, "unsigned-arm64", path)
	data, err := plist.Marshal(map[string]any{"get-task-allow": true}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ent, data, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-s", "-", "--entitlements", ent, path}
	ao, ae, ac := run(t, reference, args...)
	goout, ge, gc := run(t, binaryPath, args...)
	if ac != 1 || gc != ac || goout != ao || ge != ae {
		t.Fatalf("Apple (%d) %s%s; Go (%d) %s%s", ac, ao, ae, gc, goout, ge)
	}
	unsigned, err := os.ReadFile(filepath.Join(root, "testdata/macho/unsigned-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unsigned, actual) {
		t.Fatal("failed operation modified input")
	}
}

func TestPortableCLI(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hello")
	copyFixture(t, "unsigned-universal", target)
	if _, _, code := run(t, binaryPath, "--verify", target); code != 1 {
		t.Fatal("unsigned exit", code)
	}
	mustRun(t, binaryPath, "-s", "-", "-i", "org.example.fixture", target)
	want, err := os.ReadFile(filepath.Join(root, "testdata", "macho", "adhoc-universal"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("portable signer differs from Apple fixture")
	}
	mustRun(t, binaryPath, "-vv", target)
	if _, _, code := run(t, binaryPath, `-R=identifier "wrong"`, "-v", target); code != 3 {
		t.Fatal("requirement mismatch exit", code)
	}
	if _, _, code := run(t, binaryPath, "-s", "-", target); code != 1 {
		t.Fatal("already signed exit", code)
	}
	mustRun(t, binaryPath, "-fs", "-", "-i", "org.example.fixture", target)
	mustRun(t, binaryPath, "--remove-signature", target)
	if _, _, code := run(t, binaryPath, "--verify", target); code != 1 {
		t.Fatal("removed signature exit", code)
	}
	for _, args := range [][]string{nil, {"--unknown"}, {"-s"}, {"-s", "-", "-d", target}, {"-h", "1"}} {
		if _, _, code := run(t, binaryPath, args...); code == 0 {
			t.Fatal("invalid arguments succeeded", args)
		}
	}
	if _, _, code := run(t, binaryPath, "--help"); code != 0 {
		t.Fatal("help exit", code)
	}
}

func TestTamperRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tampered")
	copyFixture(t, "adhoc-arm64", path)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[4096] ^= 1
	if err := os.WriteFile(path, b, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, binaryPath, "--verify", path); code != 1 {
		t.Fatal("Go accepted tamper")
	}
	if runtime.GOOS == "darwin" {
		if _, _, code := run(t, apple(t), "--verify", path); code != 1 {
			t.Fatal("Apple accepted tamper")
		}
	}
}

func TestAppleExecution(t *testing.T) {
	reference := apple(t)
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	path := filepath.Join(t.TempDir(), "hello")
	copyFixture(t, "unsigned-"+arch, path)
	mustRun(t, binaryPath, "-s", "-", "-i", "org.example.fixture", path)
	mustRun(t, reference, "--verify", "--strict", path)
	mustRun(t, path)
	attest(t, map[string]any{"architecture": arch, "executed": true, "exit": 0})
}

func TestCrossPlatformArtifact(t *testing.T) {
	dir := os.Getenv("MACOSCODESIGN_EXPORT_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		path := filepath.Join(dir, "signed-"+arch)
		copyFixture(t, "unsigned-"+arch, path)
		mustRun(t, binaryPath, "-s", "-", "-i", "org.example.fixture", path)
		mustRun(t, binaryPath, "--verify", path)
	}
}

func TestVerifyImportedArtifacts(t *testing.T) {
	dir := os.Getenv("MACOSCODESIGN_IMPORT_DIR")
	if dir == "" {
		return
	}
	reference := apple(t)
	count, dmgs, binaryBundles, nestedBundles, recursiveBundles := 0, 0, 0, 0, 0
	layoutArchives, versionArchives, pathArchives := 0, 0, 0
	seen := map[string]int{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), "signed-bundle-") {
			args := []string{"--verify", "--strict"}
			if strings.HasPrefix(d.Name(), "signed-bundle-nested-") {
				nestedBundles++
				args = append(args, "--deep")
			}
			if strings.HasPrefix(d.Name(), "signed-bundle-recursive-") {
				recursiveBundles++
				args = append(args, "--deep")
			}
			mustRun(t, reference, append(args, path)...)
			if strings.HasPrefix(d.Name(), "signed-bundle-binary") {
				binaryBundles++
			}
			count++
			seen[d.Name()]++
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), "signed-") {
			if strings.HasPrefix(d.Name(), "signed-paths-") {
				verifyFrameworkVersionsArchive(t, reference, path)
				pathArchives++
			} else if strings.HasPrefix(d.Name(), "signed-versions-") {
				verifyFrameworkVersionsArchive(t, reference, path)
				versionArchives++
			} else if strings.HasPrefix(d.Name(), "signed-layout-") {
				verifyLayoutArchive(t, reference, path)
				layoutArchives++
			} else {
				mustRun(t, reference, "--verify", "--strict", path)
			}
			if strings.HasPrefix(d.Name(), "signed-dmg-") {
				mustRun(t, "/usr/bin/hdiutil", "verify", path)
				dmgs++
			}
			count++
			seen[d.Name()]++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 336 || dmgs != 30 || binaryBundles != 24 || nestedBundles != 18 || recursiveBundles != 36 || layoutArchives != 126 || versionArchives != 18 || pathArchives != 18 {
		t.Fatalf("expected 336 artifacts including 30 DMGs, 24 binary-plist bundles, 18 nested Mach-O bundles, 36 recursive app trees, 126 layout archives, 18 multi-version trees and 18 direct-path trees from Linux and Windows, found %d/%d/%d/%d/%d/%d/%d/%d", count, dmgs, binaryBundles, nestedBundles, recursiveBundles, layoutArchives, versionArchives, pathArchives)
	}
	for _, profile := range []string{"raw", "zlib", "lzfse", "lzma", "apfs"} {
		for _, identity := range []string{"adhoc", "rsa", "p256"} {
			if seen["signed-dmg-"+profile+"-"+identity+".dmg"] != 2 {
				t.Fatalf("expected both OS DMGs for %s/%s", profile, identity)
			}
		}
	}
	if seen["signed-timestamp-arm64"] != 2 {
		t.Fatal("expected both OS timestamp artifacts")
	}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, identity := range []string{"adhoc", "rsa", "p256"} {
			if seen["signed-paths-"+identity+"-"+arch+".tar"] != 2 {
				t.Fatalf("expected both OS direct-path archives for %s/%s", identity, arch)
			}
			if seen["signed-versions-"+identity+"-"+arch+".tar"] != 2 {
				t.Fatalf("expected both OS multi-version archives for %s/%s", identity, arch)
			}
		}
		for _, kind := range append(append([]string{}, bundleLayouts...), "mixed") {
			for _, identity := range []string{"adhoc", "rsa", "p256"} {
				if seen["signed-layout-"+kind+"-"+identity+"-"+arch+".tar"] != 2 {
					t.Fatalf("expected both OS layout archives for %s/%s/%s", kind, identity, arch)
				}
			}
		}
		for _, profile := range []string{"xml", "mixed"} {
			for _, identity := range []string{"adhoc", "rsa", "p256"} {
				if seen["signed-bundle-recursive-"+profile+"-"+identity+"-"+arch+".app"] != 2 {
					t.Fatalf("expected both OS recursive app trees for %s/%s/%s", profile, identity, arch)
				}
			}
		}
		for _, identity := range []string{"adhoc", "rsa", "p256"} {
			if seen["signed-bundle-nested-"+identity+"-"+arch+".app"] != 2 {
				t.Fatalf("expected both OS nested bundles for %s/%s", identity, arch)
			}
		}
		for _, profile := range []string{"binary", "binary-go"} {
			for _, identity := range []string{"adhoc", "rsa"} {
				if seen["signed-bundle-"+profile+"-"+identity+"-"+arch+".app"] != 2 {
					t.Fatalf("expected both OS binary bundles for %s/%s/%s", profile, identity, arch)
				}
			}
		}
		for _, identity := range []string{"adhoc", "rsa"} {
			if seen["signed-bundle-"+identity+"-"+arch+".app"] != 2 {
				t.Fatalf("expected both OS bundles for %s/%s", identity, arch)
			}
		}
		for _, prefix := range []string{"signed-", "signed-cert-rsa-", "signed-cert-p256-", "signed-cert-p384-", "signed-cert-p521-"} {
			if seen[prefix+arch] != 2 {
				t.Fatalf("expected both OS artifacts for %s%s", prefix, arch)
			}
		}
	}
	for _, name := range []string{"root", "intermediate", "leaf"} {
		if seen["signed-chain-"+name] != 2 {
			t.Fatalf("expected both OS chain artifacts for %s", name)
		}
	}
	for _, algorithm := range []string{"rsa", "p256", "p384", "p521"} {
		for _, profile := range []string{"legacy", "modern"} {
			if seen["signed-pfx-"+algorithm+"-"+profile] != 2 {
				t.Fatalf("expected both OS PKCS#12 artifacts for %s/%s", algorithm, profile)
			}
		}
	}
	attest(t, map[string]any{"imported_artifacts_verified": count, "imported_dmgs_verified": dmgs, "imported_binary_bundles_verified": binaryBundles, "imported_nested_bundles_deep_verified": nestedBundles, "imported_recursive_app_trees_deep_verified": recursiveBundles, "imported_layout_archives_deep_verified": layoutArchives, "imported_framework_version_trees_deep_verified": versionArchives, "imported_framework_path_trees_deep_verified": pathArchives})
}
