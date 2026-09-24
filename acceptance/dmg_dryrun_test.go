package acceptance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var dmgDryRunModes = []string{"plain", "pages", "runtime", "entitlements", "forced-entitlements", "requirement", "combined"}

func dmgDryRunArgs(mode string) []string {
	args := []string{"-fs", "-", "--dryrun", "--timestamp=none", "-i", "org.example.dryrun"}
	switch mode {
	case "pages":
		args = append(args, "--pagesize", "4096")
	case "runtime":
		args = append(args, "--options", "runtime", "--runtime-version", "13.0")
	}
	if mode == "entitlements" || mode == "forced-entitlements" || mode == "combined" {
		args = append(args, "--entitlements", filepath.Join(root, "testdata/entitlements.plist"))
	}
	if mode == "forced-entitlements" || mode == "combined" {
		args = append(args, "--force-library-entitlements")
	}
	if mode == "requirement" || mode == "combined" {
		args = append(args, `-r=designated => identifier "org.example.dryrun"`)
	}
	return args
}

func seedDryRunDMG(t *testing.T, exe, path, profile, state string) {
	t.Helper()
	if err := os.WriteFile(path, dmgFixture(t, profile), 0o644); err != nil {
		t.Fatal(err)
	}
	if state == "signed" {
		mustRun(t, exe, "-s", "-", "-i", "org.example.old", "--timestamp=none", path)
	}
}

func assertUnsignedDMG(t *testing.T, exe, path string) {
	t.Helper()
	for _, operation := range []string{"--verify", "-dvv"} {
		out, stderr, status := run(t, exe, operation, path)
		if status != 1 || out != "" || stderr != path+": code object is not signed at all\n" {
			t.Fatalf("%s %s: exit=%d stdout=%q stderr=%q", exe, operation, status, out, stderr)
		}
	}
}

func TestDMGDryRun(t *testing.T) {
	for _, profile := range []string{"raw", "zlib", "lzfse", "lzma", "apfs"} {
		for _, state := range []string{"unsigned", "signed"} {
			for _, mode := range dmgDryRunModes {
				t.Run(profile+"/"+state+"/"+mode, func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "image.dmg")
					seedDryRunDMG(t, binaryPath, path, profile, state)
					before := nativeRead(t, path)
					original := accessFileInfo(t, path)
					args := append(dmgDryRunArgs(mode), path)
					out, stderr, status := run(t, binaryPath, args...)
					diagnostics := map[string]any{"go_stdout": out, "go_stderr": stderr, "exit": status}
					if status != 0 {
						t.Fatalf("dry run: %d %s%s", status, out, stderr)
					}
					got := nativeRead(t, path)
					if !os.SameFile(original, accessFileInfo(t, path)) || hash(got) == hash(before) {
						t.Fatal("dry run must change bytes without replacing inode")
					}
					assertUnsignedDMG(t, binaryPath, path)
					nativeCompared := runtime.GOOS == "darwin"
					if nativeCompared {
						seedDryRunDMG(t, apple(t), path, profile, state)
						wantOut, wantErr, wantStatus := run(t, apple(t), args...)
						expectedNativeError := ""
						if state == "signed" {
							expectedNativeError = path + ": replacing existing signature\n"
						}
						// The existing CLI has no replacement notice for any format.
						// Record this exact gap; do not normalize away arbitrary output.
						if out != "" || wantOut != "" || stderr != "" || wantErr != expectedNativeError || status != wantStatus {
							t.Fatalf("native dry-run diagnostics: Go %d %q %q, Apple %d %q %q", status, out, stderr, wantStatus, wantOut, wantErr)
						}
						diagnostics["native_stdout"], diagnostics["native_stderr"] = wantOut, wantErr
						diagnostics["replacement_notice_missing"] = state == "signed"
						nativeEqual(t, "DMG dry run", got, nativeRead(t, path))
						assertUnsignedDMG(t, apple(t), path)
					}
					if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
						if err := os.MkdirAll(export, 0o755); err != nil {
							t.Fatal(err)
						}
						name := "dryrun-dmg-" + profile + "-" + state + "-" + mode + ".dmg"
						if err := os.WriteFile(filepath.Join(export, name), got, 0o644); err != nil {
							t.Fatal(err)
						}
					}
					// The directory-less container is unsigned: neither repeating a dry
					// run nor applying a real signature requires --force.
					args[0] = "-s"
					mustRun(t, binaryPath, args...)
					nativeEqual(t, "repeated dry run", nativeRead(t, path), got)
					if nativeCompared {
						mustRun(t, apple(t), args...)
						nativeEqual(t, "native repeated dry run", nativeRead(t, path), got)
					}
					mustRun(t, binaryPath, "-s", "-", "--timestamp=none", "-i", "org.example.recovered", path)
					mustRun(t, binaryPath, "--verify", path)
					if nativeCompared {
						mustRun(t, apple(t), "--verify", "--strict", path)
						recovered := nativeRead(t, path)
						if err := os.WriteFile(path, got, 0o644); err != nil {
							t.Fatal(err)
						}
						mustRun(t, apple(t), "-s", "-", "--timestamp=none", "-i", "org.example.recovered", path)
						nativeEqual(t, "native re-sign after dry run", recovered, nativeRead(t, path))
					}
					attest(t, map[string]any{"profile": profile, "state": state, "mode": mode, "output_sha256": hash(got), "native_compared": nativeCompared, "unsigned": true, "repeated_without_force": true, "resigned_without_force": true, "inode_preserved": true, "diagnostics": diagnostics})
				})
			}
		}
	}
}

func accessFileInfo(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestVerifyImportedDMGDryRuns(t *testing.T) {
	dir := os.Getenv("MACOSCODESIGN_IMPORT_DIR")
	if dir == "" {
		return
	}
	reference := apple(t)
	want := map[string][]byte{}
	for _, profile := range []string{"raw", "zlib", "lzfse", "lzma", "apfs"} {
		for _, state := range []string{"unsigned", "signed"} {
			for _, mode := range dmgDryRunModes {
				path := filepath.Join(t.TempDir(), "image.dmg")
				seedDryRunDMG(t, reference, path, profile, state)
				mustRun(t, reference, append(dmgDryRunArgs(mode), path)...)
				want["dryrun-dmg-"+profile+"-"+state+"-"+mode+".dmg"] = nativeRead(t, path)
			}
		}
	}
	seen := map[string]int{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "dryrun-dmg-") {
			return nil
		}
		expected, ok := want[d.Name()]
		if !ok {
			t.Fatalf("unexpected dry-run artifact %s", path)
		}
		nativeEqual(t, "foreign DMG dry run "+path, nativeRead(t, path), expected)
		assertUnsignedDMG(t, reference, path)
		seen[d.Name()]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range want {
		if seen[name] != 2 {
			t.Fatalf("expected Linux and Windows artifact %s, found %d", name, seen[name])
		}
	}
	attest(t, map[string]any{"imported_dmg_dryruns_compared": 2 * len(want), "native_unsigned": true, "complete_byte_equality": true})
}
