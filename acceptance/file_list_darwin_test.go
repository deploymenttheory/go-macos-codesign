package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileListPermission(t *testing.T) {
	dir := extractionDirectory(t)
	t.Chdir(dir)
	path, _ := certificateExtractionInput(t, dir, "arm64", "adhoc")
	if err := os.WriteFile("list", []byte("preserve"), 0444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod("list", 0644) })
	for _, exe := range fileListPrograms(t) {
		out, stderr, code := run(t, exe, "-d", "--continue", "--file-list=list", path, path)
		if code != 1 || out != "" || stderr != "Executable="+path+"\nlist: Permission denied\n" || string(nativeRead(t, "list")) != "preserve" {
			t.Fatal(exe, out, stderr, code)
		}
	}
	attest(t, map[string]any{"native_compared": true, "exact_output": true, "output_preserved": true, "stopped_after_first": true})
}

// Explicit divergences, never counted as native-equivalent success. The local
// native baseline crashes in these combinations; Go returns an error for an
// unsigned dry-run report, rejects removal+file-list before mutation, and safely
// lists a freshly signed DMG. Retain raw output and compare the actual writes.
func TestFileListNativeCrashProfiles(t *testing.T) {
	for _, profile := range []string{"standalone", "app", "dmg-raw"} {
		for _, op := range []string{"remove", "unsigned-dryrun", "fresh-sign"} {
			if op == "remove" && profile == "dmg-raw" {
				continue
			} // Native DMG removal is already unsupported.
			if op == "fresh-sign" && profile != "dmg-raw" {
				continue
			}
			t.Run(profile+"/"+op, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				var goAfter []byte
				var goOut, goErr string
				var goCode int
				for i, exe := range fileListPrograms(t) {
					inputs := filepath.Join(dir, "inputs")
					if err := os.RemoveAll(inputs); err != nil {
						t.Fatal(err)
					}
					path, _, _ := fileListInput(t, inputs, profile, "arm64")
					if op == "remove" {
						mustRun(t, binaryPath, "-fs", "-", path)
					} else if strings.HasPrefix(profile, "dmg-") {
						if err := os.WriteFile(path, dmgFixture(t, "raw"), 0644); err != nil {
							t.Fatal(err)
						}
					}
					before := layoutArchive(t, inputs)
					args := []string{"--remove-signature"}
					if op != "remove" {
						args = []string{"-s", "-", "--timestamp=none"}
						if op == "unsigned-dryrun" {
							args = append(args, "--dryrun")
						}
					}
					out, stderr, code := run(t, exe, append(args, "--file-list=-", path)...)
					current := layoutArchive(t, inputs)
					if i == 0 {
						goAfter = current
						goOut, goErr, goCode = out, stderr, code
						if op == "remove" {
							nativeEqual(t, "rejected combination preserves input", current, before)
						}
						if op == "fresh-sign" {
							if code != 0 || out != path+"\n" || stderr != "" {
								t.Fatal(out, stderr, code)
							}
						} else if code != 1 {
							t.Fatal("expected explicit Go error", code, stderr)
						}
					} else {
						if code != -1 || out != "" || stderr != "" {
							t.Fatalf("native crash baseline changed: exit=%d stdout=%q stderr=%q", code, out, stderr)
						}
						if op != "remove" {
							nativeEqual(t, "native pre-crash writes", current, goAfter)
						} else if string(current) == string(before) {
							t.Fatal("native removal did not occur")
						}
					}
				}
				attest(t, map[string]any{"profile": profile, "operation": op, "native_compared": true, "remaining_crash_difference": true, "native_exit": -1, "go_exit": goCode, "go_stdout": goOut, "go_stderr": goErr, "go_after_sha256": hash(goAfter), "side_effects_checked": true})
			})
		}
	}
}
