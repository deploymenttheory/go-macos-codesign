package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSigningNoticeWriteFailure(t *testing.T) {
	for _, profile := range []string{"macho", "dmg", "bundle"} {
		for _, mode := range []string{"sign", "dryrun"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "hello")
				records := []map[string]any{}
				for _, exe := range []string{binaryPath, apple(t)} {
					denied, perm := dir, os.FileMode(0o555)
					switch profile {
					case "macho":
						copyFixture(t, "adhoc-arm64", path)
					case "dmg":
						seedDryRunDMG(t, exe, path, "zlib", "signed")
						denied, perm = path, 0o444
					case "bundle":
						path = filepath.Join(dir, "Example.app")
						if err := os.RemoveAll(path); err != nil {
							t.Fatal(err)
						}
						bundleFixture(t, path, "arm64")
						mustRun(t, exe, "-s", "-", path)
						denied = filepath.Join(path, "Contents/_CodeSignature/CodeResources")
						if err := os.Remove(denied); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(denied, 0755); err != nil {
							t.Fatal(err)
						}
					}
					before := layoutArchive(t, dir)
					if profile != "bundle" {
						if err := os.Chmod(denied, perm); err != nil {
							t.Fatal(err)
						}
					}
					args := []string{"-fs", "-", "--timestamp=none", "-i", "changed"}
					if mode == "dryrun" {
						args = append(args, "--dryrun")
					}
					out, stderr, status := run(t, exe, append(args, path)...)
					if err := os.Chmod(denied, 0755); err != nil {
						t.Fatal(err)
					}
					if profile == "dmg" {
						if err := os.Chmod(path, 0644); err != nil {
							t.Fatal(err)
						}
					}
					notice := path + ": replacing existing signature\n"
					wantStatus := 1
					if profile == "bundle" && mode == "dryrun" {
						wantStatus = 0
					}
					if status != wantStatus || out != "" || !strings.HasPrefix(stderr, notice) || strings.Count(stderr, notice) != 1 || status != 0 && stderr == notice {
						t.Fatalf("%s: exit=%d stdout=%q stderr=%q", exe, status, out, stderr)
					}
					nativeEqual(t, "failed write preservation", layoutArchive(t, dir), before)
					records = append(records, map[string]any{"stdout": out, "stderr": stderr, "exit": status})
				}
				// Error wording is deliberately retained in both records. This
				// slice matches the notice and its position, not all OS errors.
				attest(t, map[string]any{"profile": profile, "mode": mode, "records": records, "native_compared": true, "notice_before_failure": true, "bytes_preserved": true, "remaining_error_text_difference": records[0]["stderr"] != records[1]["stderr"]})
			})
		}
	}
}

func TestSigningNoticeContinueAfterFailure(t *testing.T) {
	for _, continued := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop", true: "continue"}[continued], func(t *testing.T) {
			dir := t.TempDir()
			denied := filepath.Join(dir, "denied")
			if err := os.Mkdir(denied, 0755); err != nil {
				t.Fatal(err)
			}
			first, second := filepath.Join(denied, "first"), filepath.Join(dir, "second")
			records := []map[string]any{}
			var outputs [][]byte
			for _, exe := range []string{binaryPath, apple(t)} {
				copyFixture(t, "adhoc-arm64", first)
				copyFixture(t, "adhoc-arm64", second)
				before := nativeRead(t, first)
				if err := os.Chmod(denied, 0555); err != nil {
					t.Fatal(err)
				}
				args := []string{"-fs", "-", "--timestamp=none", "-i", "changed"}
				if continued {
					args = append(args, "--continue")
				}
				out, stderr, status := run(t, exe, append(args, first, second)...)
				if err := os.Chmod(denied, 0755); err != nil {
					t.Fatal(err)
				}
				notice := first + ": replacing existing signature\n"
				secondNotice := second + ": replacing existing signature\n"
				if out != "" || status != 1 || !strings.HasPrefix(stderr, notice) || strings.Contains(stderr, secondNotice) != continued {
					t.Fatalf("%s: exit=%d stdout=%q stderr=%q", exe, status, out, stderr)
				}
				if continued && !strings.HasSuffix(stderr, secondNotice) {
					t.Fatal("notice reordered before previous error", stderr)
				}
				nativeEqual(t, "failed first target", nativeRead(t, first), before)
				after := nativeRead(t, second)
				if (hash(after) != hash(before)) != continued {
					t.Fatal("unexpected later target mutation")
				}
				outputs = append(outputs, after)
				records = append(records, map[string]any{"stdout": out, "stderr": stderr, "exit": status})
			}
			nativeEqual(t, "continued signing", outputs[0], outputs[1])
			attest(t, map[string]any{"continued": continued, "records": records, "native_compared": true, "notice_order_matches": true, "output_sha256": hash(outputs[0]), "remaining_error_text_difference": records[0]["stderr"] != records[1]["stderr"]})
		})
	}
}
