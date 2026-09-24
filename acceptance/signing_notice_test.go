package acceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Each native invocation uses exactly the same path and fresh input as Go, so
// stderr comparisons need no normalization. Layout archives bind all file bytes.
func TestSigningReplacementNotice(t *testing.T) {
	profiles := []string{"macho-arm64", "macho-x86_64", "macho-universal", "app", "recursive", "dmg-raw", "dmg-zlib", "dmg-lzfse", "dmg-lzma", "dmg-apfs"}
	profiles = append(profiles, bundleLayouts...)
	for _, profile := range profiles {
		for _, mode := range []string{"unsigned", "replace", "dryrun", "no-force", "bad-page"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				seed := func(exe string) (string, bool) {
					t.Helper()
					var path string
					bundle := false
					switch {
					case strings.HasPrefix(profile, "macho-"):
						path = filepath.Join(dir, "hello")
						copyFixture(t, "unsigned-"+strings.TrimPrefix(profile, "macho-"), path)
					case strings.HasPrefix(profile, "dmg-"):
						path = filepath.Join(dir, "image.dmg")
						seedDryRunDMG(t, exe, path, strings.TrimPrefix(profile, "dmg-"), "unsigned")
					case profile == "app" || profile == "recursive":
						path, bundle = filepath.Join(dir, "Example.app"), true
						if profile == "recursive" {
							recursiveFixture(t, path, "arm64", "mixed")
						} else {
							bundleFixture(t, path, "arm64")
						}
					default:
						path, bundle = layoutFixture(t, dir, profile, "arm64", "binary"), true
					}
					if mode != "unsigned" {
						mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", path)
					}
					return path, bundle
				}
				path, bundle := seed(binaryPath)
				snapshot := func() []byte {
					if bundle {
						return layoutArchive(t, path)
					}
					return nativeRead(t, path)
				}
				before := snapshot()
				args := []string{"-fs", "-", "--deep", "--timestamp=none", "-i", "org.example.notice"}
				wantErr, wantStatus := "", 0
				switch mode {
				case "replace", "dryrun":
					wantErr = path + ": replacing existing signature\n"
					if mode == "dryrun" {
						args = append(args, "--dryrun")
					}
				case "no-force":
					args[0] = "-s"
					wantErr, wantStatus = path+": is already signed\n", 1
				case "bad-page":
					args = append(args, "--pagesize", "3")
					wantErr, wantStatus = "page size must be a power of two\n", 1
				}
				args = append(args, path)
				out, stderr, status := run(t, binaryPath, args...)
				if out != "" || stderr != wantErr || status != wantStatus {
					t.Fatalf("Go: exit=%d stdout=%q stderr=%q, want %d %q", status, out, stderr, wantStatus, wantErr)
				}
				got := snapshot()
				if mode == "no-force" || mode == "bad-page" || mode == "dryrun" && !strings.HasPrefix(profile, "dmg-") {
					nativeEqual(t, "preserved input", got, before)
				}
				nativeCompared := runtime.GOOS == "darwin"
				if nativeCompared {
					if err := os.RemoveAll(path); err != nil {
						t.Fatal(err)
					}
					seed(apple(t))
					wantOut, nativeErr, nativeStatus := run(t, apple(t), args...)
					if out != wantOut || stderr != nativeErr || status != nativeStatus {
						t.Fatalf("native: exit=%d stdout=%q stderr=%q; Go: %d %q %q", nativeStatus, wantOut, nativeErr, status, out, stderr)
					}
					nativeEqual(t, "notice lifecycle", got, snapshot())
				}
				attest(t, map[string]any{"profile": profile, "mode": mode, "stdout": out, "stderr": stderr, "exit": status, "output_sha256": hash(got), "native_compared": nativeCompared, "exact_diagnostics": true})
			})
		}
	}
}

func TestSigningNoticeSignatureState(t *testing.T) {
	for _, profile := range []string{"adhoc", "tampered-page", "tampered-cdhash", "rsa", "p256", "linker-signed", "damaged-directory"} {
		t.Run(profile, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hello")
			data := nativeRead(t, filepath.Join(root, "testdata/macho/adhoc-arm64"))
			switch profile {
			case "rsa", "p256":
				data = nativeRead(t, filepath.Join(root, "testdata/certificate-layout", profile+"-arm64"))
			case "tampered-page":
				data[4096] ^= 1
			case "tampered-cdhash", "linker-signed", "damaged-directory":
				i := bytes.Index(data, []byte{0xfa, 0xde, 0x0c, 0x02})
				if i < 0 {
					t.Fatal("no native CodeDirectory")
				}
				switch profile {
				case "tampered-cdhash":
					data[i+100] ^= 1 // identifier/hash bytes; structurally readable
				case "linker-signed":
					data[i+13] |= 2 // CS_LINKER_SIGNED
				case "damaged-directory":
					data[i+7] = 0 // structurally invalid length
				}
			}
			var records []map[string]any
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			for _, exe := range programs {
				if err := os.WriteFile(path, data, 0755); err != nil {
					t.Fatal(err)
				}
				out, stderr, status := run(t, exe, "-fs", "-", "--timestamp=none", "--dryrun", path)
				want := path + ": replacing existing signature\n"
				if profile == "damaged-directory" {
					// Malformed-signature repair/rejection already differs. Require
					// absence of a notice and record the complete remaining outcome.
					if strings.Contains(stderr, "replacing existing signature") {
						t.Fatal("malformed signature notified", stderr)
					}
				} else if out != "" || status != 0 || stderr != want {
					t.Fatalf("%s: exit=%d stdout=%q stderr=%q, want %q", exe, status, out, stderr, want)
				}
				nativeEqual(t, "dry-run preservation", nativeRead(t, path), data)
				records = append(records, map[string]any{"stdout": out, "stderr": stderr, "exit": status})
			}
			attest(t, map[string]any{"profile": profile, "records": records, "native_compared": len(programs) == 2, "remaining_malformed_difference": profile == "damaged-directory"})
		})
	}
}

func TestSigningNoticeAliasesAndTargets(t *testing.T) {
	for _, kind := range []string{"relative", "chain", "main-executable", "framework-current", "multiple-targets"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			var targets []string
			switch kind {
			case "main-executable":
				app := filepath.Join(dir, "Example.app")
				bundleFixture(t, app, "arm64")
				mustRun(t, binaryPath, "-s", "-", app)
				targets = []string{filepath.Join(app, "Contents/MacOS/hello")}
			case "framework-current":
				app := layoutFixture(t, dir, "versioned", "arm64", "xml")
				mustRun(t, binaryPath, "-s", "-", "--deep", app)
				targets = []string{filepath.Join(app, "Versions/Current")}
			default:
				path := filepath.Join(dir, "hello")
				copyFixture(t, "adhoc-arm64", path)
				if kind == "multiple-targets" {
					unsigned := filepath.Join(dir, "unsigned")
					copyFixture(t, "unsigned-arm64", unsigned)
					targets = []string{path, unsigned, path}
				} else {
					layoutLink(t, dir, "alias", "hello")
					target := filepath.Join(dir, "alias")
					if kind == "chain" {
						layoutLink(t, dir, "outer", "alias")
						target = filepath.Join(dir, "outer")
					}
					targets = []string{target}
				}
			}
			before := layoutArchive(t, dir)
			args := append([]string{"-fs", "-", "--dryrun", "--timestamp=none"}, targets...)
			want := targets[0] + ": replacing existing signature\n"
			if kind == "multiple-targets" {
				want += want
			}
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			for _, exe := range programs {
				out, stderr, status := run(t, exe, args...)
				if status != 0 || out != "" || stderr != want {
					t.Fatalf("%s: exit=%d stdout=%q stderr=%q, want %q", exe, status, out, stderr, want)
				}
				nativeEqual(t, "alias dry run", layoutArchive(t, dir), before)
			}
			attest(t, map[string]any{"profile": kind, "argv": args, "stderr": want, "exit": 0, "input_preserved": true, "native_compared": len(programs) == 2})
		})
	}
}
