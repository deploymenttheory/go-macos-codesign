package acceptance

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func extractionDirectory(t *testing.T) string {
	t.Helper()
	// Compare raw display on canonical inputs. Bundle-parent alias reporting is
	// an existing separate discovery gap; do not normalize the tool output.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func certificateExtractionInput(t *testing.T, dir, format, identity string) (string, [][]byte) {
	t.Helper()
	var id *codesign.Identity
	if identity != "adhoc" {
		name := filepath.Join(root, "testdata/identities", identity+"-identity.pem")
		if identity == "chain" {
			name = filepath.Join(root, "testdata/chains/root-identity.pem")
		}
		var err error
		id, err = codesign.LoadIdentityPEM(nativeRead(t, name), nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	opts := codesign.SignOptions{Identity: id, Identifier: "org.example.extract", Deep: true, SigningTime: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}
	path := filepath.Join(dir, "input")
	switch format {
	case "app":
		path = filepath.Join(dir, "Example.app")
		bundleFixture(t, path, "arm64")
	case "framework":
		path = layoutFixture(t, dir, "versioned", "arm64", "binary")
	default:
		data := dmgFixture(t, "zlib")
		if format != "dmg" {
			data = nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+format))
		}
		if err := os.WriteFile(path, data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := codesign.Sign(context.Background(), path, opts); err != nil {
		t.Fatal(err)
	}
	if id == nil {
		return path, nil
	}
	return path, id.Certificates
}

func TestCertificateExtraction(t *testing.T) {
	for _, format := range []string{"arm64", "x86_64", "universal", "app", "framework", "dmg"} {
		for _, identity := range []string{"adhoc", "rsa", "p256", "chain"} {
			for _, mode := range []string{"default", "empty", "prefix", "verbose"} {
				t.Run(format+"/"+identity+"/"+mode, func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					path, certs := certificateExtractionInput(t, dir, format, identity)
					before := layoutArchive(t, dir)
					args, prefix := []string{"-d", "--extract-certificates"}, "codesign"
					if mode != "default" {
						prefix = "chain-"
						if mode == "empty" {
							prefix = ""
						}
						args[1] += "=" + prefix
					}
					if mode == "verbose" {
						args[0] = "-dvv"
					}
					args = append(args, path)
					programs := []string{binaryPath}
					if runtime.GOOS == "darwin" {
						programs = append(programs, apple(t))
					}
					var goOut, goErr string
					hashes := []string{}
					for i, exe := range programs {
						out, stderr, status := run(t, exe, args...)
						if status != 0 || out != "" {
							t.Fatalf("%s: exit=%d stdout=%q stderr=%q", exe, status, out, stderr)
						}
						if i == 0 {
							goOut, goErr = out, stderr
						} else if out != goOut || stderr != goErr {
							t.Fatalf("native display differs: Go %q %q, Apple %q %q", goOut, goErr, out, stderr)
						}
						for n, cert := range certs {
							name := prefix + strconv.Itoa(n)
							got := nativeRead(t, name)
							nativeEqual(t, "certificate "+name, got, cert)
							if i == 0 {
								hashes = append(hashes, hash(got))
							}
							if err := os.Remove(name); err != nil {
								t.Fatal(err)
							}
						}
						nativeEqual(t, "no extra output/input mutation", layoutArchive(t, dir), before)
					}
					attest(t, map[string]any{"format": format, "identity": identity, "mode": mode, "certificates": len(certs), "certificate_sha256": hashes, "stderr": goErr, "native_compared": len(programs) == 2, "input_preserved": true, "exact_display": true})
				})
			}
		}
	}
}

func TestCertificateExtractionOutputLifecycle(t *testing.T) {
	for _, mode := range []string{"overwrite", "stale", "missing-parent", "directory-zero", "directory-one", "symlink", "hardlink", "repeated-prefix"} {
		t.Run(mode, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			path, certs := certificateExtractionInput(t, dir, "arm64", "chain")
			input := nativeRead(t, path)
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			var goErr string
			var after []byte
			for i, exe := range programs {
				outDir := filepath.Join(dir, "out")
				if err := os.RemoveAll(outDir); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(outDir, 0755); err != nil {
					t.Fatal(err)
				}
				prefix := filepath.Join(outDir, "cert")
				var original os.FileInfo
				switch mode {
				case "overwrite", "symlink", "hardlink":
					if err := os.WriteFile(prefix+"0", bytes.Repeat([]byte("old"), 1000), 0600); err != nil {
						t.Fatal(err)
					}
					// File.Stat captures Windows identity immediately. Path-based
					// Stat loads it lazily and would inspect the new symlink after
					// this fixture renames the original output below.
					file, err := os.Open(prefix + "0")
					if err != nil {
						t.Fatal(err)
					}
					original, err = file.Stat()
					closeErr := file.Close()
					if err != nil || closeErr != nil {
						t.Fatal(err, closeErr)
					}
					if mode == "hardlink" {
						if err := os.Link(prefix+"0", filepath.Join(outDir, "neighbour")); err != nil {
							t.Fatal(err)
						}
					}
					if mode == "symlink" {
						if err := os.Rename(prefix+"0", filepath.Join(outDir, "neighbour")); err != nil {
							t.Fatal(err)
						}
						layoutLink(t, outDir, "cert0", "neighbour")
					}
				case "stale":
					if err := os.WriteFile(prefix+"3", []byte("retained"), 0644); err != nil {
						t.Fatal(err)
					}
				case "missing-parent":
					prefix = filepath.Join(outDir, "missing", "cert")
				case "directory-zero", "directory-one":
					n := "0"
					if mode == "directory-one" {
						n = "1"
					}
					if err := os.Mkdir(prefix+n, 0755); err != nil {
						t.Fatal(err)
					}
				}
				args := []string{"-d", "--extract-certificates=" + prefix}
				if mode == "repeated-prefix" {
					args = []string{"-d", "--extract-certificates=ignored", "--extract-certificates=" + prefix}
				}
				out, stderr, status := run(t, exe, append(args, path)...)
				failure := mode == "missing-parent" || strings.HasPrefix(mode, "directory-")
				wantStatus := 0
				wantErr := "Executable=" + path + "\n"
				if failure {
					wantStatus = 1
					message := "Is a directory"
					if mode == "missing-parent" {
						message = "No such file or directory"
					}
					wantErr += path + ": " + message + "\n"
				}
				if out != "" || stderr != wantErr || status != wantStatus {
					t.Fatalf("%s: exit=%d stdout=%q stderr=%q", exe, status, out, stderr)
				}
				if !failure || mode == "directory-one" {
					nativeEqual(t, "first extracted DER", nativeRead(t, prefix+"0"), certs[0])
				}
				if original != nil {
					current := accessFileInfo(t, prefix+"0")
					same := os.SameFile(original, current)
					if !same || original.Mode() != current.Mode() {
						t.Fatalf("existing certificate changed: same_file=%t before_mode=%v after_mode=%v before=%+v after=%+v", same, original.Mode(), current.Mode(), original.Sys(), current.Sys())
					}
				}
				if mode == "hardlink" || mode == "symlink" {
					nativeEqual(t, "linked output", nativeRead(t, filepath.Join(outDir, "neighbour")), certs[0])
				}
				if mode == "stale" && string(nativeRead(t, prefix+"3")) != "retained" {
					t.Fatal("removed stale output")
				}
				if i == 0 {
					goErr, after = stderr, layoutArchive(t, outDir)
				} else {
					if stderr != goErr {
						t.Fatalf("diagnostics: Go %q, Apple %q", goErr, stderr)
					}
					nativeEqual(t, "complete output directory", after, layoutArchive(t, outDir))
				}
				nativeEqual(t, "input preserved", nativeRead(t, path), input)
			}
			attest(t, map[string]any{"mode": mode, "native_compared": len(programs) == 2, "stderr": goErr, "output_sha256": hash(after), "input_preserved": true, "exact_diagnostics": true})
		})
	}
}

func TestCertificateExtractionMultipleTargets(t *testing.T) {
	for _, mode := range []string{"success", "stop", "continue"} {
		t.Run(mode, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			for _, name := range []string{"first", "second"} {
				if err := os.Mkdir(name, 0755); err != nil {
					t.Fatal(err)
				}
			}
			first, chain := certificateExtractionInput(t, filepath.Join(dir, "first"), "arm64", "chain")
			second, leaf := certificateExtractionInput(t, filepath.Join(dir, "second"), "arm64", "p256")
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			var goErr string
			var after []byte
			for i, exe := range programs {
				if err := os.RemoveAll("out"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir("out", 0755); err != nil {
					t.Fatal(err)
				}
				if mode != "success" {
					if err := os.Mkdir("out/cert1", 0755); err != nil {
						t.Fatal(err)
					}
				}
				args := []string{"-d", "--extract-certificates=out/cert"}
				if mode == "continue" {
					args = append(args, "--continue")
				}
				out, stderr, status := run(t, exe, append(args, first, second)...)
				wantStatus := 0
				wantErr := "Executable=" + first + "\n"
				if mode != "success" {
					wantStatus = 1
					wantErr += first + ": Is a directory\n"
				}
				if mode != "stop" {
					wantErr += "Executable=" + second + "\n"
				}
				if out != "" || stderr != wantErr || status != wantStatus {
					t.Fatalf("%s: %d %q %q", exe, status, out, stderr)
				}
				want := leaf[0]
				if mode == "stop" {
					want = chain[0]
				}
				nativeEqual(t, "last reached leaf", nativeRead(t, "out/cert0"), want)
				if mode == "success" {
					for n := 1; n < len(chain); n++ {
						nativeEqual(t, "retained earlier chain", nativeRead(t, "out/cert"+strconv.Itoa(n)), chain[n])
					}
				}
				if i == 0 {
					goErr, after = stderr, layoutArchive(t, "out")
				} else {
					if stderr != goErr {
						t.Fatalf("Go %q, Apple %q", goErr, stderr)
					}
					nativeEqual(t, "multiple-target outputs", after, layoutArchive(t, "out"))
				}
			}
			attest(t, map[string]any{"mode": mode, "native_compared": len(programs) == 2, "stderr": goErr, "output_sha256": hash(after), "exact_diagnostics": true})
		})
	}
}

func TestCertificateExtractionSignatureState(t *testing.T) {
	for _, mode := range []string{"unsigned", "page", "cms", "arm64", "x86_64"} {
		t.Run(mode, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			path, certs := certificateExtractionInput(t, dir, "universal", "rsa")
			data := nativeRead(t, path)
			args := []string{"-d", "--extract-certificates=cert"}
			switch mode {
			case "unsigned":
				data = nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-universal"))
				certs = nil
			case "arm64", "x86_64":
				args = append(args, "-a", mode)
			case "page", "cms":
				r, err := codesign.InspectBytes(data)
				if err != nil {
					t.Fatal(err)
				}
				for _, a := range r.Architectures {
					if mode == "page" {
						data[a.Offset+4096] ^= 1
					} else {
						cms := signatureBlob(a.Signature, codesign.SlotCMS)
						at := bytes.Index(data, cms)
						if at < 0 {
							t.Fatal("missing CMS")
						}
						data[at+len(cms)-1] ^= 1
					}
				}
				if mode == "cms" {
					certs = nil
				}
			}
			if err := os.WriteFile(path, data, 0755); err != nil {
				t.Fatal(err)
			}
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			var goErr string
			for i, exe := range programs {
				out, stderr, status := run(t, exe, append(args, path)...)
				wantStatus := 0
				if mode == "unsigned" {
					wantStatus = 1
				}
				if out != "" || status != wantStatus {
					t.Fatalf("%s: %d %q %q", exe, status, out, stderr)
				}
				if i == 0 {
					goErr = stderr
				} else if stderr != goErr {
					t.Fatalf("Go %q, Apple %q", goErr, stderr)
				}
				for n, cert := range certs {
					name := "cert" + strconv.Itoa(n)
					nativeEqual(t, "state certificate", nativeRead(t, name), cert)
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := os.Stat("cert0"); !os.IsNotExist(err) {
					t.Fatal("unexpected certificate output", err)
				}
				nativeEqual(t, "state input preserved", nativeRead(t, path), data)
			}
			attest(t, map[string]any{"mode": mode, "native_compared": len(programs) == 2, "stderr": goErr, "certificates": len(certs), "input_preserved": true, "exact_diagnostics": true})
		})
	}
}

func TestCertificateExtractionIgnoredOperations(t *testing.T) {
	for _, operation := range []string{"sign", "verify", "remove"} {
		t.Run(operation, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			path := filepath.Join(dir, "input")
			args := []string{"--verify"}
			if operation == "sign" {
				args = []string{"-fs", "-", "-i", "org.example.extract", "--timestamp=none"}
			}
			if operation == "remove" {
				args = []string{"--remove-signature"}
			}
			args = append(args, "--extract-certificates=cert", path)
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			var goErr string
			var after []byte
			for i, exe := range programs {
				copyFixture(t, "adhoc-arm64", path)
				out, stderr, status := run(t, exe, args...)
				if status != 0 || out != "" {
					t.Fatal(exe, status, out, stderr)
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 1 {
					t.Fatal("unexpected extraction", entries, err)
				}
				if i == 0 {
					goErr, after = stderr, nativeRead(t, path)
				} else {
					if stderr != goErr {
						t.Fatal("diagnostic mismatch", goErr, stderr)
					}
					nativeEqual(t, "ignored-option operation", nativeRead(t, path), after)
				}
			}
			attest(t, map[string]any{"operation": operation, "native_compared": len(programs) == 2, "exact_diagnostics": true, "no_extracted_files": true, "output_sha256": hash(after)})
		})
	}
}
