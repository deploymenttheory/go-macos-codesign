package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
	"howett.net/plist"
)

func TestVerificationDiagnostics(t *testing.T) {
	for _, format := range []string{"arm64", "x86_64", "universal", "app", "framework", "dmg"} {
		for _, damage := range []string{"unsigned", "page", "requirements", "info", "resources", "cms-der", "cms-signature"} {
			if (damage == "info" || damage == "resources") && format != "app" && format != "framework" {
				continue
			}
			t.Run(format+"/"+damage, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				path := defaultFixture(t, dir, format)
				algorithm := "adhoc"
				if strings.HasPrefix(damage, "cms-") {
					algorithm = "rsa"
				}
				id, _, trust := verificationIdentity(t, algorithm)
				if damage != "unsigned" {
					if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Identifier: "org.example.diagnostic", Identity: id, SigningTime: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}); err != nil {
						t.Fatal(err)
					}
					r, data := inspectDefaults(t, path)
					executable := path
					if r.Bundle != nil {
						executable = r.Bundle.Executable
					}
					if damage == "info" || damage == "resources" {
						base := filepath.Join(path, "Contents")
						name := "Info.plist"
						if format == "framework" {
							base = filepath.Join(path, "Versions/A")
							name = "Resources/Info.plist"
						}
						if damage == "resources" {
							name = "_CodeSignature/CodeResources"
						}
						file := filepath.Join(base, name)
						var value map[string]any
						if _, err := plist.Unmarshal(nativeRead(t, file), &value); err != nil {
							t.Fatal(err)
						}
						changed, err := plist.Marshal(value, plist.XMLFormat)
						if err != nil {
							t.Fatal(err)
						}
						// Valid syntax and identical values, but different sealed bytes.
						if err := os.WriteFile(file, append(changed, '\n'), 0644); err != nil {
							t.Fatal(err)
						}
					} else {
						for _, a := range r.Architectures {
							if damage == "page" {
								at := a.Offset + 4096
								if format == "dmg" {
									at = 0
								}
								data[at] ^= 1
								continue
							}
							slot := codesign.SlotRequirements
							if strings.HasPrefix(damage, "cms-") {
								slot = codesign.SlotCMS
							}
							blob := signatureBlob(a.Signature, slot)
							base := int(a.Offset + a.SignatureOffset)
							at := base + bytes.Index(data[base:], blob)
							index := len(blob) - 1
							if damage == "cms-signature" {
								index = len(blob) - 64
							}
							data[at+index] ^= 1
						}
						if err := os.WriteFile(executable, data, 0755); err != nil {
							t.Fatal(err)
						}
					}
				}
				before := layoutArchive(t, dir)
				operand, err := filepath.Rel(dir, path)
				if err != nil {
					t.Fatal(err)
				}
				selections := []string{"default"}
				if format == "arm64" || format == "x86_64" || format == "universal" {
					selections = append(selections, "all", "arm64", "x86_64")
				}
				for _, selection := range selections {
					for _, verbose := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/verbose-%t", selection, verbose), func(t *testing.T) {
							args := []string{"--verify"}
							if selection == "all" {
								args = append(args, "--all-architectures")
							} else if selection != "default" {
								args = append(args, "-a", selection)
							}
							if verbose {
								args = append(args, "--verbose=1")
							}
							out, stderr, status := run(t, binaryPath, append(append(append([]string{}, args...), trust...), operand)...)
							if status != 1 || out != "" {
								t.Fatal("damaged input result", status, out, stderr)
							}
							nativeOut, nativeErr := "", ""
							if runtime.GOOS == "darwin" {
								var nativeStatus int
								nativeOut, nativeErr, nativeStatus = run(t, apple(t), append(args, operand)...)
								if nativeStatus != status {
									t.Fatal("native exit", nativeStatus, status, nativeErr)
								}
								nativeEqual(t, "verification stdout", []byte(out), []byte(nativeOut))
								if stderr != nativeErr {
									t.Logf("portable stderr=%q; native stderr=%q", stderr, nativeErr)
								}
								nativeEqual(t, "verification stderr", []byte(stderr), []byte(nativeErr))
							}
							nativeEqual(t, "damaged input preservation", layoutArchive(t, dir), before)
							attest(t, map[string]any{"format": format, "damage": damage, "selection": selection, "verbose": verbose, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nativeOut, "native_stderr": nativeErr, "input_sha256": hash(before), "diagnostics_sha256": hash([]byte(out + "\x00" + stderr)), "input_preserved": true, "exact_diagnostics": true, "native_compared": runtime.GOOS == "darwin"})
						})
					}
				}
			})
		}
	}
}

func TestVerificationDiagnosticContext(t *testing.T) {
	for _, state := range []string{"unsigned", "page", "sealed-false"} {
		t.Run(state, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			parent := filepath.Join(dir, "Parent.app")
			child := filepath.Join(parent, "Contents/PlugIns/Child.app")
			grandchild := filepath.Join(child, "Contents/Helpers/tool")
			bundleFixture(t, parent, "arm64")
			bundleFixture(t, child, "arm64")
			bundleWrite(t, child, "Contents/Helpers/tool", nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-universal")))
			source := "always"
			if state == "sealed-false" {
				source = "never"
			}
			req, err := codesign.CompileRequirements("designated => " + source)
			if err != nil {
				t.Fatal(err)
			}
			if err := codesign.Sign(context.Background(), grandchild, codesign.SignOptions{Identifier: "org.example.grandchild", Requirements: req}); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{child, parent} {
				if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Identifier: "org.example.parent"}); err != nil {
					t.Fatal(err)
				}
			}
			switch state {
			case "unsigned":
				if err := codesign.RemoveSignature(context.Background(), grandchild); err != nil {
					t.Fatal(err)
				}
			case "page":
				verificationMutation(t, grandchild, "", "page", false)
			}
			before := layoutArchive(t, dir)
			for _, absolute := range []bool{false, true} {
				for _, verbose := range []bool{false, true} {
					for _, jsonOutput := range []bool{false, true} {
						t.Run(fmt.Sprintf("absolute-%t/verbose-%t/json-%t", absolute, verbose, jsonOutput), func(t *testing.T) {
							operand := "Parent.app"
							if absolute {
								operand = parent
							}
							args := []string{"--verify", "--deep"}
							if verbose {
								args = append(args, "--verbose=1")
							}
							if jsonOutput {
								args = append(args, "--json")
							}
							out, stderr, status := run(t, binaryPath, append(args, operand)...)
							if status != 1 {
								t.Fatal(status, out, stderr)
							}
							subcomponent := grandchild
							if state == "sealed-false" {
								subcomponent = child
							}
							if !strings.Contains(stderr, "In subcomponent: "+subcomponent+"\n") {
								t.Fatal("failing path missing", stderr)
							}
							if jsonOutput {
								var report codesign.Report
								if err := json.Unmarshal([]byte(out), &report); err != nil || report.Valid {
									t.Fatal("invalid JSON failure", err, out)
								}
								if state == "sealed-false" && verbose && !strings.Contains(stderr, "file modified: "+grandchild+"\n") {
									t.Fatal("JSON detail missing", stderr)
								}
							} else if runtime.GOOS == "darwin" {
								nativeOut, nativeErr, nativeStatus := run(t, apple(t), append(args, operand)...)
								if nativeStatus != status {
									t.Fatal(nativeStatus, status, nativeErr)
								}
								if out != nativeOut || stderr != nativeErr {
									t.Fatalf("Go=(%q,%q); Apple=(%q,%q)", out, stderr, nativeOut, nativeErr)
								}
							}
							nativeEqual(t, "nested inputs preserved", layoutArchive(t, dir), before)
							attest(t, map[string]any{"state": state, "absolute": absolute, "verbose": verbose, "json": jsonOutput, "stdout": out, "stderr": stderr, "exit": status, "input_sha256": hash(before), "input_preserved": true, "exact_diagnostics": !jsonOutput, "native_compared": !jsonOutput && runtime.GOOS == "darwin"})
						})
					}
				}
			}
		})
	}
}
