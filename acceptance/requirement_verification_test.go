package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func verificationIdentity(t *testing.T, algorithm string) (*codesign.Identity, codesign.VerifyOptions, []string) {
	t.Helper()
	if algorithm == "adhoc" {
		return nil, codesign.VerifyOptions{}, nil
	}
	id, err := codesign.LoadIdentityPEM(nativeRead(t, filepath.Join(root, "testdata/identities", algorithm+"-identity.pem")), nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, codesign.VerifyOptions{TrustedCertificates: id.Certificates}, []string{"--trust", filepath.Join(root, "testdata/identities", algorithm+"-cert.pem")}
}

func TestRequirementVerification(t *testing.T) {
	for _, algorithm := range []string{"adhoc", "rsa", "p256", "p384", "p521"} {
		for _, format := range []string{"arm64", "x86_64", "universal", "app", "framework", "dmg"} {
			for _, self := range []string{"always", "never", "mismatch"} {
				t.Run(algorithm+"/"+format+"/"+self, func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					path := defaultFixture(t, filepath.Join(dir, "fixture"), format)
					id, verify, trust := verificationIdentity(t, algorithm)
					expression := self
					if self == "mismatch" {
						expression = `identifier "wrong"`
					}
					requirements, err := codesign.CompileRequirements("host => never designated => " + expression)
					if err != nil {
						t.Fatal(err)
					}
					if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Identifier: "org.example.verify", Identity: id, Requirements: requirements, SigningTime: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}); err != nil {
						t.Fatal(err)
					}
					relative, err := filepath.Rel(dir, path)
					if err != nil {
						t.Fatal(err)
					}
					relative = filepath.ToSlash(relative)
					before := layoutArchive(t, filepath.Join(dir, "fixture"))
					components := hash(defaultComponents(t, path))
					for _, verbose := range []bool{false, true} {
						for _, explicit := range []string{"none", "always", "never"} {
							t.Run(fmt.Sprintf("verbose-%t/%s", verbose, explicit), func(t *testing.T) {
								args := []string{"--verify"}
								if verbose {
									args = append(args, "--verbose=1")
								}
								if explicit != "none" {
									args = append(args, "-R="+explicit)
								}
								wanted := 0
								if verbose && self != "always" || explicit == "never" {
									wanted = 3
								}
								out, stderr, status := run(t, binaryPath, append(append(append([]string{}, args...), trust...), relative)...)
								if status != wanted || out != "" {
									t.Fatal("portable result", status, wanted, out, stderr)
								}
								if runtime.GOOS == "darwin" {
									nativeOut, nativeErr, nativeStatus := run(t, apple(t), append(args, relative)...)
									if nativeStatus != status {
										t.Fatal("native status", nativeStatus, status, nativeErr, stderr)
									}
									nativeEqual(t, "verification stdout", []byte(out), []byte(nativeOut))
									nativeEqual(t, "verification stderr", []byte(stderr), []byte(nativeErr))
								}
								opts := verify
								opts.CheckDesignatedRequirement = verbose
								if explicit != "none" {
									opts.Requirement = explicit
								}
								report, err := codesign.Verify(context.Background(), path, opts)
								if (err == nil) != (wanted == 0) || report == nil || report.Valid != (wanted == 0) {
									t.Fatal("library result", report, err, wanted)
								}
								nativeEqual(t, "verification input preserved", layoutArchive(t, filepath.Join(dir, "fixture")), before)
								attest(t, map[string]any{"algorithm": algorithm, "format": format, "self": self, "verbose": verbose, "explicit": explicit, "exit": status, "stdout": out, "stderr": stderr, "components_sha256": components, "diagnostics_sha256": hash([]byte(out + "\x00" + stderr)), "input_preserved": true, "library_policy_matched": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": true})
							})
						}
					}
				})
			}
		}
	}
}

func TestRequirementVerificationNested(t *testing.T) {
	for _, algorithm := range []string{"adhoc", "rsa"} {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, kind := range []string{"file", "app", "framework"} {
				for _, state := range []string{"replaced-self", "sealed-false", "identifier-mismatch", "page", "requirements"} {
					t.Run(algorithm+"/"+arch+"/"+kind+"/"+state, func(t *testing.T) {
						dir := extractionDirectory(t)
						t.Chdir(dir)
						parent := filepath.Join(dir, "Parent.app")
						bundleFixture(t, parent, arch)
						var child string
						switch kind {
						case "file":
							child = filepath.Join(parent, "Contents/Helpers/tool")
							bundleWrite(t, parent, "Contents/Helpers/tool", nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+arch)))
						case "app":
							child = filepath.Join(parent, "Contents/PlugIns/Child.app")
							bundleFixture(t, child, arch)
						case "framework":
							child = layoutFixture(t, filepath.Join(parent, "Contents/Frameworks"), "versioned", arch, "binary")
							if err := codesign.Sign(context.Background(), filepath.Join(child, "Versions/A/helper"), codesign.SignOptions{Identifier: "org.example.helper"}); err != nil {
								t.Fatal(err)
							}
						}
						id, verify, trust := verificationIdentity(t, algorithm)
						source := "always"
						if state == "sealed-false" {
							source = "never"
						}
						if state == "identifier-mismatch" {
							source = `identifier "org.example.child"`
						}
						req, err := codesign.CompileRequirements("designated => " + source)
						if err != nil {
							t.Fatal(err)
						}
						opts := codesign.SignOptions{Identifier: "org.example.child", Identity: id, Requirements: req, SigningTime: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
						if err := codesign.Sign(context.Background(), child, opts); err != nil {
							t.Fatal(err)
						}
						if err := codesign.Sign(context.Background(), parent, codesign.SignOptions{Identifier: "org.example.parent", Identity: id, SigningTime: opts.SigningTime}); err != nil {
							t.Fatal(err)
						}
						switch state {
						case "replaced-self", "identifier-mismatch":
							source = "never"
							if state == "identifier-mismatch" {
								source = "always"
								opts.Identifier = "org.example.changed"
							}
							opts.Requirements, err = codesign.CompileRequirements("designated => " + source)
							if err != nil {
								t.Fatal(err)
							}
							opts.Force = true
							if err := codesign.Sign(context.Background(), child, opts); err != nil {
								t.Fatal(err)
							}
						case "page", "requirements":
							verificationMutation(t, child, "", state, false)
						}
						before := layoutArchive(t, parent)
						for _, deep := range []bool{false, true} {
							t.Run(fmt.Sprintf("deep-%t", deep), func(t *testing.T) {
								accepted := state == "replaced-self" || state == "page" && !deep
								args := []string{"--verify", "--verbose=1"}
								if deep {
									args = append(args, "--deep")
								}
								out, stderr, status := run(t, binaryPath, append(append(append([]string{}, args...), trust...), "Parent.app")...)
								want := 0
								if !accepted {
									want = 1
								}
								nativeErr, nativeStdout := "", ""
								if runtime.GOOS == "darwin" {
									nativeOut, e, nativeStatus := run(t, apple(t), append(args, "Parent.app")...)
									nativeErr, nativeStdout = e, nativeOut
									if nativeStatus != status {
										t.Fatal("native parent policy", nativeStatus, status, e, stderr)
									}
									if accepted {
										nativeEqual(t, "parent stdout", []byte(out), []byte(nativeOut))
										nativeEqual(t, "parent success diagnostics", []byte(stderr), []byte(e))
									}
								}
								if status != want {
									t.Fatal("portable parent policy", status, want, stderr)
								}
								opts := verify
								opts.Deep = deep
								r, err := codesign.Verify(context.Background(), parent, opts)
								if (err == nil) != accepted || r == nil || r.Valid != accepted {
									t.Fatal("library parent policy", err, accepted)
								}
								nativeEqual(t, "parent verification preserves tree", layoutArchive(t, parent), before)
								attest(t, map[string]any{"algorithm": algorithm, "architecture": arch, "child_kind": kind, "state": state, "deep": deep, "accepted": accepted, "exit": status, "stdout": out, "native_stdout": nativeStdout, "stderr": stderr, "native_stderr": nativeErr, "input_sha256": hash(before), "input_preserved": true, "parent_requirement_enforced": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": accepted})
							})
						}
					})
				}
			}
		}
	}
}

func verificationMutation(t *testing.T, path, architecture, kind string, rebind bool) {
	t.Helper()
	r, data := inspectDefaults(t, path)
	if r.Bundle != nil {
		path = r.Bundle.Executable
	}
	for _, a := range r.Architectures {
		if architecture != "" && architecture != a.Name {
			continue
		}
		if kind == "page" {
			data[a.Offset+4096] ^= 1
			continue
		}
		base := int(a.Offset + a.SignatureOffset)
		set := signatureBlob(a.Signature, codesign.SlotRequirements)
		at := base + bytes.Index(data[base:], set)
		switch kind {
		case "false":
			binary.BigEndian.PutUint32(data[at+len(set)-4:], 0)
		case "malformed":
			binary.BigEndian.PutUint32(data[at+16:], 1)
		case "requirements":
			data[at+len(set)-1] ^= 1
		}
		if rebind {
			d := a.Signature.Directories[0]
			cd := base + bytes.Index(data[base:], d.Raw)
			sum := sha256.Sum256(data[at : at+len(set)])
			copy(data[cd+int(d.HashOffset)-2*int(d.HashSize):], sum[:])
		}
	}
	if err := os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
}

func TestRequirementVerificationArchitectures(t *testing.T) {
	for _, changed := range []string{"arm64", "x86_64"} {
		for _, mutation := range []string{"false", "page"} {
			t.Run(changed+"/"+mutation, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				path := defaultFixture(t, dir, "universal")
				req, err := codesign.CompileRequirements("designated => always")
				if err != nil {
					t.Fatal(err)
				}
				if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Identifier: "org.example.verify", Requirements: req}); err != nil {
					t.Fatal(err)
				}
				verificationMutation(t, path, changed, mutation, mutation == "false")
				report, data := inspectDefaults(t, path)
				before := hash(data)
				for _, selection := range []string{"default", "all", "arm64", "x86_64"} {
					for _, check := range []string{"quiet", "verbose", "explicit-arm64", "explicit-x86_64"} {
						t.Run(selection+"/"+check, func(t *testing.T) {
							args := []string{"--verify"}
							if selection == "all" {
								args = append(args, "--all-architectures")
							} else if selection != "default" {
								args = append(args, "-a", selection)
							}
							if check == "verbose" {
								args = append(args, "--verbose=4")
							}
							if strings.HasPrefix(check, "explicit-") {
								a, err := report.SelectArchitecture(strings.TrimPrefix(check, "explicit-"))
								if err != nil {
									t.Fatal(err)
								}
								args = append(args, `-R=cdhash H"`+a.Signature.Directories[0].CDHash+`"`)
							}
							out, stderr, status := run(t, binaryPath, append(args, "input")...)
							expected := 0
							selected := selection
							if selected == "default" || selected == "all" {
								selected = "arm64"
							}
							if mutation == "page" && (selection == "default" || selection == "all" || selected == changed) {
								expected = 1
							} else if mutation == "false" && check == "verbose" && selected == changed || strings.HasPrefix(check, "explicit-") && (selection == "default" || selection == "all" || check != "explicit-"+selected) {
								expected = 3
							}
							if status != expected {
								t.Fatal("architecture result", status, expected, stderr)
							}
							nativeErr := ""
							if runtime.GOOS == "darwin" {
								nativeOut, e, nativeStatus := run(t, apple(t), append(args, "input")...)
								nativeErr = e
								if nativeStatus != status {
									t.Fatal("native architecture result", nativeStatus, status, e, stderr)
								}
								nativeEqual(t, "architecture stdout", []byte(out), []byte(nativeOut))
								if mutation != "page" {
									nativeEqual(t, "architecture diagnostics", []byte(stderr), []byte(e))
								}
							}
							if hash(nativeRead(t, path)) != before {
								t.Fatal("verification changed input")
							}
							attest(t, map[string]any{"changed": changed, "mutation": mutation, "selection": selection, "check": check, "exit": status, "stderr": stderr, "native_stderr": nativeErr, "input_sha256": before, "input_preserved": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": mutation != "page"})
						})
					}
				}
			})
		}
	}
}

func TestRequirementVerificationIntegrity(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, kind := range []string{"requirements", "malformed-bound", "cms"} {
			t.Run(arch+"/"+kind, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				path := defaultFixture(t, dir, arch)
				algorithm := "adhoc"
				if kind == "cms" {
					algorithm = "rsa"
				}
				id, verify, trust := verificationIdentity(t, algorithm)
				req, err := codesign.CompileRequirements("designated => never")
				if err != nil {
					t.Fatal(err)
				}
				if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Identifier: "org.example.verify", Identity: id, Requirements: req, SigningTime: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}); err != nil {
					t.Fatal(err)
				}
				if kind == "cms" {
					r, data := inspectDefaults(t, path)
					a := r.Architectures[0]
					cms := signatureBlob(a.Signature, codesign.SlotCMS)
					at := int(a.Offset+a.SignatureOffset) + bytes.Index(data[a.Offset+a.SignatureOffset:], cms)
					data[at+len(cms)-1] ^= 1
					if err := os.WriteFile(path, data, 0755); err != nil {
						t.Fatal(err)
					}
				} else {
					mutation := kind
					if kind == "malformed-bound" {
						mutation = "malformed"
					}
					verificationMutation(t, path, "", mutation, kind == "malformed-bound")
				}
				before := hash(nativeRead(t, path))
				for _, verbose := range []bool{false, true} {
					t.Run(fmt.Sprintf("verbose-%t", verbose), func(t *testing.T) {
						args := []string{"--verify"}
						if verbose {
							args = append(args, "--verbose=1")
						}
						out, stderr, status := run(t, binaryPath, append(append(append([]string{}, args...), trust...), "input")...)
						if status != 1 {
							t.Fatal("integrity accepted", status, out, stderr)
						}
						if _, err := codesign.Verify(context.Background(), path, verify); err == nil {
							t.Fatal("library integrity accepted")
						}
						nativeStatus := -1
						nativeOut, nativeErr := "", ""
						if runtime.GOOS == "darwin" {
							nativeOut, nativeErr, nativeStatus = run(t, apple(t), append(args, "input")...)
							want := 1
							if kind == "malformed-bound" && !verbose {
								want = 0
							}
							if nativeStatus != want {
								t.Fatal("native integrity result", nativeStatus, nativeErr)
							}
						}
						if hash(nativeRead(t, path)) != before {
							t.Fatal("verification mutated damaged input")
						}
						attest(t, map[string]any{"architecture": arch, "kind": kind, "verbose": verbose, "exit": status, "stdout": out, "stderr": stderr, "native_exit": nativeStatus, "native_stdout": nativeOut, "native_stderr": nativeErr, "input_sha256": before, "input_preserved": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": false, "bounded_structure_difference": kind == "malformed-bound"})
					})
				}
			})
		}
	}
}

func TestRequirementVerificationLifecycle(t *testing.T) {
	for _, order := range []string{"good,bad", "bad,good", "bad,unsigned", "unsigned,bad", "good,bad,unsigned", "unsigned,good,bad"} {
		for _, explicit := range []string{"none", "never"} {
			t.Run(order+"/"+explicit, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				for _, name := range []string{"good", "bad", "unsigned"} {
					copyFixture(t, "unsigned-arm64", name)
					if name == "unsigned" {
						continue
					}
					source := "always"
					if name == "bad" {
						source = "never"
					}
					req, err := codesign.CompileRequirements("designated => " + source)
					if err != nil {
						t.Fatal(err)
					}
					if err := codesign.Sign(context.Background(), name, codesign.SignOptions{Identifier: "org.example.verify", Requirements: req}); err != nil {
						t.Fatal(err)
					}
				}
				before := layoutArchive(t, dir)
				args := []string{"--verify", "--verbose=2", "--continue"}
				if explicit != "none" {
					args = append(args, "-R="+explicit)
				}
				args = append(args, strings.Split(order, ",")...)
				out, stderr, status := run(t, binaryPath, args...)
				wanted := 3
				if strings.HasPrefix(order, "unsigned") {
					wanted = 1
				}
				if status != wanted {
					t.Fatal(status, wanted, stderr)
				}
				exact := !strings.Contains(order, "unsigned")
				nativeOut, nativeErr := "", ""
				if runtime.GOOS == "darwin" {
					var nativeStatus int
					nativeOut, nativeErr, nativeStatus = run(t, apple(t), args...)
					if nativeStatus != status {
						t.Fatal(nativeStatus, status, nativeErr, stderr)
					}
					nativeEqual(t, "ordered stdout", []byte(out), []byte(nativeOut))
					if exact {
						nativeEqual(t, "ordered stderr", []byte(stderr), []byte(nativeErr))
					}
				}
				nativeEqual(t, "multiple inputs preserved", layoutArchive(t, dir), before)
				attest(t, map[string]any{"order": order, "explicit": explicit, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nativeOut, "native_stderr": nativeErr, "input_sha256": hash(before), "diagnostics_sha256": hash([]byte(out + "\x00" + stderr)), "input_preserved": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": exact})
			})
		}
	}
}

func TestRequirementVerificationJSON(t *testing.T) {
	for _, self := range []string{"always", "never"} {
		for _, verbose := range []bool{false, true} {
			for _, explicit := range []string{"none", "never"} {
				t.Run(fmt.Sprintf("%s/%t/%s", self, verbose, explicit), func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					copyFixture(t, "unsigned-arm64", "input")
					req, err := codesign.CompileRequirements("designated => " + self)
					if err != nil {
						t.Fatal(err)
					}
					if err := codesign.Sign(context.Background(), "input", codesign.SignOptions{Identifier: "org.example.verify", Requirements: req}); err != nil {
						t.Fatal(err)
					}
					before := hash(nativeRead(t, "input"))
					args := []string{"--verify", "--json"}
					if verbose {
						args = append(args, "--verbose=1")
					}
					if explicit != "none" {
						args = append(args, "-R="+explicit)
					}
					out, stderr, status := run(t, binaryPath, append(args, "input")...)
					wanted := 0
					if verbose && self == "never" || explicit == "never" {
						wanted = 3
					}
					var report codesign.Report
					if err := json.Unmarshal([]byte(out), &report); err != nil || status != wanted || report.Valid != (wanted == 0) {
						t.Fatal(status, wanted, err, out, stderr)
					}
					resolved, err := filepath.EvalSymlinks(dir)
					if err != nil || report.Path != filepath.Join(resolved, "input") {
						t.Fatal("JSON resolved input path", report.Path, resolved, err)
					}
					// Preserve the raw response, but exclude the independently checked
					// temporary directory from the portable JSON comparison hash.
					// Native diagnostics elsewhere in this matrix remain unmodified.
					report.Path = "input"
					portable, err := json.Marshal(report)
					if err != nil {
						t.Fatal(err)
					}
					if hash(nativeRead(t, "input")) != before {
						t.Fatal("JSON verification changed input")
					}
					attest(t, map[string]any{"self": self, "verbose": verbose, "explicit": explicit, "exit": status, "valid": report.Valid, "stdout": out, "stderr": stderr, "input_sha256": before, "normalized_output_sha256": hash(append(append(portable, 0), stderr...)), "resolved_input_path_checked": true, "input_preserved": true, "portable_json_extension": true})
				})
			}
		}
	}
}
