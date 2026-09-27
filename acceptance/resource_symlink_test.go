package acceptance

import (
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

var verificationLinkStates = []string{"existing", "dangling", "self-cycle", "pair-cycle", "chain", "dangling-chain", "directory", "directory-chain", "parent-inside", "relative-escape", "chain-escape", "absolute-system", "absolute-missing", "absolute-external", "repeated-separators", "dot-target", "excluded-target"}

// Construct a signed text seal independently of path signing's containment policy.
// Native verification checks this byte-API fixture; native-signing imports below
// separately test seals emitted by Apple. Neither production policy is bypassed.
func verificationLinkFixture(t *testing.T, dir, format, algorithm, state string) (string, string, codesign.VerifyOptions, []string) {
	t.Helper()
	bundle, base, verify, trust := resourceFixture(t, dir, format, algorithm, "added")
	report, err := codesign.Inspect(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	resourceDir := filepath.Join(base, "Resources")
	bundleWrite(t, dir, "external", []byte("outside resource base"))
	bundleWrite(t, base, "Resources/.DS_Store", []byte("excluded"))
	external, err := filepath.Rel(resourceDir, filepath.Join(dir, "external"))
	if err != nil {
		t.Fatal(err)
	}
	target, second := "target", ""
	var extraLinks []string
	switch state {
	case "dangling":
		target = "absent"
	case "self-cycle":
		target = "link"
	case "pair-cycle":
		target, second = "second", "link"
	case "chain":
		target, second = "second", "target"
	case "dangling-chain":
		target, second = "second", "absent"
	case "directory":
		target = "fr.lproj"
	case "directory-chain":
		target, second = "second/a", "fr.lproj"
	case "parent-inside":
		target = "../Resources/target"
	case "relative-escape":
		target = filepath.ToSlash(external)
	case "chain-escape":
		target, second = "second", filepath.ToSlash(external)
	case "absolute-system":
		target = "/System/Library/CoreServices/SystemVersion.plist"
	case "absolute-missing":
		target = "/Library/codesign-test-absent"
	case "absolute-external":
		target = "/private/tmp"
	case "repeated-separators":
		target = "fr.lproj//a"
	case "dot-target":
		target = "."
	case "excluded-target":
		target = ".DS_Store"
	case "resource-root":
		target = ".."
	case "executable-target":
		var err error
		target, err = filepath.Rel(resourceDir, report.Bundle.Executable)
		if err != nil {
			t.Fatal(err)
		}
		target = filepath.ToSlash(target)
	case "signature-target":
		target = "../_CodeSignature/CodeResources"
	case "ancestor-target":
		var err error
		target, err = filepath.Rel(resourceDir, filepath.Join(dir, "../Resources/value"))
		if err != nil {
			t.Fatal(err)
		}
		target = filepath.ToSlash(target)
	case "physical-parent":
		target, second = "second/../target", "fr.lproj"
	case "file-slash":
		target = "target/"
	case "chain-33", "chain-34":
		count := 33
		if state == "chain-34" {
			count++
		}
		target = "hop-0"
		for i := range count {
			name, next := fmt.Sprintf("hop-%d", i), fmt.Sprintf("hop-%d", i+1)
			if i == count-1 {
				next = "target"
			}
			layoutLink(t, base, "Resources/"+name, next)
			extraLinks = append(extraLinks, name)
		}
	}
	if err := os.Remove(filepath.Join(resourceDir, "link")); err != nil {
		t.Fatal(err)
	}
	layoutLink(t, base, "Resources/link", target)
	if second != "" {
		layoutLink(t, base, "Resources/second", second)
	}
	envelope := filepath.Join(base, "_CodeSignature/CodeResources")
	var resources map[string]any
	if _, err := plist.Unmarshal(nativeRead(t, envelope), &resources); err != nil {
		t.Fatal(err)
	}
	for _, name := range append([]string{"link", "second"}, extraLinks...) {
		if name == "second" && second == "" {
			continue
		}
		text, err := os.Readlink(filepath.Join(resourceDir, name))
		if err != nil {
			t.Fatal(err)
		}
		// Windows stores target separators differently. Preserve actual link text
		// under the same documented separator conversion as resource envelopes.
		resources["files2"].(map[string]any)["Resources/"+name] = map[string]any{"symlink": filepath.ToSlash(text)}
	}
	encoded, err := plist.Marshal(resources, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	info := filepath.Join(base, "Info.plist")
	if format == "framework" {
		info = filepath.Join(resourceDir, "Info.plist")
	}
	id, _, _ := verificationIdentity(t, algorithm)
	executable := report.Bundle.Executable
	signed, err := codesign.SignBytes(context.Background(), nativeRead(t, executable), codesign.SignOptions{Force: true, Identifier: "org.example.resource", Identity: id, InfoPlist: nativeRead(t, info), Resources: encoded, SigningTime: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, signed, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envelope, encoded, 0644); err != nil {
		t.Fatal(err)
	}
	return bundle, base, verify, trust
}

func TestResourceSymlinkVerification(t *testing.T) {
	for _, format := range []string{"app", "framework"} {
		for _, algorithm := range []string{"adhoc", "rsa"} {
			for _, state := range verificationLinkStates {
				t.Run(format+"/"+algorithm+"/"+state, func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					bundle, base, verify, trust := verificationLinkFixture(t, dir, format, algorithm, state)
					for _, changed := range []bool{false, true} {
						if changed {
							if err := os.Remove(filepath.Join(base, "Resources/link")); err != nil {
								t.Fatal(err)
							}
							layoutLink(t, base, "Resources/link", "changed-and-absent")
						}
						before := layoutArchive(t, dir)
						for _, verbose := range []bool{false, true} {
							t.Run(fmt.Sprintf("changed-%t/verbose-%t", changed, verbose), func(t *testing.T) {
								args := []string{"--verify"}
								if verbose {
									args = append(args, "--verbose=1")
								}
								operand := filepath.Base(bundle)
								out, stderr, status := run(t, binaryPath, append(append(append([]string{}, args...), trust...), operand)...)
								want := 0
								if changed {
									want = 1
								}
								if status != want {
									t.Fatal(status, want, stderr)
								}
								report, err := codesign.Verify(context.Background(), bundle, verify)
								if report == nil || report.Valid != (want == 0) || (err == nil) != (want == 0) {
									t.Fatal(report, err)
								}
								nout, nerr := "", ""
								if runtime.GOOS == "darwin" {
									var nstatus int
									nout, nerr, nstatus = run(t, apple(t), append(args, operand)...)
									if nstatus != status || nout != out || nerr != stderr {
										t.Fatal("native link verification", nstatus, status, nout, out, nerr, stderr)
									}
								}
								nativeEqual(t, "link tree preservation", layoutArchive(t, dir), before)
								r := map[string]any{"format": format, "algorithm": algorithm, "state": state, "changed": changed, "verbose": verbose, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nout, "native_stderr": nerr, "input_preserved": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": true}
								// Absolute target spelling is host dependent on Windows; record it
								// without treating its input bytes as a cross-host comparison.
								if strings.HasPrefix(state, "absolute-") {
									r["host_input_sha256"] = hash(before)
								} else {
									r["input_sha256"] = hash(before)
								}
								r["normalized_diagnostics_sha256"] = hash([]byte(strings.ReplaceAll(strings.ReplaceAll(out+"\x00"+stderr, dir, "ROOT"), "\\", "/")))
								r["fixture_root"] = dir
								attest(t, r)
							})
						}
					}
				})
			}
		}
	}
}

func TestResourceSymlinkNested(t *testing.T) {
	for _, format := range []string{"app", "framework"} {
		for _, state := range []string{"dangling", "pair-cycle", "relative-escape"} {
			for _, changed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/changed-%t", format, state, changed), func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					parent := filepath.Join(dir, "Outer.app")
					bundleFixture(t, parent, "arm64")
					container := filepath.Join(parent, "Contents/Frameworks")
					if err := os.MkdirAll(container, 0755); err != nil {
						t.Fatal(err)
					}
					child, base, _, _ := verificationLinkFixture(t, container, format, "adhoc", state)
					if err := os.Remove(filepath.Join(container, "external")); err != nil {
						t.Fatal(err)
					}
					// Temporarily restore valid target text only while constructing the outer
					// seal; the child's executable (and parent-sealed requirement) stay fixed.
					link := filepath.Join(base, "Resources/link")
					target, err := os.Readlink(link)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(link); err != nil {
						t.Fatal(err)
					}
					layoutLink(t, base, "Resources/link", "target")
					second := filepath.Join(base, "Resources/second")
					secondTarget, secondErr := os.Readlink(second)
					if secondErr == nil {
						if err := os.Remove(second); err != nil {
							t.Fatal(err)
						}
						layoutLink(t, base, "Resources/second", "target")
					}
					if err := codesign.Sign(context.Background(), parent, codesign.SignOptions{}); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(link); err != nil {
						t.Fatal(err)
					}
					if changed {
						target = "changed"
					}
					layoutLink(t, base, "Resources/link", target)
					if secondErr == nil {
						if err := os.Remove(second); err != nil {
							t.Fatal(err)
						}
						layoutLink(t, base, "Resources/second", secondTarget)
					}
					before := layoutArchive(t, dir)
					for _, deep := range []bool{false, true} {
						for _, jsonOutput := range []bool{false, true} {
							t.Run(fmt.Sprintf("deep-%t/json-%t", deep, jsonOutput), func(t *testing.T) {
								args := []string{"--verify", "--verbose=1"}
								if deep {
									args = append(args, "--deep")
								}
								nativeArgs := append(append([]string{}, args...), filepath.Base(parent))
								if jsonOutput {
									args = append(args, "--json")
								}
								out, stderr, status := run(t, binaryPath, append(args, filepath.Base(parent))...)
								want := 0
								if deep && changed {
									want = 1
								}
								if status != want {
									t.Fatal(status, want, stderr, child)
								}
								nout, nerr := "", ""
								if !jsonOutput && runtime.GOOS == "darwin" {
									var nstatus int
									nout, nerr, nstatus = run(t, apple(t), nativeArgs...)
									if status != nstatus || out != nout || stderr != nerr {
										t.Fatal("nested links", status, nstatus, out, nout, stderr, nerr)
									}
								}
								if jsonOutput {
									var r codesign.Report
									if err := json.Unmarshal([]byte(out), &r); err != nil || r.Valid != (want == 0) {
										t.Fatal(r, err, out)
									}
								}
								nativeEqual(t, "nested link preservation", layoutArchive(t, dir), before)
								attest(t, map[string]any{"format": format, "state": state, "changed": changed, "deep": deep, "json": jsonOutput, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nout, "native_stderr": nerr, "input_sha256": hash(before), "input_preserved": true, "native_compared": !jsonOutput && runtime.GOOS == "darwin", "exact_diagnostics": !jsonOutput})
							})
						}
					}
				})
			}
		}
	}
}

func TestResourceSymlinkWriteGuards(t *testing.T) {
	for _, format := range []string{"app", "framework"} {
		for _, state := range []string{"dangling", "self-cycle", "pair-cycle", "dangling-chain", "relative-escape", "chain-escape", "absolute-system", "absolute-missing"} {
			t.Run(format+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				bundle, _, _, _ := verificationLinkFixture(t, dir, format, "adhoc", state)
				before := layoutArchive(t, dir)
				for _, dry := range []bool{false, true} {
					t.Run(fmt.Sprintf("dry-%t", dry), func(t *testing.T) {
						err := codesign.Sign(context.Background(), bundle, codesign.SignOptions{Force: true, DryRun: dry})
						if err == nil {
							t.Fatal("relaxed signing link guard")
						}
						nativeEqual(t, "rejected signing preserves tree", layoutArchive(t, dir), before)
						r := map[string]any{"format": format, "state": state, "dryrun": dry, "rejected": true, "input_preserved": true, "native_compared": false}
						if strings.HasPrefix(state, "absolute-") {
							r["host_input_sha256"] = hash(before)
						} else {
							r["input_sha256"] = hash(before)
						}
						attest(t, r)
					})
				}
			})
		}
	}
}

func TestResourceSymlinkNativeSigning(t *testing.T) {
	reference := apple(t)
	for _, format := range []string{"app", "framework"} {
		for _, state := range verificationLinkStates {
			t.Run(format+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				bundle, _, _, _ := verificationLinkFixture(t, dir, format, "adhoc", state)
				operand := filepath.Base(bundle)
				mustRun(t, reference, "-fs", "-", "--timestamp=none", operand)
				before := layoutArchive(t, dir)
				for _, verbose := range []bool{false, true} {
					t.Run(fmt.Sprintf("verbose-%t", verbose), func(t *testing.T) {
						args := []string{"--verify"}
						if verbose {
							args = append(args, "--verbose=1")
						}
						args = append(args, operand)
						out, stderr, status := run(t, binaryPath, args...)
						nout, nerr, nstatus := run(t, reference, args...)
						if status != 0 || nstatus != status || out != nout || stderr != nerr {
							t.Fatal("native-produced seal", status, nstatus, out, nout, stderr, nerr)
						}
						var strict []map[string]any
						if verbose {
							for _, selector := range []string{"--strict", "--strict=symlinks", "--strict=all"} {
								// Apple's asynchronous sideband scan can destroy resource rules
								// while validation workers still use them (see docs/strict-verification.md).
								// Only the unsupported plain/all observations use the SDK's
								// kSecCSSingleThreaded flag; implemented comparisons stay unchanged.
								serial := selector != "--strict=symlinks" && os.Getenv("MACOSCODESIGN_REPRODUCE_NATIVE_STRICT_CRASH") != "1"
								args := []string{"--verify", "--verbose=1", selector}
								if serial {
									args = append(args, "--strict=4096")
								}
								args = append(args, operand)
								nout, nerr, nstatus := run(t, reference, args...)
								want := 0
								switch state {
								case "dangling", "self-cycle", "pair-cycle", "dangling-chain", "relative-escape", "chain-escape", "absolute-missing", "absolute-external", "excluded-target":
									want = 1
								}
								if nstatus != want {
									// Preserve the exact public fixture before TempDir cleanup.
									// A reference-process signal stays a hard failure.
									failure := filepath.Join(root, "artifacts", "native-failures", fmt.Sprintf("%s-%s-%d", format, state, time.Now().UnixNano()))
									if err := os.MkdirAll(failure, 0755); err != nil {
										t.Fatal(err)
									}
									if err := os.WriteFile(filepath.Join(failure, "input.tar"), before, 0644); err != nil {
										t.Fatal(err)
									}
									data, err := json.MarshalIndent(map[string]any{"test": t.Name(), "selector": selector, "native_args": args, "native_single_threaded": serial, "native_exit": nstatus, "stdout": nout, "stderr": nerr, "input_sha256": hash(before)}, "", "  ")
									if err != nil {
										t.Fatal(err)
									}
									if err := os.WriteFile(filepath.Join(failure, "failure.json"), data, 0644); err != nil {
										t.Fatal(err)
									}
									t.Fatal("native strict policy", selector, nstatus, want, nerr)
								}
								gout, gerr, gstatus := run(t, binaryPath, "--verify", selector, operand)
								implemented := selector == "--strict=symlinks"
								if implemented {
									// This invocation is quiet; the native observation above is verbose.
									if gstatus != nstatus || gout != "" || nstatus == 0 && gerr != "" || nstatus != 0 && gerr != nerr {
										t.Fatal("implemented strict symlink result", gstatus, nstatus, gout, gerr, nerr)
									}
								} else if gstatus != 2 || !strings.Contains(gerr, "unsupported operation: --strict") {
									t.Fatal("strict must remain explicitly unsupported", gstatus, gerr)
								}
								strict = append(strict, map[string]any{"selector": selector, "native_args": args, "native_single_threaded": serial, "native_exit": nstatus, "native_stdout": nout, "native_stderr": nerr, "portable_exit": gstatus, "portable_stdout": gout, "portable_stderr": gerr, "implemented": implemented})
							}
						}
						nativeEqual(t, "native-produced link input preservation", layoutArchive(t, dir), before)
						attest(t, map[string]any{"format": format, "state": state, "verbose": verbose, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nout, "native_stderr": nerr, "native_signed": true, "native_compared": true, "exact_diagnostics": true, "input_preserved": true, "host_input_sha256": hash(before), "strict_profiles": strict})
					})
				}
			})
		}
	}
}
