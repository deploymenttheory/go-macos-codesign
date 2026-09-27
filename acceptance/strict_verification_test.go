package acceptance

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestStrictSymlinkVerification(t *testing.T) {
	for _, format := range []string{"app", "framework"} {
		for _, algorithm := range []string{"adhoc", "rsa"} {
			for _, state := range append(append([]string{}, verificationLinkStates...), "resource-root", "executable-target", "signature-target", "physical-parent", "file-slash", "chain-33", "chain-34") {
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
						want := 0
						switch state {
						case "dangling", "self-cycle", "pair-cycle", "dangling-chain", "relative-escape", "chain-escape", "absolute-missing", "absolute-external", "excluded-target", "signature-target", "chain-34":
							want = 1
						case "chain-33":
							if format == "framework" {
								want = 1
							}
						case "absolute-system":
							if runtime.GOOS != "darwin" {
								want = 1
							}
						}
						if changed {
							want = 1
						}
						verify.StrictSymlinks = true
						report, err := codesign.Verify(context.Background(), bundle, verify)
						if report == nil || report.Valid != (want == 0) || (err == nil) != (want == 0) {
							t.Fatal(report, err, want)
						}
						for _, verbose := range []bool{false, true} {
							t.Run(fmt.Sprintf("changed-%t/verbose-%t", changed, verbose), func(t *testing.T) {
								multi := state == "pair-cycle" || state == "dangling-chain" || state == "chain-escape" || state == "chain-34" && format == "framework"
								mixed := multi && changed
								exact := !mixed && (!multi || !verbose)
								args := []string{"--verify", "--strict=symlinks"}
								if verbose {
									args = append(args, "--verbose=1")
								}
								operand := filepath.Base(bundle)
								out, stderr, status := run(t, binaryPath, append(append(append([]string{}, args...), trust...), operand)...)
								if status != want {
									t.Fatal(status, want, out, stderr)
								}
								nout, nerr := "", ""
								var observations []map[string]any
								if runtime.GOOS == "darwin" {
									repeats := 1
									if !exact {
										repeats = 3
									}
									for range repeats {
										var nstatus int
										nout, nerr, nstatus = run(t, apple(t), append(args, operand)...)
										validSummary := nerr == stderr
										if mixed {
											validSummary = nerr == operand+": a sealed resource is missing or invalid\n" || nerr == operand+": invalid destination for symbolic link in bundle\n"
										}
										if nstatus != status || orderedResourceDetails(t, out) != orderedResourceDetails(t, nout) || !validSummary || exact && out != nout {
											t.Fatal("strict native comparison", status, nstatus, out, nout, stderr, nerr)
										}
										observations = append(observations, map[string]any{"exit": nstatus, "stdout": nout, "stderr": nerr})
									}
								}
								nativeEqual(t, "strict links preserve input", layoutArchive(t, dir), before)
								r := map[string]any{"format": format, "algorithm": algorithm, "state": state, "changed": changed, "verbose": verbose, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nout, "native_stderr": nerr, "native_observations": observations, "input_preserved": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": exact, "mixed_primary_status": mixed, "ordering_profile": multi && verbose && !mixed}
								if strings.HasPrefix(state, "absolute-") {
									r["host_input_sha256"] = hash(before)
								} else {
									r["input_sha256"] = hash(before)
								}
								r["fixture_root"] = dir
								if state != "absolute-system" {
									r["normalized_diagnostics_sha256"] = hash([]byte(strings.ReplaceAll(strings.ReplaceAll(out+"\x00"+stderr, dir, "ROOT"), "\\", "/")))
								}
								attest(t, r)
							})
						}
					}
				})
			}
		}
	}
}

func TestStrictLayoutVerification(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		states := []string{"clean", "trailing", "corrupt"}
		if arch == "universal" {
			states = append(states, "padding", "excess-padding", "reverse-order")
		}
		for _, state := range states {
			t.Run(arch+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				data := nativeRead(t, filepath.Join(root, "testdata/macho/adhoc-"+arch))
				offset := 0
				if arch == "universal" {
					offset = int(binary.BigEndian.Uint32(data[16:]))
				}
				switch state {
				case "trailing":
					data = append(data, 0, 0, 0, 0)
				case "corrupt":
					data[offset+4096] ^= 1
				case "padding":
					data[100] = 1
				case "excess-padding":
					off := int(binary.BigEndian.Uint32(data[36:]))
					gap := 1 << binary.BigEndian.Uint32(data[44:])
					data = append(data[:off:off], append(make([]byte, gap), data[off:]...)...)
					binary.BigEndian.PutUint32(data[36:], uint32(off+gap))
				case "reverse-order":
					first := append([]byte{}, data[8:28]...)
					copy(data[8:28], data[28:48])
					copy(data[28:48], first)
				}
				bundleWrite(t, dir, "fixture", data)
				selections := []string{""}
				if arch == "universal" {
					selections = append(selections, "arm64", "x86_64")
				}
				for _, selection := range selections {
					for _, policy := range []string{"default", "--strict=0", "--strict=symlinks", "--strict=none", "--no-strict"} {
						t.Run(selection+"/"+policy, func(t *testing.T) {
							disabled := policy == "--strict=none" || policy == "--no-strict"
							want := 0
							if state == "corrupt" || !disabled && state != "clean" && state != "reverse-order" {
								want = 1
							}
							if state == "padding" {
								want = 1
							}
							if arch == "universal" && selection != "" && state != "corrupt" {
								want = 0
							}
							// The corrupt universal page belongs only to the first selected architecture.
							if state == "corrupt" && selection != "" {
								r, e := codesign.InspectBytes(data)
								if e != nil {
									t.Fatal(e)
								}
								if selection != r.Architectures[0].Name {
									want = 0
								}
							}
							args := []string{"--verify", "--verbose=1"}
							if policy != "default" {
								args = append(args, policy)
							}
							if selection != "" {
								args = append(args, "-a", selection)
							}
							args = append(args, "fixture")
							out, stderr, status := run(t, binaryPath, args...)
							if status != want {
								t.Fatal(status, want, out, stderr)
							}
							nout, nerr := "", ""
							if runtime.GOOS == "darwin" {
								var nstatus int
								nout, nerr, nstatus = run(t, apple(t), args...)
								if nstatus != status || out != nout || stderr != nerr {
									t.Fatal("layout native comparison", status, nstatus, out, nout, stderr, nerr)
								}
							}
							nativeEqual(t, "strict layout input preservation", nativeRead(t, "fixture"), data)
							attest(t, map[string]any{"architecture": arch, "selection": selection, "state": state, "policy": policy, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nout, "native_stderr": nerr, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": true, "input_preserved": true, "input_sha256": hash(data), "diagnostics_sha256": hash([]byte(out + "\x00" + stderr)), "fixture_root": dir})
						})
					}
				}
			})
		}
	}
}

func TestStrictSelectorVerification(t *testing.T) {
	dir := extractionDirectory(t)
	t.Chdir(dir)
	bundle, _, _, _ := verificationLinkFixture(t, dir, "app", "adhoc", "dangling")
	operand := filepath.Base(bundle)
	before := layoutArchive(t, dir)
	profiles := [][]string{{"--strict=s"}, {"--strict=symlink"}, {"--strict=128"}, {"--strict=0x80"}, {"--strict=0X80"}, {"--strict=0200"}, {"--strict=128x"}, {"--strict=128 "}, {"--strict=4294967424"}, {"--strict=0"}, {"--strict=00"}, {"--strict=08"}, {"--strict=0x"}, {"--strict=n"}, {"--no-strict"}, {"--strict=0", "--strict=symlinks"}, {"--strict=symlinks", "--strict=0"}, {"--strict=none", "--strict=symlinks"}, {"--strict=symlinks", "--strict=none"}, {"--strict=symlinks,sideband"}, {"--strict=none,symlinks"}, {"--strict=+128"}, {"--strict=-1"}, {"--strict=SYMLINKS"}, {"--no-strict", "--strict=bad"}}
	for i, flags := range profiles {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			want := 1
			if i >= 9 && i <= 14 || i == 17 || i == 18 {
				want = 0
			}
			args := append(append([]string{"--verify", "--verbose=1"}, flags...), operand)
			out, stderr, status := run(t, binaryPath, args...)
			if status != want {
				t.Fatal(flags, status, want, out, stderr)
			}
			nout, nerr := "", ""
			if runtime.GOOS == "darwin" {
				var nstatus int
				nout, nerr, nstatus = run(t, apple(t), args...)
				if nstatus != status || out != nout || stderr != nerr {
					t.Fatal(flags, status, nstatus, out, nout, stderr, nerr)
				}
			}
			nativeEqual(t, "selector input preservation", layoutArchive(t, dir), before)
			attest(t, map[string]any{"selectors": flags, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nout, "native_stderr": nerr, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": true, "input_preserved": true, "input_sha256": hash(before), "diagnostics_sha256": hash([]byte(strings.ReplaceAll(strings.ReplaceAll(out+"\x00"+stderr, dir, "ROOT"), "\\", "/"))), "fixture_root": dir})
		})
	}
}

func TestStrictNestedVerification(t *testing.T) {
	for _, format := range []string{"app", "framework"} {
		for _, state := range []string{"existing", "ancestor-target", "signature-target", "dangling"} {
			t.Run(format+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				parent := filepath.Join(dir, "Outer.app")
				bundleFixture(t, parent, "arm64")
				bundleWrite(t, parent, "Contents/Resources/value", []byte("enclosing scope"))
				container := filepath.Join(parent, "Contents/Frameworks")
				if e := os.MkdirAll(container, 0755); e != nil {
					t.Fatal(e)
				}
				child, base, _, _ := verificationLinkFixture(t, container, format, "adhoc", state)
				if e := os.Remove(filepath.Join(container, "external")); e != nil {
					t.Fatal(e)
				}
				link := filepath.Join(base, "Resources/link")
				target, e := os.Readlink(link)
				if e != nil {
					t.Fatal(e)
				}
				if e := os.Remove(link); e != nil {
					t.Fatal(e)
				}
				layoutLink(t, base, "Resources/link", "target")
				if e := codesign.Sign(context.Background(), parent, codesign.SignOptions{}); e != nil {
					t.Fatal(e)
				}
				if e := os.Remove(link); e != nil {
					t.Fatal(e)
				}
				layoutLink(t, base, "Resources/link", target)
				before := layoutArchive(t, dir)
				for _, deep := range []bool{false, true} {
					for _, jsonOutput := range []bool{false, true} {
						t.Run(fmt.Sprintf("deep-%t/json-%t", deep, jsonOutput), func(t *testing.T) {
							want := 0
							if deep && (state == "signature-target" || state == "dangling") {
								want = 1
							}
							args := []string{"--verify", "--strict=symlinks", "--verbose=1"}
							if deep {
								args = append(args, "--deep")
							}
							args = append(args, filepath.Base(parent))
							nativeArgs := append([]string{}, args...)
							if jsonOutput {
								args = append([]string{"--json"}, args...)
							}
							out, stderr, status := run(t, binaryPath, args...)
							if status != want {
								t.Fatal(status, want, out, stderr)
							}
							nout, nerr := "", ""
							if !jsonOutput && runtime.GOOS == "darwin" {
								var nstatus int
								nout, nerr, nstatus = run(t, apple(t), nativeArgs...)
								if status != nstatus || out != nout || stderr != nerr {
									t.Fatal(status, nstatus, out, nout, stderr, nerr)
								}
							}
							if jsonOutput {
								var r codesign.Report
								if e := json.Unmarshal([]byte(out), &r); e != nil || r.Valid != (want == 0) {
									t.Fatal(r, e, out)
								}
							}
							nativeEqual(t, "strict nested preservation", layoutArchive(t, dir), before)
							attest(t, map[string]any{"format": format, "state": state, "deep": deep, "json": jsonOutput, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nout, "native_stderr": nerr, "native_compared": !jsonOutput && runtime.GOOS == "darwin", "exact_diagnostics": !jsonOutput, "input_preserved": true, "input_sha256": hash(before), "fixture_root": dir})
						})
					}
				}
				// The enclosing resource scope exists only while verifying the parent.
				if state == "ancestor-target" {
					if _, e := codesign.Verify(context.Background(), child, codesign.VerifyOptions{StrictSymlinks: true}); e == nil {
						t.Fatal("standalone child incorrectly inherited scope")
					}
				}
			})
		}
	}
}
