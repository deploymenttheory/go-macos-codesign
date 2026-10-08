package acceptance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func sidebandBundleFixture(t *testing.T, dir, format string) (string, map[string]string) {
	t.Helper()
	var b, base string
	if format == "recursive" {
		b = filepath.Join(dir, "Parent.app")
		recursiveFixture(t, b, "arm64", "xml")
		if err := codesign.Sign(context.Background(), b, codesign.SignOptions{Deep: true}); err != nil {
			t.Fatal(err)
		}
		base = filepath.Join(b, "Contents")
	} else {
		b, base, _, _ = resourceFixture(t, dir, format, "adhoc", "")
	}
	paths := map[string]string{"root": b, "main": filepath.Join(base, "MacOS/hello"), "resource": filepath.Join(base, "Resources/a"), "info": filepath.Join(base, "Info.plist"), "signature": filepath.Join(base, "_CodeSignature/CodeResources"), "directory": filepath.Join(base, "Resources"), "link": filepath.Join(base, "Resources/target"), "helper": filepath.Join(base, "Helpers/tool"), "version-root": base}
	if strings.Contains(format, "framework") {
		paths["main"] = filepath.Join(base, "Fixture")
		paths["info"] = filepath.Join(base, "Resources/Info.plist")
	}
	for i, child := range recursiveApps[1:] {
		prefix := "child-"
		if i == 1 {
			prefix = "grandchild-"
		}
		p := filepath.Join(b, child)
		paths[prefix+"root"] = p
		paths[prefix+"main"] = filepath.Join(p, "Contents/MacOS/hello")
		paths[prefix+"resource"] = filepath.Join(p, "Contents/Resources/message.txt")
	}
	return b, paths
}

// Resource workers append detail arrays in unspecified order. Compare the full
// multiset (including duplicates), without changing the diagnostic or paths.
func sortedSidebandDetails(s string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestBundleSidebandVerification(t *testing.T) {
	for _, format := range []string{"app", "app-universal", "framework", "flat-framework", "recursive"} {
		locations := []string{"root", "main", "resource", "info", "signature", "directory", "link", "helper"}
		if format == "recursive" {
			locations = []string{"child-root", "child-main", "child-resource", "grandchild-root", "grandchild-main"}
		}
		if format == "framework" {
			locations = append(locations, "version-root")
		}
		for _, location := range locations {
			states := []string{"clean", "finder", "fork", "both"}
			if location == "root" || location == "directory" || strings.HasSuffix(location, "-root") {
				states = []string{"clean", "finder"}
			} // macOS cannot attach a resource fork to a directory.
			for _, state := range states {
				for _, transport := range []string{"native"} {
					t.Run(format+"/"+location+"/"+state+"/"+transport, func(t *testing.T) {
						dir := extractionDirectory(t)
						b, paths := sidebandBundleFixture(t, dir, format)
						target := paths[location]
						metadata := appledouble.File{}
						if state == "fork" || state == "both" {
							metadata.ResourceFork = []byte("resource fork")
						}
						if state == "finder" || state == "both" {
							copy(metadata.FinderInfo[:], "TEXTttxt")
						}
						setSidebandObject(t, target, metadata)
						type result struct {
							out, stderr string
							status      int
							args        []string
						}
						results := map[string]result{}
						for _, policy := range []string{"default", "sideband", "all", "plain", "deep", "ignore", "none", "no-strict"} {
							t.Run(policy, func(t *testing.T) {
								args := []string{"--verify", "--verbose=1"}
								switch policy {
								case "sideband", "all":
									args = append(args, "--strict="+policy)
								case "plain":
									args = append(args, "--strict")
								case "deep":
									args = append(args, "--strict=sideband", "--deep")
								case "ignore":
									args = append(args, "--strict=sideband", "--ignore-resources")
								case "none":
									args = append(args, "--strict=sideband", "--strict=none")
								case "no-strict":
									args = append(args, "--strict=sideband", "--no-strict")
								}
								active := policy != "default" && policy != "none" && policy != "no-strict"
								goArgs := append([]string{}, args...)
								before, attrs := layoutArchive(t, dir), sidebandObjectAttrs(t, target)
								out, se, status := run(t, binaryPath, append(goArgs, b)...)
								checked := location != "signature" && location != "directory" && (location != "info" || !strings.HasPrefix(format, "app")) && (location != "root" || format != "framework")
								if policy == "ignore" {
									checked = location == "main" || location == "root" && format != "framework" || location == "version-root"
								}
								if format == "recursive" && policy != "deep" && (strings.HasPrefix(location, "grandchild-") || location == "child-resource") {
									checked = false
								}
								want := 0
								if active && checked && state != "clean" && runtime.GOOS != "linux" {
									want = 1
								}
								if status != want {
									t.Fatal("portable sideband", status, want, out, se)
								}
								nativeEqual(t, "bundle metadata input preservation", layoutArchive(t, dir), before)
								if !reflect.DeepEqual(attrs, sidebandObjectAttrs(t, target)) {
									t.Fatal("attributes changed")
								}
								results[policy] = result{out, se, status, args}
								attest(t, map[string]any{"format": format, "location": location, "state": state, "transport": transport, "policy": policy, "exit": status, "stdout": out, "stderr": se, "input_preserved": true, "fixture_root": dir})
							})
						}
						if runtime.GOOS == "darwin" {
							before, attrs := layoutArchive(t, dir), sidebandObjectAttrs(t, target)
							for _, policy := range []string{"default", "sideband", "all", "plain", "deep", "ignore", "none", "no-strict"} {
								t.Run("reference/"+policy, func(t *testing.T) {
									r, ok := results[policy]
									if !ok {
										return
									}
									out, se, status := run(t, apple(t), append(r.args, b)...)
									if status != r.status || sortedSidebandDetails(out) != sortedSidebandDetails(r.out) || se != r.stderr {
										t.Errorf("native %s: exit %d/%d stdout %q/%q stderr %q/%q", policy, status, r.status, out, r.out, se, r.stderr)
									}
									nativeEqual(t, "native bundle preservation", layoutArchive(t, dir), before)
									if !reflect.DeepEqual(attrs, sidebandObjectAttrs(t, target)) {
										t.Fatal("native attributes changed")
									}
									attest(t, map[string]any{"format": format, "location": location, "state": state, "transport": transport, "policy": policy, "native_exit": status, "native_stdout": out, "native_stderr": se, "compared": true, "input_preserved": true, "fixture_root": dir})
								})
							}
						}
					})
				}
			}
		}
	}
}

func TestBundleSidebandLinkOpen(t *testing.T) {
	for _, format := range []string{"app", "framework"} {
		for _, state := range append(append([]string{}, verificationLinkStates...), "chain-31", "chain-32", "chain-33", "chain-34", "file-slash", "physical-parent") {
			t.Run(format+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				b, _, _, _ := verificationLinkFixture(t, dir, format, "adhoc", state)
				before := layoutArchive(t, dir)
				for _, selector := range []string{"sideband", "all"} {
					t.Run(selector, func(t *testing.T) {
						args := []string{"--verify", "--verbose=1", "--strict=" + selector}
						out, se, status := run(t, binaryPath, append(args, b)...)
						want := 0
						switch state {
						case "dangling", "self-cycle", "pair-cycle", "dangling-chain", "absolute-missing", "chain-32", "chain-33", "chain-34", "file-slash":
							want = 1
						case "relative-escape", "chain-escape", "absolute-external", "excluded-target":
							if selector == "all" {
								want = 1
							}
						}
						// These fixed absolute paths intentionally describe each verifying host.
						if runtime.GOOS != "darwin" && (state == "absolute-system" || state == "absolute-external") {
							want = 1
						}
						if format == "framework" && state == "chain-31" {
							want = 1
						} // Current is another followed link.
						if status != want {
							t.Fatal(status, want, out, se)
						}
						nativeEqual(t, "link-open verification preservation", layoutArchive(t, dir), before)
						nout, nerr := "", ""
						nstatus := status
						if runtime.GOOS == "darwin" {
							nativeArgs := append(append([]string{}, args...), "--strict=4096", b)
							nout, nerr, nstatus = run(t, apple(t), nativeArgs...)
							if status != nstatus || sortedSidebandDetails(out) != sortedSidebandDetails(nout) || se != nerr {
								t.Fatal("native link-open", status, nstatus, out, nout, se, nerr)
							}
							nativeEqual(t, "native link-open preservation", layoutArchive(t, dir), before)
						}
						attest(t, map[string]any{"format": format, "state": state, "selector": selector, "exit": status, "stdout": out, "stderr": se, "native_exit": nstatus, "native_stdout": nout, "native_stderr": nerr, "native_compared": runtime.GOOS == "darwin", "native_single_threaded": runtime.GOOS == "darwin", "input_preserved": true})
					})
				}
			})
		}
	}
}

func TestBundleSidebandFailureOrder(t *testing.T) {
	for _, state := range []string{"root-main-resource", "root-main", "root-modified-resource", "root-missing-resource", "resource-modified", "corrupt-main", "modified-link-dangling", "modified-link-metadata"} {
		t.Run(state, func(t *testing.T) {
			dir := extractionDirectory(t)
			b, paths := sidebandBundleFixture(t, dir, "app")
			metadata := appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{'T', 'E', 'X', 'T'}}
			finder := appledouble.File{FinderInfo: [32]byte{'T', 'E', 'X', 'T'}}
			assignments := map[string]appledouble.File{}
			switch state {
			case "root-main-resource":
				assignments[paths["root"]] = finder
				assignments[paths["main"]] = metadata
				assignments[paths["resource"]] = metadata
			case "root-main":
				assignments[paths["root"]] = finder
				assignments[paths["main"]] = metadata
			case "root-modified-resource":
				assignments[paths["root"]] = finder
				bundleWrite(t, b, "Contents/Resources/a", []byte("changed"))
			case "root-missing-resource":
				assignments[paths["root"]] = finder
				if err := os.Remove(paths["resource"]); err != nil {
					t.Fatal(err)
				}
			case "resource-modified":
				assignments[paths["resource"]] = metadata
				bundleWrite(t, b, "Contents/Resources/a", []byte("changed"))
			case "corrupt-main":
				assignments[paths["root"]] = finder
				assignments[paths["resource"]] = metadata
				data := nativeRead(t, paths["main"])
				data[4096] ^= 1
				bundleWrite(t, b, "Contents/MacOS/hello", data)
			case "modified-link-dangling", "modified-link-metadata":
				link := filepath.Join(b, "Contents/Resources/link")
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				target := "absent"
				if state == "modified-link-metadata" {
					target = "a"
					assignments[paths["resource"]] = metadata
				}
				layoutLink(t, b, "Contents/Resources/link", target)
			}
			for target, metadata := range assignments {
				setSidebandObject(t, target, metadata)
			}
			before := layoutArchive(t, dir)
			args := []string{"--verify", "--verbose=1", "--strict=sideband"}
			out, se, status := run(t, binaryPath, append(append([]string{}, args...), b)...)
			want := 1
			if runtime.GOOS == "linux" && (state == "root-main-resource" || state == "root-main") {
				want = 0
			}
			if status != want {
				t.Fatal(status, out, se)
			}
			nativeEqual(t, "mixed-failure preservation", layoutArchive(t, dir), before)
			if state == "corrupt-main" && (!strings.Contains(se, "code or signature have been modified") || out != "") {
				t.Fatal("integrity must precede metadata", out, se)
			}
			if runtime.GOOS != "linux" && state == "root-main" && !strings.Contains(out, "FinderInfo found on "+b+"\n") {
				t.Fatal("root must precede executable", out, se)
			}
			if runtime.GOOS == "darwin" {
				for path, value := range assignments {
					setSidebandObject(t, path, value)
				}
				before = layoutArchive(t, dir)
				nout, nerr, nstatus := run(t, apple(t), append(append([]string{}, args...), "--strict=4096", b)...)
				if status != nstatus || sortedSidebandDetails(out) != sortedSidebandDetails(nout) || se != nerr {
					t.Fatal(status, nstatus, out, nout, se, nerr)
				}
				nativeEqual(t, "native mixed-failure preservation", layoutArchive(t, dir), before)
			}
			attest(t, map[string]any{"state": state, "exit": status, "stdout": out, "stderr": se, "native_compared": runtime.GOOS == "darwin", "native_single_threaded": runtime.GOOS == "darwin", "input_preserved": true})
		})
	}
}

func TestBundleSidebandFrameworkVersions(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, version := range []string{"A", "B"} {
			for _, location := range []string{"root", "main", "resource", "outer-root"} {
				t.Run(fmt.Sprintf("nested-%t/%s/%s", nested, version, location), func(t *testing.T) {
					dir := extractionDirectory(t)
					parent := filepath.Join(dir, "Parent.app")
					where := dir
					if nested {
						bundleFixture(t, parent, "arm64")
						where = filepath.Join(parent, "Contents/Frameworks")
					}
					framework := frameworkVersionsFixture(t, where, "arm64", "binary")
					signFrameworkVersions(t, binaryPath, framework, "-")
					b := framework
					if nested {
						b = parent
						mustRun(t, binaryPath, "-s", "-", parent)
					}
					base := filepath.Join(framework, "Versions", version)
					target := base
					switch location {
					case "main":
						target = filepath.Join(base, "Fixture")
					case "resource":
						target = filepath.Join(base, "Resources/message.txt")
					case "outer-root":
						target = framework
					}
					metadata := appledouble.File{FinderInfo: [32]byte{'T', 'E', 'X', 'T'}}
					setSidebandObject(t, target, metadata)
					for _, deep := range []bool{false, true} {
						t.Run(fmt.Sprintf("deep-%t", deep), func(t *testing.T) {
							args := []string{"--verify", "--verbose=1", "--strict=sideband"}
							if deep {
								args = append(args, "--deep")
							}
							before := layoutArchive(t, dir)
							out, se, status := run(t, binaryPath, append(append([]string{}, args...), b)...)
							want := 0
							if runtime.GOOS != "linux" && (nested || version == "B") && (location != "resource" || !nested || deep) && (location != "outer-root" || nested) {
								want = 1
							}
							if status != want {
								t.Fatal(status, want, out, se)
							}
							nativeEqual(t, "framework metadata preservation", layoutArchive(t, dir), before)
							if runtime.GOOS == "darwin" {
								setSidebandObject(t, target, metadata)
								nout, nerr, nstatus := run(t, apple(t), append(append([]string{}, args...), "--strict=4096", b)...)
								if status != nstatus || sortedSidebandDetails(out) != sortedSidebandDetails(nout) || se != nerr {
									t.Error("native versions", status, nstatus, out, nout, se, nerr)
								}
								nativeEqual(t, "native framework preservation", layoutArchive(t, dir), before)
							}
							attest(t, map[string]any{"nested": nested, "version": version, "location": location, "deep": deep, "exit": status, "stdout": out, "stderr": se, "native_compared": runtime.GOOS == "darwin", "input_preserved": true})
						})
					}
				})
			}
		}
	}
}

func TestBundleSidebandParentPaths(t *testing.T) {
	for _, profile := range []string{"app", "versioned"} {
		for _, mode := range []string{"relative", "parent-dotdot"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				physical := filepath.Join(dir, "physical")
				b, suffix, target := parentAliasFixture(t, physical, profile, "arm64")
				if err := os.Mkdir(filepath.Join(physical, "nested"), 0755); err != nil {
					t.Fatal(err)
				}
				layoutLink(t, dir, "alias", "physical")
				layoutLink(t, dir, "left/link", "../physical/nested")
				decoy, _, _ := parentAliasFixture(t, filepath.Join(dir, "left"), profile, "arm64")
				beforeDecoy := layoutArchive(t, decoy)
				if err := codesign.Sign(context.Background(), b, codesign.SignOptions{Deep: true}); err != nil {
					t.Fatal(err)
				}
				operand := filepath.Join("alias", suffix)
				if mode == "parent-dotdot" {
					operand = filepath.Join(dir, "left/link") + string(filepath.Separator) + ".." + string(filepath.Separator) + suffix
				}
				value := appledouble.File{FinderInfo: [32]byte{'T', 'E', 'X', 'T'}}
				setSidebandObject(t, target, value)
				args := []string{"--verify", "--verbose=1", "--strict=all"}
				before := layoutArchive(t, dir)
				out, se, status := run(t, binaryPath, append(append([]string{}, args...), operand)...)
				if runtime.GOOS == "linux" {
					if status != 0 {
						t.Fatal(status, out, se)
					}
				} else if status != 1 || !strings.Contains(out, "FinderInfo found on "+target) {
					t.Fatal(status, out, se)
				}
				nativeEqual(t, "metadata alias verification preservation", layoutArchive(t, dir), before)
				if runtime.GOOS == "darwin" {
					setSidebandObject(t, target, value)
					nout, nerr, nstatus := run(t, apple(t), append(args, operand)...)
					if status != nstatus || out != nout || se != nerr {
						t.Fatal(status, nstatus, out, nout, se, nerr)
					}
					nativeEqual(t, "native alias verification preservation", layoutArchive(t, dir), before)
				}
				nativeEqual(t, "lexical neighbour preservation", layoutArchive(t, decoy), beforeDecoy)
				attest(t, map[string]any{"profile": profile, "mode": mode, "exit": status, "stdout": out, "stderr": se, "native_compared": runtime.GOOS == "darwin", "input_preserved": true, "lexical_neighbour_preserved": true})
			})
		}
	}
}
