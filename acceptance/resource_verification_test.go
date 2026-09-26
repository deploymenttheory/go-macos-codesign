package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

var resourceStates = []string{"added", "modified", "missing", "all-three", "multi-added", "multi-modified", "multi-missing", "optional-missing", "optional-modified", "optional-added", "base-missing", "symlink-added", "symlink-modified", "symlink-missing", "file-to-link", "link-to-file", "nested-missing", "nested-false", "mixed-nested"}

func resourceFixture(t *testing.T, dir, format, algorithm, state string) (string, string, codesign.VerifyOptions, []string) {
	t.Helper()
	path, base := "", "Contents"
	arch := "arm64"
	if format == "app-universal" {
		arch = "universal"
	}
	if strings.HasPrefix(format, "app") {
		path = filepath.Join(dir, "Parent.app")
		bundleFixture(t, path, arch)
	} else {
		kind := "versioned"
		base = "Versions/A"
		if format == "flat-framework" {
			kind, base = "framework", ""
		}
		path = layoutFixture(t, dir, kind, arch, "binary")
		if err := codesign.Sign(context.Background(), filepath.Join(path, base, "helper"), codesign.SignOptions{Identifier: "helper"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"a", "b", "c", "target", "fr.lproj/a", "Base.lproj/a"} {
		bundleWrite(t, path, filepath.ToSlash(filepath.Join(base, "Resources", name)), []byte("original"))
	}
	linkTarget := "target"
	if state == "dangling-optional" {
		linkTarget = "fr.lproj/a"
	}
	layoutLink(t, path, filepath.ToSlash(filepath.Join(base, "Resources/link")), linkTarget)
	bundleWrite(t, path, filepath.ToSlash(filepath.Join(base, "Helpers/tool")), nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+arch)))
	id, verify, trust := verificationIdentity(t, algorithm)
	source := "always"
	if state == "nested-false" || state == "mixed-nested" {
		source = "never"
	}
	req, err := codesign.CompileRequirements("designated => " + source)
	if err != nil {
		t.Fatal(err)
	}
	opts := codesign.SignOptions{Identifier: "org.example.resource", Identity: id, SigningTime: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC), Requirements: req}
	if err := codesign.Sign(context.Background(), filepath.Join(path, base, "Helpers/tool"), opts); err != nil {
		t.Fatal(err)
	}
	opts.Requirements = nil
	if err := codesign.Sign(context.Background(), path, opts); err != nil {
		t.Fatal(err)
	}
	return path, filepath.Join(path, base), verify, trust
}

func mutateResource(t *testing.T, base, state string) {
	t.Helper()
	write := func(name string) { t.Helper(); bundleWrite(t, base, "Resources/"+name, []byte("changed")) }
	remove := func(name string) {
		t.Helper()
		if err := os.Remove(filepath.Join(base, "Resources", name)); err != nil {
			t.Fatal(err)
		}
	}
	link := func(name, target string) { t.Helper(); layoutLink(t, base, "Resources/"+name, target) }
	switch state {
	case "added":
		write("new")
	case "modified":
		write("a")
	case "missing":
		remove("a")
	case "all-three", "mixed-nested":
		write("new")
		write("a")
		remove("b")
	case "multi-added":
		for _, name := range []string{"newZ", "newA", "newM"} {
			write(name)
		}
	case "multi-modified":
		for _, name := range []string{"a", "b", "c"} {
			write(name)
		}
	case "multi-missing":
		for _, name := range []string{"a", "b", "c"} {
			remove(name)
		}
	case "optional-missing":
		remove("fr.lproj/a")
	case "optional-modified":
		write("fr.lproj/a")
	case "optional-added":
		write("fr.lproj/new")
	case "base-missing":
		remove("Base.lproj/a")
	case "symlink-added":
		link("new-link", "b")
	case "symlink-modified":
		remove("link")
		link("link", "b")
	case "symlink-missing":
		remove("link")
	case "file-to-link":
		remove("a")
		link("a", "b")
	case "link-to-file":
		remove("link")
		write("link")
	case "nested-missing":
		if err := os.Remove(filepath.Join(base, "Helpers/tool")); err != nil {
			t.Fatal(err)
		}
	case "nested-false":
	default:
		t.Fatal("unknown resource mutation", state)
	}
}

// Normalize only order within each native category. Reject unknown lines,
// changed category order, dropped duplicates and invented resource paths.
func orderedResourceDetails(t *testing.T, out string) string {
	t.Helper()
	groups := make([][]string, 3)
	previous := 0
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		index := -1
		for i, prefix := range []string{"file added: ", "file modified: ", "file missing: "} {
			if strings.HasPrefix(line, prefix) {
				index = i
			}
		}
		if index < previous || index < 0 {
			t.Fatal("invalid resource detail order", out)
		}
		previous = index
		groups[index] = append(groups[index], line)
	}
	var lines []string
	for _, group := range groups {
		sort.Strings(group)
		lines = append(lines, group...)
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestResourceVerification(t *testing.T) {
	for _, format := range []string{"app", "app-universal", "framework", "flat-framework"} {
		for _, algorithm := range []string{"adhoc", "rsa"} {
			for _, state := range resourceStates {
				t.Run(format+"/"+algorithm+"/"+state, func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					path, base, verify, trust := resourceFixture(t, dir, format, algorithm, state)
					mutateResource(t, base, state)
					before := layoutArchive(t, dir)
					operand := filepath.Base(path)
					for _, verbose := range []bool{false, true} {
						t.Run(fmt.Sprintf("verbose-%t", verbose), func(t *testing.T) {
							args := []string{"--verify"}
							if verbose {
								args = append(args, "--verbose=1")
							}
							out, stderr, status := run(t, binaryPath, append(append(append([]string{}, args...), trust...), operand)...)
							wanted := 1
							if state == "optional-missing" {
								wanted = 0
							}
							if status != wanted {
								t.Fatal("portable status", status, wanted, stderr)
							}
							if state == "mixed-nested" && stderr != operand+": nested code is modified or invalid\n" {
								t.Fatal("unstable portable first resource error", stderr)
							}
							if !verbose && out != "" {
								t.Fatal("quiet resource details", out)
							}
							exact := state != "mixed-nested" && (!strings.HasPrefix(state, "multi-") || !verbose)
							nativeOut, nativeErr := "", ""
							var observations []map[string]any
							if runtime.GOOS == "darwin" {
								var nativeStatus int
								attempts := 1
								if !exact {
									attempts = 3
								}
								for i := 0; i < attempts; i++ {
									nativeOut, nativeErr, nativeStatus = run(t, apple(t), append(args, operand)...)
									observations = append(observations, map[string]any{"stdout": nativeOut, "stderr": nativeErr, "exit": nativeStatus})
									if nativeStatus != status {
										t.Fatal("native status", nativeStatus, status, nativeErr, stderr)
									}
									if exact {
										if out != nativeOut || stderr != nativeErr {
											t.Fatalf("Go=(%q,%q); Apple=(%q,%q)", out, stderr, nativeOut, nativeErr)
										}
									} else {
										nativeEqual(t, "complete resource details", []byte(orderedResourceDetails(t, out)), []byte(orderedResourceDetails(t, nativeOut)))
										if state != "mixed-nested" {
											nativeEqual(t, "resource summary", []byte(stderr), []byte(nativeErr))
										} else if nativeErr != operand+": a sealed resource is missing or invalid\n" && nativeErr != operand+": nested code is modified or invalid\n" {
											t.Fatal("unexpected mixed summary", nativeErr)
										}
									}
								}
							}
							report, err := codesign.Verify(context.Background(), path, verify)
							if report == nil || report.Valid != (wanted == 0) || (err == nil) != (wanted == 0) {
								t.Fatal("library result", report, err)
							}
							if err != nil {
								var detail *codesign.VerificationError
								if !errors.Is(err, codesign.ErrInvalid) || !errors.As(err, &detail) || detail.Architecture != "" || detail.Subcomponent != "" {
									t.Fatal("library failure context", err)
								}
								for _, group := range [][]string{detail.AddedResources, detail.ModifiedResources, detail.MissingResources} {
									for _, resource := range group {
										if !strings.HasPrefix(resource, dir+string(filepath.Separator)) {
											t.Fatal("resource path outside fixture", resource)
										}
									}
								}
							}
							nativeEqual(t, "resource verification preservation", layoutArchive(t, dir), before)
							// Only the asserted fixture root is normalized for cross-OS hashes.
							normalized := strings.ReplaceAll(out+"\x00"+stderr, dir, "ROOT")
							normalized = strings.ReplaceAll(normalized, "\\", "/")
							attest(t, map[string]any{"format": format, "algorithm": algorithm, "state": state, "verbose": verbose, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nativeOut, "native_stderr": nativeErr, "native_observations": observations, "input_sha256": hash(before), "normalized_diagnostics_sha256": hash([]byte(normalized)), "fixture_root": dir, "resource_paths_checked": true, "input_preserved": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": exact, "order_difference": strings.HasPrefix(state, "multi-") && verbose, "mixed_status_difference": state == "mixed-nested"})
						})
					}
				})
			}
		}
	}
}

func TestResourceVerificationContext(t *testing.T) {
	for _, kind := range []string{"app", "framework"} {
		for _, state := range []string{"added", "modified", "missing"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				parent := filepath.Join(dir, "Parent.app")
				bundleFixture(t, parent, "arm64")
				container := filepath.Join(parent, "Contents/PlugIns")
				if kind == "framework" {
					container = filepath.Join(parent, "Contents/Frameworks")
				}
				child, base, _, _ := resourceFixture(t, container, kind, "adhoc", state)
				if err := codesign.Sign(context.Background(), parent, codesign.SignOptions{Identifier: "parent"}); err != nil {
					t.Fatal(err)
				}
				mutateResource(t, base, state)
				before := layoutArchive(t, dir)
				for _, deep := range []bool{false, true} {
					for _, verbose := range []bool{false, true} {
						for _, jsonOutput := range []bool{false, true} {
							t.Run(fmt.Sprintf("deep-%t/verbose-%t/json-%t", deep, verbose, jsonOutput), func(t *testing.T) {
								args := []string{"--verify"}
								if deep {
									args = append(args, "--deep")
								}
								if verbose {
									args = append(args, "--verbose=1")
								}
								if jsonOutput {
									args = append(args, "--json")
								}
								out, stderr, status := run(t, binaryPath, append(args, "Parent.app")...)
								wanted := 0
								if deep {
									wanted = 1
								}
								if status != wanted {
									t.Fatal(status, wanted, stderr)
								}
								if deep && !strings.Contains(stderr, "In subcomponent: "+child+"\n") {
									t.Fatal("nested context missing", stderr)
								}
								nativeOut, nativeErr := "", ""
								if jsonOutput {
									var report codesign.Report
									if err := json.Unmarshal([]byte(out), &report); err != nil || report.Valid == deep {
										t.Fatal("JSON report", err, out)
									}
									if verbose && deep && !strings.Contains(stderr, "file "+state+": ") {
										t.Fatal("JSON resource stream", stderr)
									}
								} else if runtime.GOOS == "darwin" {
									var n int
									nativeOut, nativeErr, n = run(t, apple(t), append(args, "Parent.app")...)
									if n != status || out != nativeOut || stderr != nativeErr {
										t.Fatalf("Go=(%d,%q,%q); Apple=(%d,%q,%q)", status, out, stderr, n, nativeOut, nativeErr)
									}
								}
								nativeEqual(t, "nested resource preservation", layoutArchive(t, dir), before)
								attest(t, map[string]any{"kind": kind, "state": state, "deep": deep, "verbose": verbose, "json": jsonOutput, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nativeOut, "native_stderr": nativeErr, "input_sha256": hash(before), "input_preserved": true, "native_compared": !jsonOutput && runtime.GOOS == "darwin", "exact_diagnostics": !jsonOutput})
							})
						}
					}
				}
			})
		}
	}
}

func TestResourceVerificationFrameworkSelection(t *testing.T) {
	for _, state := range []string{"added", "modified", "missing"} {
		t.Run(state, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			path, base, _, _ := resourceFixture(t, dir, "framework", "adhoc", state)
			mutateResource(t, base, state)
			before := layoutArchive(t, dir)
			for _, selection := range []string{"Current", "A", "direct"} {
				for _, verbose := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/verbose-%t", selection, verbose), func(t *testing.T) {
						args := []string{"--verify"}
						if verbose {
							args = append(args, "--verbose=1")
						}
						operand := filepath.Base(path)
						if selection == "direct" {
							operand += "/Versions/A"
						} else {
							args = append(args, "--bundle-version="+selection)
						}
						out, stderr, status := run(t, binaryPath, append(args, operand)...)
						if status != 1 {
							t.Fatal(status, out, stderr)
						}
						nativeOut, nativeErr := "", ""
						if runtime.GOOS == "darwin" {
							var n int
							nativeOut, nativeErr, n = run(t, apple(t), append(args, operand)...)
							if n != status || out != nativeOut || stderr != nativeErr {
								t.Fatalf("Go=(%d,%q,%q); Apple=(%d,%q,%q)", status, out, stderr, n, nativeOut, nativeErr)
							}
						}
						nativeEqual(t, "selected framework preservation", layoutArchive(t, dir), before)
						attest(t, map[string]any{"state": state, "selection": selection, "verbose": verbose, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nativeOut, "native_stderr": nativeErr, "input_sha256": hash(before), "input_preserved": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": true})
					})
				}
			}
		})
	}
}

// Default verification checks the sealed text without resolving its target.
func TestResourceVerificationDangling(t *testing.T) {
	for _, format := range []string{"app", "framework"} {
		for _, state := range []string{"dangling-required", "dangling-retarget", "dangling-optional"} {
			t.Run(format+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				path, base, _, _ := resourceFixture(t, dir, format, "adhoc", state)
				switch state {
				case "dangling-required":
					if err := os.Remove(filepath.Join(base, "Resources/target")); err != nil {
						t.Fatal(err)
					}
				case "dangling-optional":
					if err := os.Remove(filepath.Join(base, "Resources/fr.lproj/a")); err != nil {
						t.Fatal(err)
					}
				case "dangling-retarget":
					if err := os.Remove(filepath.Join(base, "Resources/link")); err != nil {
						t.Fatal(err)
					}
					layoutLink(t, base, "Resources/link", "absent")
				}
				before := layoutArchive(t, dir)
				for _, verbose := range []bool{false, true} {
					t.Run(fmt.Sprintf("verbose-%t", verbose), func(t *testing.T) {
						args := []string{"--verify"}
						if verbose {
							args = append(args, "--verbose=1")
						}
						operand := filepath.Base(path)
						out, stderr, status := run(t, binaryPath, append(args, operand)...)
						want := 1
						if state == "dangling-optional" {
							want = 0
						}
						if status != want {
							t.Fatal(status, stderr)
						}
						if report, err := codesign.Verify(context.Background(), path, codesign.VerifyOptions{}); report == nil || report.Valid != (want == 0) || (want == 0 && err != nil) || (want == 1 && !errors.Is(err, codesign.ErrInvalid)) {
							t.Fatal("default dangling verification", report, err)
						}
						nativeOut, nativeErr := "", ""
						nativeStatus := -1
						if runtime.GOOS == "darwin" {
							nativeOut, nativeErr, nativeStatus = run(t, apple(t), append(args, operand)...)
							if nativeStatus != status || nativeOut != out || nativeErr != stderr {
								t.Fatal("native dangling comparison", nativeStatus, status, nativeOut, out, nativeErr, stderr)
							}
						}
						nativeEqual(t, "dangling tree preserved", layoutArchive(t, dir), before)
						attest(t, map[string]any{"format": format, "state": state, "verbose": verbose, "exit": status, "native_exit": nativeStatus, "stdout": out, "stderr": stderr, "native_stdout": nativeOut, "native_stderr": nativeErr, "input_sha256": hash(before), "input_preserved": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": true, "bounded_discovery_difference": false})
					})
				}
			})
		}
	}
}
