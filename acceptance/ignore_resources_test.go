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
)

var ignoredResourceStates = []string{"clean", "all-three", "nested-missing", "nested-false", "nested-page", "nested-malformed", "resources-missing", "resources-file", "envelope-missing", "envelope-changed", "envelope-empty", "signature-missing", "cycle", "escape"}

func mutateIgnoredResource(t *testing.T, path, base, state string) {
	t.Helper()
	remove := func(name string) {
		t.Helper()
		if err := os.RemoveAll(filepath.Join(base, name)); err != nil {
			t.Fatal(err)
		}
	}
	switch state {
	case "clean", "nested-false":
	case "all-three", "nested-missing":
		mutateResource(t, base, state)
	case "nested-page":
		verificationMutation(t, filepath.Join(base, "Helpers/tool"), "", "page", false)
	case "nested-malformed":
		bundleWrite(t, base, "Helpers/tool", []byte("not an executable"))
	case "resources-missing", "resources-file":
		remove("Resources")
		if state == "resources-file" {
			bundleWrite(t, base, "Resources", []byte("not a directory"))
		}
	case "envelope-missing", "envelope-directory", "envelope-link":
		remove("_CodeSignature/CodeResources")
		switch state {
		case "envelope-directory":
			if err := os.Mkdir(filepath.Join(base, "_CodeSignature/CodeResources"), 0755); err != nil {
				t.Fatal(err)
			}
		case "envelope-link":
			layoutLink(t, base, "_CodeSignature/CodeResources", "../Resources/a")
		}
	case "envelope-changed":
		bundleWrite(t, base, "_CodeSignature/CodeResources", []byte("not a resource envelope"))
	case "envelope-empty":
		bundleWrite(t, base, "_CodeSignature/CodeResources", nil)
	case "signature-missing", "signature-file":
		remove("_CodeSignature")
		if state == "signature-file" {
			bundleWrite(t, base, "_CodeSignature", []byte("not a directory"))
		}
	case "signature-extra", "signature-empty", "signature-nonempty":
		name, contents := "CodeSignature", []byte{}
		switch state {
		case "signature-extra":
			name = "rogue"
		case "signature-nonempty":
			contents = []byte("rogue")
		}
		bundleWrite(t, base, "_CodeSignature/"+name, contents)
	case "root-extra":
		bundleWrite(t, path, "rogue", []byte("unsealed"))
	case "cycle":
		layoutLink(t, base, "Resources/cycle-a", "cycle-b")
		layoutLink(t, base, "Resources/cycle-b", "cycle-a")
	case "escape":
		layoutLink(t, base, "Resources/escape", "../../../../absent")
	default:
		t.Fatal("unknown ignored resource mutation", state)
	}
}

// Every attestation includes both actual invocations and raw diagnostics. Only
// path separators are normalized in the portable cross-producer digest.
func compareIgnoredVerification(t *testing.T, dir, path string, verify codesign.VerifyOptions, trust, flags []string, wanted int) {
	t.Helper()
	operand, err := filepath.Rel(dir, path)
	if err != nil {
		t.Fatal(err)
	}
	operand = filepath.ToSlash(operand)
	before := layoutArchive(t, dir)
	args := append([]string{"--verify", "--ignore-resources"}, flags...)
	goArgs := append(append(append([]string{}, args...), trust...), operand)
	nativeArgs := append(append([]string{}, args...), operand)
	out, stderr, status := run(t, binaryPath, goArgs...)
	if status != wanted || out != "" {
		t.Fatalf("portable: exit=%d want=%d stdout=%q stderr=%q", status, wanted, out, stderr)
	}
	nativeOut, nativeErr, nativeStatus := "", "", -1
	if runtime.GOOS == "darwin" {
		nativeOut, nativeErr, nativeStatus = run(t, apple(t), nativeArgs...)
		if nativeStatus != status || nativeOut != out || nativeErr != stderr {
			t.Fatalf("portable=(%d,%q,%q), Apple=(%d,%q,%q)", status, out, stderr, nativeStatus, nativeOut, nativeErr)
		}
	}
	verify.IgnoreResources = true
	for _, flag := range flags {
		if strings.HasPrefix(flag, "--architecture=") {
			verify.Architecture = strings.TrimPrefix(flag, "--architecture=")
		}
		switch flag {
		case "--deep":
			verify.Deep = true
		case "--no-strict":
			verify.NoStrict = true
		case "--strict=symlinks":
			verify.StrictSymlinks = true
		case "--verbose=1":
			verify.CheckDesignatedRequirement = true
		case "-R=never":
			verify.Requirement = "never"
		}
	}
	report, err := codesign.Verify(context.Background(), path, verify)
	if (err == nil) != (wanted == 0) || report == nil || report.Valid != (wanted == 0) || !report.ResourcesIgnored {
		t.Fatal("library verification scope", report, err, wanted)
	}
	nativeEqual(t, "verification preserved the complete input tree", layoutArchive(t, dir), before)
	attest(t, map[string]any{"args": goArgs, "native_args": nativeArgs, "exit": status, "stdout": out, "stderr": stderr, "native_exit": nativeStatus, "native_stdout": nativeOut, "native_stderr": nativeErr, "input_sha256": hash(before), "diagnostics_sha256": hash([]byte(strings.ReplaceAll(out+"\x00"+stderr, "\\", "/"))), "input_preserved": true, "resources_ignored": report.ResourcesIgnored, "library_policy_matched": true, "native_compared": runtime.GOOS == "darwin", "exact_diagnostics": true})
}

func TestIgnoreResourcesArchitectures(t *testing.T) {
	for _, changed := range []string{"arm64", "x86_64"} {
		t.Run(changed, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			path := defaultFixture(t, dir, "universal")
			if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Identifier: "org.example.ignore"}); err != nil {
				t.Fatal(err)
			}
			verificationMutation(t, path, changed, "page", false)
			for _, selection := range []string{"all", "arm64", "x86_64"} {
				t.Run(selection, func(t *testing.T) {
					flags, wanted := []string{"--verbose=1"}, 1
					if selection != "all" {
						flags = append(flags, "--architecture="+selection)
					}
					if selection != "all" && selection != changed {
						wanted = 0
					}
					compareIgnoredVerification(t, dir, path, codesign.VerifyOptions{}, nil, flags, wanted)
				})
			}
		})
	}
}

func TestIgnoreResourcesNestedBundles(t *testing.T) {
	for _, kind := range []string{"app", "framework"} {
		for _, state := range []string{"missing", "info", "page"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				parent := defaultFixture(t, dir, "app")
				child := defaultFixture(t, filepath.Join(parent, "Contents/Frameworks"), kind)
				if err := codesign.Sign(context.Background(), parent, codesign.SignOptions{Identifier: "org.example.ignore", Deep: true}); err != nil {
					t.Fatal(err)
				}
				switch state {
				case "missing":
					if err := os.RemoveAll(child); err != nil {
						t.Fatal(err)
					}
				case "info":
					info := "Contents/Info.plist"
					if kind == "framework" {
						info = "Versions/A/Resources/Info.plist"
					}
					bundleWrite(t, child, info, []byte("not a plist"))
				case "page":
					verificationMutation(t, child, "", "page", false)
				}
				for _, deep := range []bool{false, true} {
					t.Run(fmt.Sprintf("deep-%t", deep), func(t *testing.T) {
						flags := []string{"--verbose=1"}
						if deep {
							flags = append(flags, "--deep")
						}
						compareIgnoredVerification(t, dir, parent, codesign.VerifyOptions{}, nil, flags, 0)
					})
				}
			})
		}
	}
}

func TestIgnoreResources(t *testing.T) {
	for _, format := range []string{"app", "framework"} {
		for _, algorithm := range []string{"adhoc", "rsa"} {
			for _, state := range ignoredResourceStates {
				if format == "framework" && (state == "resources-missing" || state == "resources-file") {
					continue // Framework Resources also contains required Info.plist.
				}
				t.Run(format+"/"+algorithm+"/"+state, func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					path, base, verify, trust := resourceFixture(t, dir, format, algorithm, state)
					mutateIgnoredResource(t, path, base, state)
					for _, profile := range []struct {
						name  string
						flags []string
					}{{"quiet", nil}, {"verbose", []string{"--verbose=1"}}, {"deep", []string{"--verbose=1", "--deep"}}, {"symlinks", []string{"--verbose=1", "--strict=symlinks"}}, {"no-strict", []string{"--verbose=1", "--no-strict"}}} {
						t.Run(profile.name, func(t *testing.T) { compareIgnoredVerification(t, dir, path, verify, trust, profile.flags, 0) })
					}
				})
			}
		}
	}
}

func TestIgnoreResourcesStructure(t *testing.T) {
	for _, format := range []string{"app", "framework"} {
		for _, state := range []string{"envelope-directory", "envelope-link", "signature-extra", "signature-empty", "signature-nonempty", "signature-file", "root-extra"} {
			if format == "framework" && state == "root-extra" {
				continue // Noncanonical framework roots remain explicitly unsupported.
			}
			t.Run(format+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				path, base, verify, trust := resourceFixture(t, dir, format, "adhoc", "clean")
				mutateIgnoredResource(t, path, base, state)
				for _, noStrict := range []bool{false, true} {
					t.Run(fmt.Sprintf("no-strict-%t", noStrict), func(t *testing.T) {
						flags, wanted := []string{"--verbose=1"}, 1
						if noStrict {
							flags = append(flags, "--no-strict")
						}
						if noStrict || state == "signature-empty" {
							wanted = 0
						}
						compareIgnoredVerification(t, dir, path, verify, trust, flags, wanted)
					})
				}
			})
		}
	}
}

func TestIgnoreResourcesIntegrity(t *testing.T) {
	for _, format := range []string{"arm64", "x86_64", "universal", "app", "framework", "dmg"} {
		for _, state := range []string{"clean", "page", "requirements", "cms", "self", "explicit", "info"} {
			if state == "info" && format != "app" && format != "framework" || state == "page" && format == "dmg" {
				continue
			}
			t.Run(format+"/"+state, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				path := defaultFixture(t, dir, format)
				algorithm, requirement := "adhoc", "always"
				if state == "cms" {
					algorithm = "rsa"
				}
				if state == "self" {
					requirement = "never"
				}
				id, verify, trust := verificationIdentity(t, algorithm)
				req, err := codesign.CompileRequirements("designated => " + requirement)
				if err != nil {
					t.Fatal(err)
				}
				if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Identifier: "org.example.ignore", Identity: id, Requirements: req, SigningTime: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}); err != nil {
					t.Fatal(err)
				}
				switch state {
				case "page", "requirements":
					verificationMutation(t, path, "", state, false)
				case "cms":
					r, data := inspectDefaults(t, path)
					for _, a := range r.Architectures {
						cms := signatureBlob(a.Signature, codesign.SlotCMS)
						base := int(a.Offset + a.SignatureOffset)
						at := base + bytes.Index(data[base:], cms)
						data[at+len(cms)-64] ^= 1
					}
					executable := path
					if r.Bundle != nil {
						executable = r.Bundle.Executable
					}
					if err := os.WriteFile(executable, data, 0755); err != nil {
						t.Fatal(err)
					}
				case "info":
					info := "Contents/Info.plist"
					if format == "framework" {
						info = "Versions/A/Resources/Info.plist"
					}
					data := nativeRead(t, filepath.Join(path, info))
					changed := bytes.Replace(data, []byte("example"), []byte("changed"), 1)
					if bytes.Equal(data, changed) {
						t.Fatal("missing Info.plist mutation target")
					}
					bundleWrite(t, path, info, changed)
				}
				for _, verbose := range []bool{false, true} {
					t.Run(fmt.Sprintf("verbose-%t", verbose), func(t *testing.T) {
						flags, wanted := []string{}, 1
						if verbose {
							flags = append(flags, "--verbose=1")
						}
						if state == "clean" || state == "self" && !verbose {
							wanted = 0
						}
						if state == "self" && verbose || state == "explicit" {
							wanted = 3
						}
						if state == "explicit" {
							flags = append(flags, "-R=never")
						}
						compareIgnoredVerification(t, dir, path, verify, trust, flags, wanted)
					})
				}
			})
		}
	}
}

func TestIgnoreResourcesJSON(t *testing.T) {
	for _, state := range []string{"clean", "all-three", "signature-extra", "nested-malformed"} {
		t.Run(state, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			path, base, _, _ := resourceFixture(t, dir, "app", "adhoc", "clean")
			mutateIgnoredResource(t, path, base, state)
			before := layoutArchive(t, dir)
			out, stderr, status := run(t, binaryPath, "--verify", "--ignore-resources", "--deep", "--json", "Parent.app")
			var report codesign.Report
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatal(err, out)
			}
			valid := state != "signature-extra"
			if report.Valid != valid || !report.ResourcesIgnored || (status == 0) != valid {
				t.Fatal(status, report, stderr)
			}
			if report.Path != "Parent.app" || report.Bundle == nil || report.Bundle.Executable != filepath.Join("Parent.app", "Contents/MacOS/hello") || report.Bundle.ResourceVersion != 0 || report.Bundle.ResourceRules != 0 || report.Bundle.ResourceFiles != 0 {
				t.Fatal("unread resource metadata or bundle paths", report)
			}
			report.Bundle.Executable = filepath.ToSlash(report.Bundle.Executable)
			portable, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			nativeEqual(t, "JSON verification input preserved", layoutArchive(t, dir), before)
			attest(t, map[string]any{"exit": status, "stdout": out, "stderr": stderr, "input_sha256": hash(before), "json_sha256": hash(portable), "input_preserved": true, "resources_ignored": report.ResourcesIgnored, "native_compared": false})
		})
	}
}

func TestIgnoreResourcesAppleSigned(t *testing.T) {
	_ = apple(t)
	for _, state := range []string{"all-three", "nested-missing", "nested-page", "envelope-changed", "signature-missing", "cycle", "envelope-directory", "signature-extra"} {
		t.Run(state, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			path, base, verify, trust := resourceFixture(t, dir, "app", "adhoc", "clean")
			for _, operand := range []string{filepath.Join(base, "Helpers/tool"), path} {
				out, stderr, status := run(t, apple(t), "--force", "--sign", "-", "--identifier", "org.example.apple.ignore", operand)
				if status != 0 {
					t.Fatal(status, out, stderr)
				}
			}
			mutateIgnoredResource(t, path, base, state)
			wanted := 0
			if state == "envelope-directory" || state == "signature-extra" {
				wanted = 1
			}
			compareIgnoredVerification(t, dir, path, verify, trust, []string{"--verbose=1", "--deep"}, wanted)
		})
	}
}

func TestIgnoreResourcesInertOperations(t *testing.T) {
	for _, operation := range []string{"sign", "display", "remove"} {
		t.Run(operation, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			fixture := "adhoc-arm64"
			args := []string{"--display", "--requirements", "-"}
			if operation == "sign" {
				fixture, args = "unsigned-arm64", []string{"--sign", "-", "--identifier", "org.example.ignore"}
			}
			if operation == "remove" {
				args = []string{"--remove-signature"}
			}
			original := nativeRead(t, filepath.Join(root, "testdata/macho", fixture))
			for _, exe := range []string{binaryPath, "/usr/bin/codesign"} {
				if exe != binaryPath && runtime.GOOS != "darwin" {
					continue
				}
				label := "portable"
				if exe != binaryPath {
					label = "native"
				}
				t.Run(label, func(t *testing.T) {
					var beforeOut, beforeErr string
					var beforeBytes []byte
					for _, ignored := range []bool{false, true} {
						if err := os.WriteFile("input", original, 0755); err != nil {
							t.Fatal(err)
						}
						argv := append([]string{}, args...)
						if ignored {
							argv = append(argv, "--ignore-resources")
						}
						argv = append(argv, "input")
						out, stderr, status := run(t, exe, argv...)
						if status != 0 {
							t.Fatal(argv, status, out, stderr)
						}
						result := nativeRead(t, "input")
						if !ignored {
							beforeOut, beforeErr, beforeBytes = out, stderr, result
							continue
						}
						if beforeOut != out || beforeErr != stderr || !bytes.Equal(beforeBytes, result) {
							t.Fatal("flag changed operation", out, stderr)
						}
						attest(t, map[string]any{"args": argv, "exit": status, "stdout": out, "stderr": stderr, "output_sha256": hash(result), "inert": true, "native_compared": exe != binaryPath})
					}
				})
			}
		})
	}
}
