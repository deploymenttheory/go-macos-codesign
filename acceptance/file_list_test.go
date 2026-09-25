package acceptance

import (
	"context"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Expected paths derive from fixture layouts, independently of Report.SignatureFiles.
func fileListInput(t *testing.T, dir, profile, arch string) (path, executable, resources string) {
	t.Helper()
	if profile == "standalone" {
		path = filepath.Join(dir, "tool")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		copyFixture(t, "unsigned-"+arch, path)
		return path, path, ""
	}
	if strings.HasPrefix(profile, "dmg-") {
		path = filepath.Join(dir, "image.dmg")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, dmgFixture(t, strings.TrimPrefix(profile, "dmg-")), 0644); err != nil {
			t.Fatal(err)
		}
		// Fresh native DMG signing with --file-list crashes after writing. This
		// equality matrix covers display, replacement signing and signed dry runs.
		mustRun(t, binaryPath, "-s", "-", path)
		return path, path, ""
	}
	if profile == "recursive" {
		path = filepath.Join(dir, "Recursive.app")
		recursiveFixture(t, path, arch, "xml")
		return path, filepath.Join(path, "Contents/MacOS/hello"), filepath.Join(path, "Contents/_CodeSignature/CodeResources")
	}
	_, suffix, executable := parentAliasFixture(t, dir, profile, arch)
	path = filepath.Join(dir, suffix)
	if profile == "versioned" {
		resources = filepath.Join(path, "Versions/Current") + string(filepath.Separator) + filepath.FromSlash("./_CodeSignature/CodeResources")
	} else if strings.HasPrefix(profile, "version-") {
		resources = filepath.Join(filepath.Dir(executable), "_CodeSignature/CodeResources")
	} else {
		_, base, _, _ := layoutPaths(profile)
		if profile == "app" {
			base = "Contents/"
		}
		resources = filepath.Join(path, filepath.FromSlash(base+"_CodeSignature/CodeResources"))
	}
	return path, executable, resources
}

func fileListPrograms(t *testing.T) []string {
	t.Helper()
	programs := []string{binaryPath}
	if runtime.GOOS == "darwin" {
		programs = append(programs, apple(t))
	}
	return programs
}

func TestFileList(t *testing.T) {
	profiles := []string{"standalone", "app", "bundle", "plugin", "xpc", "appex", "framework", "versioned", "version-A", "version-Current", "recursive", "dmg-raw", "dmg-zlib", "dmg-lzfse", "dmg-lzma", "dmg-apfs"}
	for _, profile := range profiles {
		architectures := []string{"arm64", "x86_64", "universal"}
		if strings.HasPrefix(profile, "dmg-") {
			architectures = []string{"none"}
		}
		for _, arch := range architectures {
			for _, mode := range []string{"stdout", "append-parent-alias"} {
				t.Run(profile+"/"+arch+"/"+mode, func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					inputs := filepath.Join(dir, "inputs")
					if err := os.Mkdir(inputs, 0755); err != nil {
						t.Fatal(err)
					}
					layoutLink(t, dir, "alias", "inputs")
					var signed, goAfter, dryrun []byte
					var recorded string
					for i, exe := range fileListPrograms(t) {
						if err := os.RemoveAll(inputs); err != nil {
							t.Fatal(err)
						}
						path, executable, resources := fileListInput(t, inputs, profile, arch)
						operand := path
						if mode == "append-parent-alias" {
							operand = "alias" + strings.TrimPrefix(path, inputs)
						}
						want := executable + "\n"
						if resources != "" {
							want += resources + "\n"
						}
						destination := "-"
						if mode != "stdout" {
							destination = "list"
							if err := os.WriteFile(destination, []byte("existing\n"), 0600); err != nil {
								t.Fatal(err)
							}
						}
						accumulated := "existing\n"
						for _, operation := range []string{"sign", "display", "resign", "dryrun"} {
							args := []string{"-d"}
							expectedErr := "Executable=" + executable + "\n"
							if operation != "display" {
								args = []string{"-s", "-", "--timestamp=none", "--deep"}
								expectedErr = ""
								if operation != "sign" || strings.HasPrefix(profile, "dmg-") {
									args = append(args, "-f")
									expectedErr = operand + ": replacing existing signature\n"
								}
								if operation == "dryrun" {
									args = append(args, "--dryrun")
								}
							} else if arch == "universal" {
								args = append(args, "-a", "x86_64")
							}
							args = append(args, "--file-list", destination, operand)
							out, stderr, code := run(t, exe, args...)
							if code != 0 || stderr != expectedErr {
								t.Fatalf("%s %s: exit=%d stdout=%q stderr=%q want=%q", exe, operation, code, out, stderr, expectedErr)
							}
							if destination == "-" {
								if out != want {
									t.Fatalf("%s %s: list=%q want=%q", exe, operation, out, want)
								}
							} else {
								accumulated += want
								if out != "" || string(nativeRead(t, destination)) != accumulated {
									t.Fatalf("append %s %s: stdout=%q file=%q want=%q", exe, operation, out, nativeRead(t, destination), accumulated)
								}
							}
							current := layoutArchive(t, inputs)
							if operation == "sign" {
								if i == 0 {
									signed = current
								} else {
									nativeEqual(t, "file-list signing", current, signed)
								}
							} else if operation == "display" || operation == "dryrun" && !strings.HasPrefix(profile, "dmg-") {
								nativeEqual(t, "read-only file-list operation", current, signed)
							}
							if operation == "dryrun" {
								if i == 0 {
									dryrun = current
								} else {
									nativeEqual(t, "file-list dry run", current, dryrun)
								}
							}
							if operation == "resign" {
								if i == 0 {
									goAfter = current
								} else {
									nativeEqual(t, "file-list replacement", current, goAfter)
								}
							}
						}
						recorded = filepath.ToSlash(strings.ReplaceAll(want, dir, "<fixture>"))
						if runtime.GOOS == "darwin" && !strings.HasPrefix(profile, "dmg-") {
							mustRun(t, apple(t), "--verify", "--strict", "--deep", path)
						}
					}
					attest(t, map[string]any{"profile": profile, "architecture": arch, "mode": mode, "native_compared": runtime.GOOS == "darwin", "exact_output": true, "entries": recorded, "signing_sha256": hash(signed), "replacement_sha256": hash(goAfter), "dryrun_sha256": hash(dryrun), "display_preserved": true, "dryrun_preserved": !strings.HasPrefix(profile, "dmg-"), "operations": 4})
				})
			}
		}
	}
}

func TestFileListExternalComponents(t *testing.T) {
	for _, mode := range []string{"absent-resources", "stale", "embedded-entitlements"} {
		t.Run(mode, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			path, executable, resources := fileListInput(t, dir, "app", "arm64")
			args := []string{"-s", "-"}
			if mode == "embedded-entitlements" {
				args = append(args, "--entitlements", filepath.Join(root, "testdata/entitlements.plist"))
			}
			mustRun(t, binaryPath, append(args, path)...)
			report, err := codesign.Inspect(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			want := executable + "\n"
			if mode == "absent-resources" {
				if err := os.Remove(resources); err != nil {
					t.Fatal(err)
				}
			} else {
				want += resources + "\n"
				for _, name := range []string{"CodeDirectory", "CodeSignature", "CodeTopDirectory", "CodeEntitlements", "CodeEntitlementDER", "CodeRepSpecific", "unrelated"} {
					bundleWrite(t, path, "Contents/_CodeSignature/"+name, []byte("unparsed external bytes"))
					if name == "CodeTopDirectory" || name == "CodeRepSpecific" || mode != "embedded-entitlements" && strings.HasPrefix(name, "CodeEntitlement") {
						want += filepath.Join(filepath.Dir(resources), name) + "\n"
					}
				}
			}
			before := layoutArchive(t, path)
			files, err := report.SignatureFiles("")
			if err != nil || strings.Join(files, "\n")+"\n" != want {
				t.Fatal(files, err, want)
			}
			// CLI inspection still rejects extra signature files; compare the
			// path-report API to native selection without weakening that policy.
			programs := []string{}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			for _, exe := range programs {
				out, stderr, code := run(t, exe, "-d", "--file-list=-", path)
				if code != 0 || out != want || stderr != "Executable="+executable+"\n" {
					t.Fatalf("%s: %d %q %q want=%q", exe, code, out, stderr, want)
				}
				nativeEqual(t, "external components preserved", layoutArchive(t, path), before)
			}
			attest(t, map[string]any{"mode": mode, "native_compared": runtime.GOOS == "darwin", "exact_output": true, "entries": filepath.ToSlash(strings.ReplaceAll(want, dir, "<fixture>")), "input_sha256": hash(before), "input_preserved": true})
		})
	}
}
