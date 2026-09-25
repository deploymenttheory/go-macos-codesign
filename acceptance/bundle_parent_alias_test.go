package acceptance

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func parentAliasFixture(t *testing.T, dir, profile, arch string) (bundle, suffix, executable string) {
	t.Helper()
	if profile == "app" {
		bundle = filepath.Join(dir, "Example.app")
		bundleFixture(t, bundle, arch)
		return bundle, "Example.app", filepath.Join(bundle, "Contents/MacOS/hello")
	}
	if strings.HasPrefix(profile, "version-") {
		bundle = frameworkVersionsFixture(t, dir, arch, "binary")
		version := strings.TrimPrefix(profile, "version-")
		suffix = filepath.Join("Fixture.framework/Versions", version)
		physical := version
		if version == "Current" {
			physical = "B"
		}
		return bundle, suffix, filepath.Join(bundle, "Versions", physical, "Fixture")
	}
	bundle = layoutFixture(t, dir, profile, arch, "binary")
	_, base, _, main := layoutPaths(profile)
	if profile == "versioned" {
		base = "Versions/Current/"
	}
	return bundle, filepath.Base(bundle), filepath.Join(bundle, filepath.FromSlash(base+main))
}

func TestBundleParentAliases(t *testing.T) {
	for _, profile := range []string{"app", "bundle", "plugin", "xpc", "appex", "framework", "versioned", "version-A", "version-Current"} {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, mode := range []string{"physical", "relative", "chain", "parent-dotdot"} {
				t.Run(profile+"/"+arch+"/"+mode, func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					physical := filepath.Join(dir, "physical")
					// Windows needs existing directory targets when creating these links.
					if err := os.MkdirAll(filepath.Join(physical, "nested"), 0755); err != nil {
						t.Fatal(err)
					}
					layoutLink(t, dir, "alias", "physical")
					layoutLink(t, dir, "chain", "alias")
					layoutLink(t, dir, "left/link", "../physical/nested")
					decoy, _, _ := parentAliasFixture(t, filepath.Join(dir, "left"), profile, arch)
					beforeDecoy := layoutArchive(t, decoy)
					programs := []string{binaryPath}
					if runtime.GOOS == "darwin" {
						programs = append(programs, apple(t))
					}
					var signed, removed []byte
					var goDisplay []string
					for i, exe := range programs {
						if err := os.RemoveAll(physical); err != nil {
							t.Fatal(err)
						}
						bundle, suffix, executable := parentAliasFixture(t, physical, profile, arch)
						if err := os.Mkdir(filepath.Join(physical, "nested"), 0755); err != nil {
							t.Fatal(err)
						}
						operand := filepath.Join(physical, suffix)
						switch mode {
						case "relative":
							operand = filepath.Join("alias", suffix)
						case "chain":
							operand = filepath.Join(dir, "chain", suffix)
						case "parent-dotdot":
							// Do not let filepath.Join erase the physical-parent test.
							operand = filepath.Join(dir, "left/link") + string(filepath.Separator) + ".." + string(filepath.Separator) + suffix
						}
						out, stderr, code := run(t, exe, "-s", "-", "--deep", "--timestamp=none", operand)
						if code != 0 || out != "" || stderr != "" {
							t.Fatalf("sign %s: %d %q %q", exe, code, out, stderr)
						}
						currentSigned := layoutArchive(t, bundle)
						if i == 0 {
							signed = currentSigned
						} else {
							nativeEqual(t, "parent alias signing tree", currentSigned, signed)
						}
						displays := []string{}
						for level := 0; level < 5; level++ {
							out, stderr, code = run(t, exe, "-d"+strings.Repeat("v", level), operand)
							if code != 0 || out != "" || !strings.HasPrefix(stderr, "Executable="+executable+"\n") {
								t.Fatalf("display %s: %d %q %q, executable=%q", exe, code, out, stderr, executable)
							}
							displays = append(displays, stderr)
						}
						if i == 0 {
							goDisplay = displays
						} else if !reflect.DeepEqual(goDisplay, displays) {
							t.Fatalf("raw display differs: Go %q native %q", goDisplay, displays)
						}
						out, stderr, code = run(t, exe, "--verify", "--deep", operand)
						if code != 0 || out != "" || stderr != "" {
							t.Fatal("verify", exe, code, out, stderr)
						}
						if i == 0 && runtime.GOOS == "darwin" {
							mustRun(t, apple(t), "--verify", "--strict", "--deep", operand)
						}
						out, stderr, code = run(t, exe, "-fs", "-", "--deep", "--dryrun", "--timestamp=none", operand)
						if code != 0 || out != "" || stderr != operand+": replacing existing signature\n" {
							t.Fatal("dry run", exe, code, out, stderr)
						}
						nativeEqual(t, "parent alias dry-run preservation", layoutArchive(t, bundle), currentSigned)
						out, stderr, code = run(t, exe, "--remove-signature", operand)
						if code != 0 || out != "" || stderr != "" {
							t.Fatal("remove", exe, code, out, stderr)
						}
						currentRemoved := layoutArchive(t, bundle)
						if i == 0 {
							removed = currentRemoved
						} else {
							nativeEqual(t, "parent alias removal tree", currentRemoved, removed)
						}
						nativeEqual(t, "lexical neighbour preserved", layoutArchive(t, decoy), beforeDecoy)
						for name, target := range map[string]string{"alias": "physical", "chain": "alias", "left/link": "../physical/nested"} {
							got, err := os.Readlink(filepath.FromSlash(name))
							if err != nil || filepath.ToSlash(got) != target {
								t.Fatal("alias changed", name, got, err)
							}
						}
					}
					attest(t, map[string]any{"profile": profile, "architecture": arch, "mode": mode, "native_compared": len(programs) == 2, "signing_sha256": hash(signed), "removal_sha256": hash(removed), "display_levels": 5, "exact_diagnostics": true, "lexical_neighbour_preserved": true, "aliases_preserved": true, "dryrun_preserved": true})
				})
			}
		}
	}
}
