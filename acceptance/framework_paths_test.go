package acceptance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAppleFrameworkPaths(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, metadata := range []string{"xml", "binary"} {
			for _, version := range []string{"A", "B", "Current"} {
				t.Run(arch+"/"+metadata+"/"+version, func(t *testing.T) {
					native := frameworkVersionsFixture(t, t.TempDir(), arch, metadata)
					portable := frameworkVersionsFixture(t, t.TempDir(), arch, metadata)
					np, gp := filepath.Join(native, "Versions", version), filepath.Join(portable, "Versions", version)
					mustRun(t, reference, "-s", "-", np)
					mustRun(t, binaryPath, "-s", "-", gp)
					nativeEqual(t, "direct version signing", layoutArchive(t, portable), layoutArchive(t, native))
					for verbose := 0; verbose < 5; verbose++ {
						option := "-d" + strings.Repeat("v", verbose)
						_, want, wc := run(t, reference, option, np)
						_, got, gc := run(t, binaryPath, option, gp)
						resolved, err := filepath.EvalSymlinks(native)
						if err != nil {
							t.Fatal(err)
						}
						resolvedGo, err := filepath.EvalSymlinks(portable)
						if err != nil {
							t.Fatal(err)
						}
						if gc != wc || strings.ReplaceAll(got, resolvedGo, "<framework>") != strings.ReplaceAll(want, resolved, "<framework>") {
							t.Fatalf("display %d\nGo %s\nApple %s", verbose, got, want)
						}
					}
					mustRun(t, reference, "--verify", "--strict", "--deep", gp)
					mustRun(t, binaryPath, "--verify", "--deep", np)
					before := layoutArchive(t, portable)
					mustRun(t, binaryPath, "-fs", "-", "--dryrun", gp)
					nativeEqual(t, "direct version dry run", layoutArchive(t, portable), before)
					mustRun(t, reference, "--remove-signature", np)
					mustRun(t, binaryPath, "--remove-signature", gp)
					nativeEqual(t, "direct version removal", layoutArchive(t, portable), layoutArchive(t, native))
					attest(t, map[string]any{"architecture": arch, "metadata": metadata, "path_version": version, "complete_signing_bytes_equal": true, "complete_removal_bytes_equal": true, "display_levels": 5, "native_strict_deep_verified": true, "dryrun_preserved": true})
				})
			}
		}
	}
}

func signFrameworkPaths(t *testing.T, tool, framework, identity string) {
	t.Helper()
	for _, version := range []string{"A", "Current"} {
		args := []string{"-s", identity, "--timestamp=none"}
		if identity == "-" {
			args = append(args, "-r", frameworkRequirement)
		}
		mustRun(t, tool, append(args, filepath.Join(framework, "Versions", version))...)
	}
}

func TestAppleFrameworkPathNested(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, version := range []string{"A", "Current"} {
			t.Run(arch+"/"+version, func(t *testing.T) {
				// This fixture includes an unsigned top-level Mach-O helper.
				native := layoutFixture(t, t.TempDir(), "versioned", arch, "binary")
				portable := layoutFixture(t, t.TempDir(), "versioned", arch, "binary")
				np, gp := filepath.Join(native, "Versions", version), filepath.Join(portable, "Versions", version)
				mustRun(t, reference, "-s", "-", "--deep", np)
				mustRun(t, binaryPath, "-s", "-", "--deep", gp)
				nativeEqual(t, "direct-path deep signing", layoutArchive(t, portable), layoutArchive(t, native))
				mustRun(t, reference, "--verify", "--strict", "--deep", gp)
				mustRun(t, binaryPath, "--verify", "--deep", np)
				attest(t, map[string]any{"architecture": arch, "path_version": version, "deep_signing_tree_equal": true, "native_strict_deep_verified": true})
			})
		}
	}
}

func TestPortableFrameworkPaths(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, identity := range []string{"adhoc", "rsa", "p256"} {
			t.Run(arch+"/"+identity, func(t *testing.T) {
				app := filepath.Join(t.TempDir(), "Outer.app")
				bundleFixture(t, app, arch)
				framework := frameworkVersionsFixture(t, filepath.Join(app, "Contents/Frameworks"), arch, "binary")
				id := "-"
				verify := []string{"--verify", "--deep"}
				if identity != "adhoc" {
					id = filepath.Join(root, "testdata/identities/"+identity+"-identity.pem")
					verify = append(verify, "--trust", filepath.Join(root, "testdata/identities/"+identity+"-cert.pem"))
				}
				signFrameworkPaths(t, binaryPath, framework, id)
				mustRun(t, binaryPath, "-s", id, "--timestamp=none", app)
				mustRun(t, binaryPath, append(verify, app)...)
				for _, version := range []string{"A", "B", "Current"} {
					p := filepath.Join(framework, "Versions", version)
					mustRun(t, binaryPath, append(verify, p)...)
					if runtime.GOOS == "darwin" {
						mustRun(t, apple(t), "--verify", "--strict", "--deep", p)
					}
				}
				archive := layoutArchive(t, app)
				if identity == "adhoc" {
					native := nativeRead(t, filepath.Join(root, "testdata/framework-versions", arch+".tar"))
					nativeEqual(t, "direct-path signing reproduces native version selection", archive, native)
				}
				if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
					bundleWrite(t, export, "signed-paths-"+identity+"-"+arch+".tar", archive)
				}
				attest(t, map[string]any{"architecture": arch, "identity": identity, "archive_sha256": hash(archive), "native_directories_verified": runtime.GOOS == "darwin", "native_fixture_equal": identity == "adhoc"})
			})
		}
	}
}

func TestAppleFrameworkPathBoundary(t *testing.T) {
	reference := apple(t)
	for _, change := range []string{"none", "missing-current", "outer-file", "other-metadata"} {
		t.Run(change, func(t *testing.T) {
			b := frameworkVersionsFixture(t, t.TempDir(), "arm64", "binary")
			p := filepath.Join(b, "Versions/A")
			switch change {
			case "missing-current":
				if err := os.Remove(filepath.Join(b, "Versions/Current")); err != nil {
					t.Fatal(err)
				}
			case "outer-file":
				bundleWrite(t, b, "unsealed", []byte("unsealed"))
			case "other-metadata":
				bundleWrite(t, b, "Versions/B/Resources/Info.plist", []byte("invalid metadata"))
			}
			mustRun(t, binaryPath, "-s", "-", p)
			mustRun(t, reference, "--verify", "--strict", "--deep", p)
			mustRun(t, binaryPath, "--verify", "--deep", p)
			for _, selection := range []string{"A", "B", "Current", "missing"} {
				for _, operation := range [][]string{{"-d"}, {"--verify"}, {"-fs", "-"}, {"--remove-signature"}} {
					args := append(append([]string{}, operation...), "--bundle-version="+selection, p)
					before := layoutArchive(t, b)
					_, ns, nc := run(t, reference, args...)
					_, gs, gc := run(t, binaryPath, args...)
					if nc != 1 || gc != nc {
						t.Fatalf("%v Apple %d %s Go %d %s", args, nc, ns, gc, gs)
					}
					nativeEqual(t, "invalid direct selection preservation", layoutArchive(t, b), before)
				}
			}
			attest(t, map[string]any{"outer_change": change, "native_direct_boundary_verified": true, "invalid_selection_cases": 16, "failures_preserved_tree": true})
		})
	}
}

func TestFrameworkPathsThroughParentLink(t *testing.T) {
	for _, version := range []string{"A", "Current"} {
		t.Run(version, func(t *testing.T) {
			dir := t.TempDir()
			left := frameworkVersionsFixture(t, filepath.Join(dir, "left"), "arm64", "binary")
			right := frameworkVersionsFixture(t, filepath.Join(dir, "right"), "arm64", "binary")
			if err := os.Mkdir(filepath.Join(dir, "right/nested"), 0755); err != nil {
				t.Fatal(err)
			}
			layoutLink(t, dir, "left/link", "../right/nested")
			// Different Current targets detect premature Windows path normalization.
			if err := os.Remove(filepath.Join(left, "Versions/Current")); err != nil {
				t.Fatal(err)
			}
			layoutLink(t, left, "Versions/Current", "A")
			input := filepath.Join(dir, "left/link") + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Join("Fixture.framework/Versions", version)
			beforeLeft := layoutArchive(t, left)
			unsigned := layoutArchive(t, right)
			mustRun(t, binaryPath, "-s", "-", input)
			mustRun(t, binaryPath, "--verify", "--deep", input)
			nativeEqual(t, "lexical sibling remains unchanged", layoutArchive(t, left), beforeLeft)
			physical := version
			if version == "Current" {
				physical = "B"
			}
			mustRun(t, binaryPath, "--verify", filepath.Join(right, "Versions", physical))
			if runtime.GOOS == "darwin" {
				mustRun(t, apple(t), "--verify", "--strict", "--deep", input)
				want := layoutArchive(t, right)
				if err := os.RemoveAll(right); err != nil {
					t.Fatal(err)
				}
				extractLayout(t, unsigned, right)
				mustRun(t, apple(t), "-s", "-", input)
				nativeEqual(t, "native physical path selection", layoutArchive(t, right), want)
				nativeEqual(t, "native lexical sibling preservation", layoutArchive(t, left), beforeLeft)
			}
			if err := os.RemoveAll(left); err != nil {
				t.Fatal(err)
			}
			mustRun(t, binaryPath, "--verify", "--deep", input)
			attest(t, map[string]any{"path_version": version, "physical_target_signed": true, "lexical_sibling_preserved": true, "missing_lexical_target_verified": true, "native_bytes_equal": runtime.GOOS == "darwin"})
		})
	}
}
