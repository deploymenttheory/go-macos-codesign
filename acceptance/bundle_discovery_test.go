package acceptance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var executableProfiles = []string{"app", "bundle", "plugin", "xpc", "appex", "framework", "version-A", "version-Current", "version-alias"}

func executableFixture(t *testing.T, profile, arch, metadata string) (bundle, executable string) {
	t.Helper()
	if profile == "app" {
		bundle = filepath.Join(t.TempDir(), "Example.app")
		bundlePlistFixture(t, bundle, arch, metadata)
		return bundle, filepath.Join(bundle, "Contents/MacOS/hello")
	}
	if strings.HasPrefix(profile, "version-") {
		bundle = frameworkVersionsFixture(t, t.TempDir(), arch, metadata)
		suffix := "Fixture"
		if profile != "version-alias" {
			suffix = "Versions/" + strings.TrimPrefix(profile, "version-") + "/Fixture"
		}
		return bundle, filepath.Join(bundle, filepath.FromSlash(suffix))
	}
	bundle = layoutFixture(t, t.TempDir(), profile, arch, metadata)
	_, base, _, exe := layoutPaths(profile)
	return bundle, filepath.Join(bundle, filepath.FromSlash(base+exe))
}

func TestAppleExecutablePaths(t *testing.T) {
	reference := apple(t)
	for _, profile := range executableProfiles {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, metadata := range []string{"xml", "binary"} {
				t.Run(profile+"/"+arch+"/"+metadata, func(t *testing.T) {
					native, np := executableFixture(t, profile, arch, metadata)
					portable, gp := executableFixture(t, profile, arch, metadata)
					args := []string{"-s", "-", "--deep", "--timestamp=none"}
					mustRun(t, reference, append(args, np)...)
					mustRun(t, binaryPath, append(args, gp)...)
					nativeEqual(t, "executable-input signing tree", layoutArchive(t, portable), layoutArchive(t, native))
					nr, err := filepath.EvalSymlinks(native)
					if err != nil {
						t.Fatal(err)
					}
					gr, err := filepath.EvalSymlinks(portable)
					if err != nil {
						t.Fatal(err)
					}
					for level := 0; level < 5; level++ {
						option := "-d" + strings.Repeat("v", level)
						wo, we, wc := run(t, reference, option, np)
						goout, ge, gc := run(t, binaryPath, option, gp)
						if wo != goout || wc != gc || strings.ReplaceAll(we, nr, "<bundle>") != strings.ReplaceAll(ge, gr, "<bundle>") {
							t.Fatalf("display %d: Apple %d %s%s Go %d %s%s", level, wc, wo, we, gc, goout, ge)
						}
					}
					mustRun(t, reference, "--verify", "--strict", "--deep", gp)
					mustRun(t, binaryPath, "--verify", "--deep", np)
					before := layoutArchive(t, portable)
					mustRun(t, binaryPath, "-fs", "-", "--deep", "--dryrun", gp)
					nativeEqual(t, "executable-input dry run", layoutArchive(t, portable), before)
					mustRun(t, reference, "--remove-signature", np)
					mustRun(t, binaryPath, "--remove-signature", gp)
					nativeEqual(t, "executable-input removal tree", layoutArchive(t, portable), layoutArchive(t, native))
					attest(t, map[string]any{"profile": profile, "architecture": arch, "metadata": metadata, "signing_tree_byte_equal": true, "removal_tree_byte_equal": true, "display_comparisons": 5, "dryrun_preserved": true, "native_strict_deep_verified": true})
				})
			}
		}
	}
}

func mixedExecutablePaths(app string) []string {
	paths := []string{filepath.Join(app, "Contents/MacOS/hello")}
	for _, kind := range bundleLayouts {
		ext, base, _, exe := layoutPaths(kind)
		bundle := filepath.Join(app, "Contents", filepath.FromSlash(layoutLocations[kind]), "Fixture."+ext)
		paths = append(paths, filepath.Join(bundle, filepath.FromSlash(base+exe)))
		if kind == "versioned" {
			paths = append(paths, filepath.Join(bundle, "Fixture"), filepath.Join(bundle, "Versions/Current/Fixture"))
		}
	}
	return paths
}

func TestPortableExecutablePaths(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, identity := range []string{"adhoc", "rsa", "p256"} {
			t.Run(arch+"/"+identity, func(t *testing.T) {
				app := mixedLayoutFixture(t, arch)
				paths := mixedExecutablePaths(app)
				id, verify := "-", []string{"--verify", "--deep"}
				if identity != "adhoc" {
					id = filepath.Join(root, "testdata/identities/"+identity+"-identity.pem")
					verify = append(verify, "--trust", filepath.Join(root, "testdata/identities/"+identity+"-cert.pem"))
				}
				// Every layout is signed through its main executable before the parent.
				for _, p := range append(append([]string{}, paths[1:7]...), paths[0]) {
					mustRun(t, binaryPath, "-s", id, "--deep", "--timestamp=none", p)
				}
				mustRun(t, binaryPath, append(verify, app)...)
				for _, p := range paths {
					mustRun(t, binaryPath, append(verify, p)...)
					if runtime.GOOS == "darwin" {
						mustRun(t, apple(t), "--verify", "--strict", "--deep", p)
					}
				}
				archive := layoutArchive(t, app)
				if identity == "adhoc" {
					for _, kind := range bundleLayouts {
						ext, _, _, _ := layoutPaths(kind)
						child := filepath.Join(app, "Contents", filepath.FromSlash(layoutLocations[kind]), "Fixture."+ext)
						nativeEqual(t, "executable discovery reproduces native child fixture", layoutArchive(t, child), nativeRead(t, filepath.Join(root, "testdata/layouts", kind+"-"+arch+".tar")))
					}
				}
				if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
					bundleWrite(t, export, "signed-executable-"+identity+"-"+arch+".tar", archive)
				}
				attest(t, map[string]any{"architecture": arch, "identity": identity, "bundle_count": 7, "executable_inputs_verified": len(paths), "native_fixture_equal": identity == "adhoc", "native_strict_deep_verified": runtime.GOOS == "darwin", "archive_sha256": hash(archive)})
			})
		}
	}
}

func TestExecutableDiscoveryAliasesAndHelpers(t *testing.T) {
	for _, mode := range []string{"main", "helper", "symlink", "outside-alias"} {
		t.Run(mode, func(t *testing.T) {
			makeInput := func() (string, string) {
				b, p := executableFixture(t, "app", "arm64", "xml")
				switch mode {
				case "helper":
					bundleWrite(t, b, "Contents/MacOS/helper", nativeRead(t, p))
					p = filepath.Join(b, "Contents/MacOS/helper")
				case "symlink":
					layoutLink(t, b, "Contents/MacOS/alias", "hello")
					p = filepath.Join(b, "Contents/MacOS/alias")
				case "outside-alias":
					q := filepath.Join(t.TempDir(), "alias")
					if err := os.Symlink(p, q); err != nil {
						t.Fatal(err)
					}
					p = q
				}
				return b, p
			}
			b, p := makeInput()
			mustRun(t, binaryPath, "-s", "-", p)
			mustRun(t, binaryPath, "--verify", p)
			_, err := os.Stat(filepath.Join(b, "Contents/_CodeSignature/CodeResources"))
			promoted := mode != "helper"
			if (err == nil) != promoted {
				t.Fatal("unexpected resource boundary", mode, err)
			}
			if runtime.GOOS == "darwin" {
				n, np := makeInput()
				mustRun(t, apple(t), "-s", "-", np)
				nativeEqual(t, "main/helper/alias boundary", layoutArchive(t, b), layoutArchive(t, n))
				mustRun(t, apple(t), "--verify", "--strict", p)
			}
			bundleWrite(t, b, "Contents/Resources/message.txt", []byte("tampered"))
			_, _, code := run(t, binaryPath, "--verify", p)
			if (code != 0) != promoted {
				t.Fatal("wrong tampered resource result", mode, code)
			}
			if runtime.GOOS == "darwin" {
				_, _, native := run(t, apple(t), "--verify", p)
				if native != code {
					t.Fatal("native tamper mismatch", native, code)
				}
			}
			attest(t, map[string]any{"mode": mode, "bundle_selected": promoted, "tampered_resource_rejected": promoted, "native_checked": runtime.GOOS == "darwin"})
		})
	}
}

func TestExecutableHardlinkDiscovery(t *testing.T) {
	b, p := executableFixture(t, "app", "arm64", "xml")
	// Start with a signed standalone file. This compares read-only discovery;
	// Native hard-link replacement during signing is covered by writer tests.
	bundleWrite(t, b, "Contents/MacOS/hello", nativeRead(t, filepath.Join(root, "testdata/macho/adhoc-arm64")))
	alias := filepath.Join(b, "Contents/MacOS/alias")
	if err := os.Link(p, alias); err != nil {
		t.Fatal(err)
	}
	_, got, code := run(t, binaryPath, "-dvv", alias)
	if code != 0 || strings.Contains(got, "bundle with") || !strings.Contains(got, "Sealed Resources=none") {
		t.Fatal(code, got)
	}
	mustRun(t, binaryPath, "--verify", alias)
	if runtime.GOOS == "darwin" {
		_, want, native := run(t, apple(t), "-dvv", alias)
		if code != native || got != want {
			t.Fatal("native hard-link discovery", got, want)
		}
	}
	attest(t, map[string]any{"hardlink_remains_standalone": true, "native_display_compared": runtime.GOOS == "darwin"})
}

func TestExecutableParentLink(t *testing.T) {
	dir := t.TempDir()
	left, right := filepath.Join(dir, "left/Example.app"), filepath.Join(dir, "right/Example.app")
	bundleFixture(t, left, "arm64")
	bundleFixture(t, right, "arm64")
	if err := os.Mkdir(filepath.Join(dir, "right/nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "right", "nested"), filepath.Join(dir, "left/link")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "left/link") + string(filepath.Separator) + filepath.FromSlash("../Example.app/Contents/MacOS/hello")
	before := layoutArchive(t, left)
	mustRun(t, binaryPath, "-s", "-", p)
	nativeEqual(t, "parent-link lexical neighbour preserved", layoutArchive(t, left), before)
	mustRun(t, binaryPath, "--verify", filepath.Join(right, "Contents/MacOS/hello"))
	if runtime.GOOS == "darwin" {
		n, np := executableFixture(t, "app", "arm64", "xml")
		mustRun(t, apple(t), "-s", "-", np)
		nativeEqual(t, "parent-link native target bytes", layoutArchive(t, right), layoutArchive(t, n))
		mustRun(t, apple(t), "--verify", "--strict", p)
	}
	if err := os.RemoveAll(left); err != nil {
		t.Fatal(err)
	}
	mustRun(t, binaryPath, "--verify", p)
	attest(t, map[string]any{"physical_target_signed": true, "lexical_neighbour_preserved": true, "missing_lexical_target_verified": true, "native_checked": runtime.GOOS == "darwin"})
}

func TestAppleExecutableVersionSelection(t *testing.T) {
	reference := apple(t)
	for _, profile := range []string{"app", "framework", "version-A", "version-alias"} {
		for _, selector := range []string{"Current", "missing"} {
			t.Run(profile+"/"+selector, func(t *testing.T) {
				b, p := executableFixture(t, profile, "arm64", "xml")
				mustRun(t, binaryPath, "-s", "-", "--deep", p)
				for _, args := range [][]string{{"-d"}, {"--verify"}, {"-fs", "-", "--deep"}, {"--remove-signature"}} {
					all := append(append([]string{}, args...), "--bundle-version="+selector, p)
					before := layoutArchive(t, b)
					_, ns, nc := run(t, reference, all...)
					_, gs, gc := run(t, binaryPath, all...)
					if nc != gc || (nc == 0) != (profile == "app") {
						t.Fatalf("%v: native=%d %s go=%d %s", args, nc, ns, gc, gs)
					}
					if nc != 0 {
						nativeEqual(t, "selector failure preservation", layoutArchive(t, b), before)
					}
				}
				attest(t, map[string]any{"profile": profile, "selector": selector, "operation_status_matches": 4, "rejection_preserves_tree": profile != "app"})
			})
		}
	}
}

func verifyExecutableArchive(t *testing.T, reference, archive string) {
	t.Helper()
	app := filepath.Join(t.TempDir(), "Outer.app")
	extractLayout(t, nativeRead(t, archive), app)
	mustRun(t, reference, "--verify", "--strict", "--deep", app)
	for _, p := range mixedExecutablePaths(app) {
		mustRun(t, reference, "--verify", "--strict", "--deep", p)
	}
}
