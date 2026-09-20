package acceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var layoutLocations = map[string]string{"bundle": "PlugIns", "plugin": "Plug-ins", "xpc": "XPCServices", "appex": "PlugIns/Extensions", "framework": "Frameworks", "versioned": "SharedFrameworks"}

func mixedLayoutFixture(t *testing.T, arch string) string {
	t.Helper()
	app := filepath.Join(t.TempDir(), "Outer.app")
	bundleFixture(t, app, arch)
	for _, kind := range bundleLayouts {
		layoutFixture(t, filepath.Join(app, "Contents", filepath.FromSlash(layoutLocations[kind])), kind, arch, "binary")
	}
	layoutLink(t, app, "Contents/Resources/framework-resource", "../Frameworks/Fixture.framework/Resources/message.txt")
	return app
}

func TestAppleMixedLayouts(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mode := range []string{"deep", "runtime", "override", "preserve"} {
			t.Run(arch+"/"+mode, func(t *testing.T) {
				native, portable := mixedLayoutFixture(t, arch), mixedLayoutFixture(t, arch)
				args := []string{"-s", "-", "--deep", "--timestamp=none"}
				switch mode {
				case "runtime":
					args = append(args, "--options", "runtime")
				case "override":
					args = append(args, "-i", "shared.identifier", "-r", `=designated => identifier "shared.identifier"`)
				case "preserve":
					for _, tool := range []struct{ program, app string }{{reference, native}, {binaryPath, portable}} {
						mustRun(t, tool.program, "-s", "-", "--deep", "-i", "preserved", filepath.Join(tool.app, "Contents/SharedFrameworks/Fixture.framework"))
					}
				}
				mustRun(t, reference, append(args, native)...)
				mustRun(t, binaryPath, append(args, portable)...)
				nativeEqual(t, "mixed bundle tree", layoutArchive(t, portable), layoutArchive(t, native))
				mustRun(t, reference, "--verify", "--strict", "--deep", portable)
				mustRun(t, binaryPath, "--verify", "--deep", native)
				attest(t, map[string]any{"architecture": arch, "mode": mode, "bundles": 7, "mach_o_files": 9, "complete_tree_bytes_equal": true, "native_strict_deep_verified": true})
			})
		}
	}
}

func TestPortableMixedLayouts(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, identity := range []string{"adhoc", "rsa", "p256"} {
			t.Run(arch+"/"+identity, func(t *testing.T) {
				app := mixedLayoutFixture(t, arch)
				id := "-"
				verify := []string{"--verify", "--deep"}
				if identity != "adhoc" {
					id = filepath.Join(root, "testdata/identities/"+identity+"-identity.pem")
					verify = append(verify, "--trust", filepath.Join(root, "testdata/identities/"+identity+"-cert.pem"))
				}
				mustRun(t, binaryPath, "-s", id, "--deep", "--timestamp=none", app)
				mustRun(t, binaryPath, append(verify, app)...)
				if runtime.GOOS == "darwin" {
					mustRun(t, apple(t), "--verify", "--strict", "--deep", app)
				}
				if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
					bundleWrite(t, export, "signed-layout-mixed-"+identity+"-"+arch+".tar", layoutArchive(t, app))
				}
				attest(t, map[string]any{"architecture": arch, "identity": identity, "bundles": 7, "native_strict_deep_verified": runtime.GOOS == "darwin"})
			})
		}
	}
}

func TestAppleMixedLayoutRemoval(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			native, portable := mixedLayoutFixture(t, arch), mixedLayoutFixture(t, arch)
			for _, tool := range []struct{ program, app string }{{reference, native}, {binaryPath, portable}} {
				mustRun(t, tool.program, "-s", "-", "--deep", "--timestamp=none", tool.app)
				before := layoutArchive(t, tool.app, "Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources")
				mustRun(t, tool.program, "--remove-signature", tool.app)
				nativeEqual(t, "outer removal preserves descendants and resources", layoutArchive(t, tool.app, "Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources"), before)
				assertRemoved(t, nativeRead(t, filepath.Join(tool.app, "Contents/MacOS/hello")))
			}
			nativeEqual(t, "removed mixed tree", layoutArchive(t, portable), layoutArchive(t, native))
			attest(t, map[string]any{"architecture": arch, "native_removal_complete_tree_bytes_equal": true, "descendants_unchanged": true})
		})
	}
}

func TestLayoutMutationParity(t *testing.T) {
	reference := apple(t)
	for _, kind := range []string{"bundle", "xpc", "framework", "versioned"} {
		for _, change := range []string{"retarget", "replace-link", "link-missing", "target-altered", "dangling", "cycle", "info", "main", "optional-missing", "header", "alias"} {
			if change == "header" && kind != "framework" && kind != "versioned" || change == "alias" && kind != "versioned" {
				continue
			}
			t.Run(kind+"/"+change, func(t *testing.T) {
				bundle := layoutFixture(t, t.TempDir(), kind, "arm64", "xml")
				mustRun(t, reference, "-s", "-", "--deep", bundle)
				_, base, info, executable := layoutPaths(kind)
				remove := func(name string) {
					t.Helper()
					if err := os.Remove(filepath.Join(bundle, filepath.FromSlash(name))); err != nil {
						t.Fatal(err)
					}
				}
				switch change {
				case "retarget":
					remove(base + "Resources/alias")
					layoutLink(t, bundle, base+"Resources/alias", "./message.txt")
				case "replace-link":
					remove(base + "Resources/alias")
					bundleWrite(t, bundle, base+"Resources/alias", []byte("hello\n"))
				case "link-missing":
					remove(base + "Resources/alias")
				case "target-altered":
					bundleWrite(t, bundle, base+"Resources/message.txt", []byte("tampered\n"))
				case "dangling":
					remove(base + "Resources/message.txt")
				case "cycle":
					remove(base + "Resources/alias")
					layoutLink(t, bundle, base+"Resources/alias", "alias")
				case "info":
					p := base + info
					data := nativeRead(t, filepath.Join(bundle, p))
					bundleWrite(t, bundle, p, bytes.ReplaceAll(data, []byte("org.example.layout"), []byte("org.example.changed")))
				case "main":
					p := base + executable
					data := nativeRead(t, filepath.Join(bundle, p))
					data[4096] ^= 1
					bundleWrite(t, bundle, p, data)
				case "optional-missing":
					remove(base + "Resources/fr.lproj/alias")
				case "header":
					bundleWrite(t, bundle, base+"Headers/Fixture.h", []byte("tampered"))
				case "alias":
					remove("Fixture")
					layoutLink(t, bundle, "Fixture", "Versions/Current/helper")
				}
				for _, deep := range []bool{false, true} {
					args := []string{"--verify"}
					if deep {
						args = append(args, "--deep")
					}
					_, ns, nc := run(t, reference, append(append([]string{"--strict"}, args...), bundle)...)
					_, gs, gc := run(t, binaryPath, append(args, bundle)...)
					want := change == "optional-missing"
					if (nc == 0) != want || (gc == 0) != want {
						t.Fatalf("deep=%v expected=%v native=%d %s Go=%d %s", deep, want, nc, ns, gc, gs)
					}
				}
				attest(t, map[string]any{"layout": kind, "mutation": change, "shallow_and_deep_agree": true, "valid": change == "optional-missing"})
			})
		}
	}
}

func TestMixedLayoutTimestamps(t *testing.T) {
	server, ca, requests, mode := localTimestampAuthority(t)
	app := mixedLayoutFixture(t, "universal")
	id, cert := filepath.Join(root, "testdata/identities/rsa-identity.pem"), filepath.Join(root, "testdata/identities/rsa-cert.pem")
	args := []string{"-fs", id, "--deep", "--timestamp=" + server.URL, "--timestamp-root", ca}
	mustRun(t, binaryPath, append(args, app)...)
	if requests.Load() != 18 {
		t.Fatal("expected eighteen architecture signatures", requests.Load())
	}
	mustRun(t, binaryPath, "--verify", "--deep", "--trust", cert, "--timestamp-root", ca, app)
	before, count := layoutArchive(t, app), requests.Load()
	mustRun(t, binaryPath, append(append([]string{}, args...), "--dryrun", app)...)
	if requests.Load()-count != 18 || !bytes.Equal(before, layoutArchive(t, app)) {
		t.Fatal("timestamp dryrun mutated tree")
	}
	failed := mixedLayoutFixture(t, "arm64")
	before, count = layoutArchive(t, failed), requests.Load()
	mode.Store("second")
	if _, _, code := run(t, binaryPath, append(args, failed)...); code == 0 {
		t.Fatal("TSA failure accepted")
	}
	if requests.Load()-count != 2 || !bytes.Equal(before, layoutArchive(t, failed)) {
		t.Fatal("late failure mutated mixed tree")
	}
	attest(t, map[string]any{"timestamps_per_tree": 18, "dryrun_preserved": true, "late_failure_preserved": true})
}

func verifyLayoutArchive(t *testing.T, reference, archive string) {
	t.Helper()
	name := filepath.Base(archive)
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, "signed-layout-"), ".tar"), "-")
	if len(parts) != 3 {
		t.Fatal("unexpected layout archive", name)
	}
	ext, _, _, _ := layoutPaths(parts[0])
	base := "Fixture." + ext
	if parts[0] == "mixed" {
		base = "Outer.app"
	}
	bundle := filepath.Join(t.TempDir(), base)
	extractLayout(t, nativeRead(t, archive), bundle)
	mustRun(t, reference, "--verify", "--strict", "--deep", bundle)
}
