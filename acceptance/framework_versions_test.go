package acceptance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const frameworkRequirement = `=designated => identifier "org.example.layout"`

func frameworkVersionsFixture(t *testing.T, dir, arch, metadata string) string {
	t.Helper()
	b := layoutFixture(t, dir, "versioned", arch, metadata)
	if err := os.Remove(filepath.Join(b, "Versions/A/helper")); err != nil {
		t.Fatal(err)
	}
	extractLayout(t, layoutArchive(t, filepath.Join(b, "Versions/A")), filepath.Join(b, "Versions/B"))
	bundleWrite(t, b, "Versions/B/Resources/message.txt", []byte("version B\n"))
	if err := os.Remove(filepath.Join(b, "Versions/Current")); err != nil {
		t.Fatal(err)
	}
	layoutLink(t, b, "Versions/Current", "B")
	return b
}

func signFrameworkVersions(t *testing.T, tool, b, identity string) {
	t.Helper()
	for _, version := range []string{"A", "B"} {
		args := []string{"-s", identity, "--timestamp=none", "--bundle-version=" + version}
		if identity == "-" {
			args = append(args, "-r", frameworkRequirement)
		}
		mustRun(t, tool, append(args, b)...)
	}
}

func TestAppleFrameworkVersions(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, metadata := range []string{"xml", "binary"} {
			t.Run(arch+"/"+metadata, func(t *testing.T) {
				native := frameworkVersionsFixture(t, t.TempDir(), arch, metadata)
				portable := frameworkVersionsFixture(t, t.TempDir(), arch, metadata)
				for _, version := range []string{"A", "B"} {
					args := []string{"-s", "-", "--bundle-version", version, "-r", frameworkRequirement}
					mustRun(t, reference, append(args, native)...)
					mustRun(t, binaryPath, append(args, portable)...)
					nativeEqual(t, "selected version tree", layoutArchive(t, portable), layoutArchive(t, native))
				}
				for _, version := range []string{"A", "B", "Current"} {
					for verbose := 0; verbose < 5; verbose++ {
						args := []string{"-d" + strings.Repeat("v", verbose), "--bundle-version=" + version}
						_, want, wc := run(t, reference, append(args, native)...)
						_, got, gc := run(t, binaryPath, append(args, portable)...)
						resolved, err := filepath.EvalSymlinks(native)
						if err != nil {
							t.Fatal(err)
						}
						if wc != gc || strings.ReplaceAll(want, resolved, "<bundle>") != strings.ReplaceAll(got, portable, "<bundle>") {
							t.Fatalf("%s display %d\nGo %s\nApple %s", version, verbose, got, want)
						}
					}
					mustRun(t, reference, "--verify", "--strict", "--deep", "--bundle-version="+version, portable)
					mustRun(t, binaryPath, "--verify", "--deep", "--bundle-version="+version, native)
				}
				before := layoutArchive(t, portable)
				mustRun(t, binaryPath, "-fs", "-", "--bundle-version=A", "--dryrun", portable)
				nativeEqual(t, "selected dry run preservation", layoutArchive(t, portable), before)
				mustRun(t, reference, "--remove-signature", "--bundle-version=A", native)
				mustRun(t, binaryPath, "--remove-signature", "--bundle-version=A", portable)
				nativeEqual(t, "selected removal", layoutArchive(t, portable), layoutArchive(t, native))
				mustRun(t, reference, "--verify", "--strict", portable)
				mustRun(t, binaryPath, "--verify", native)
				attest(t, map[string]any{"architecture": arch, "metadata": metadata, "selected_signing_tree_comparisons": 2, "display_comparisons": 15, "selected_removal_equal": true, "dryrun_preserved": true, "native_strict_deep_checks": 3})
			})
		}
	}
}

func TestAppleFrameworkSelectionBoundaries(t *testing.T) {
	reference := apple(t)
	for _, kind := range []string{"versioned", "framework", "app", "macho"} {
		t.Run(kind, func(t *testing.T) {
			var p string
			switch kind {
			case "versioned", "framework":
				p = layoutFixture(t, t.TempDir(), kind, "arm64", "xml")
			case "app":
				p = filepath.Join(t.TempDir(), "Outer.app")
				bundleFixture(t, p, "arm64")
			case "macho":
				p = filepath.Join(t.TempDir(), "hello")
				copyFixture(t, "unsigned-arm64", p)
			}
			mustRun(t, binaryPath, "-s", "-", "--deep", p)
			for _, version := range []string{"missing", "Current"} {
				_, ns, nc := run(t, reference, "-d", "--bundle-version="+version, p)
				_, gs, gc := run(t, binaryPath, "-d", "--bundle-version="+version, p)
				valid := kind == "app" || kind == "macho" || kind == "versioned" && version == "Current"
				if (nc == 0) != valid || gc != nc {
					t.Fatalf("selector %s expected valid=%v Apple=%d %s Go=%d %s", version, valid, nc, ns, gc, gs)
				}
			}
		})
	}
}

func TestPortableFrameworkVersions(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, identity := range []string{"adhoc", "rsa", "p256"} {
			t.Run(arch+"/"+identity, func(t *testing.T) {
				app := filepath.Join(t.TempDir(), "Outer.app")
				bundleFixture(t, app, arch)
				b := frameworkVersionsFixture(t, filepath.Join(app, "Contents/Frameworks"), arch, "binary")
				id := "-"
				verify := []string{"--verify", "--deep"}
				if identity != "adhoc" {
					id = filepath.Join(root, "testdata/identities/"+identity+"-identity.pem")
					verify = append(verify, "--trust", filepath.Join(root, "testdata/identities/"+identity+"-cert.pem"))
				}
				signFrameworkVersions(t, binaryPath, b, id)
				// Selection on a Contents parent must not propagate to its children.
				mustRun(t, binaryPath, "-s", id, "--bundle-version=missing", "--timestamp=none", app)
				mustRun(t, binaryPath, append(verify, app)...)
				if runtime.GOOS == "darwin" {
					mustRun(t, apple(t), "--verify", "--strict", "--deep", app)
				}
				archive := layoutArchive(t, app)
				if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
					bundleWrite(t, export, "signed-versions-"+identity+"-"+arch+".tar", archive)
				}
				attest(t, map[string]any{"architecture": arch, "identity": identity, "archive_sha256": hash(archive), "native_strict_deep_verified": runtime.GOOS == "darwin"})
			})
		}
	}
}

func TestAppleNestedFrameworkVersions(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mutation := range []string{"none", "unsigned", "cdhash", "requirement", "resource", "page", "info"} {
			t.Run(arch+"/"+mutation, func(t *testing.T) {
				app := filepath.Join(t.TempDir(), "Outer.app")
				bundleFixture(t, app, arch)
				b := frameworkVersionsFixture(t, filepath.Join(app, "Contents/Frameworks"), arch, "binary")
				if mutation == "unsigned" || mutation == "cdhash" {
					mustRun(t, binaryPath, "-s", "-", "--deep", app)
					if mutation == "cdhash" {
						mustRun(t, binaryPath, "-s", "-", "--bundle-version=A", b)
					}
				} else {
					signFrameworkVersions(t, binaryPath, b, "-")
					mustRun(t, binaryPath, "-s", "-", app)
				}
				switch mutation {
				case "requirement":
					mustRun(t, binaryPath, "-fs", "-", "-i", "org.example.wrong", "--bundle-version=A", b)
				case "resource":
					bundleWrite(t, b, "Versions/A/Resources/message.txt", []byte("modified"))
				case "page":
					data := nativeRead(t, filepath.Join(b, "Versions/A/Fixture"))
					// Change code without damaging the Mach-O structure in any slice.
					at := bytes.Index(data, []byte("fixture"))
					if at < 0 {
						t.Fatal("fixture marker missing")
					}
					data[at] ^= 1
					bundleWrite(t, b, "Versions/A/Fixture", data)
				case "info":
					data := nativeRead(t, filepath.Join(b, "Versions/A/Resources/Info.plist"))
					at := bytes.Index(data, []byte("org.example.layout"))
					if at < 0 {
						t.Fatal("identifier missing")
					}
					data[at] = 'x'
					bundleWrite(t, b, "Versions/A/Resources/Info.plist", data)
				}
				for _, deep := range []bool{false, true} {
					args := []string{"--verify"}
					if deep {
						args = append(args, "--deep")
					}
					_, ns, nc := run(t, reference, append(args, app)...)
					_, gs, gc := run(t, binaryPath, append(args, app)...)
					valid := mutation == "none" || !deep && (mutation == "page" || mutation == "resource")
					if (nc == 0) != valid || (gc == 0) != valid {
						t.Fatalf("deep=%v expected valid=%v Apple=%d %s Go=%d %s", deep, valid, nc, ns, gc, gs)
					}
					mustRun(t, reference, append(args, "--strict", b)...)
					mustRun(t, binaryPath, append(args, b)...)
				}
				attest(t, map[string]any{"architecture": arch, "mutation": mutation, "shallow_and_deep_match": true, "standalone_current_verified": true})
			})
		}
	}
}

func TestRecordAppleFrameworkVersions(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_RECORD_FRAMEWORK_VERSIONS") != "1" {
		t.Skip("explicit fixture recording only")
	}
	reference := apple(t)
	dir := filepath.Join(root, "testdata/framework-versions")
	hashes, inputs := map[string]string{}, map[string]string{}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		app := filepath.Join(t.TempDir(), "Outer.app")
		bundleFixture(t, app, arch)
		b := frameworkVersionsFixture(t, filepath.Join(app, "Contents/Frameworks"), arch, "binary")
		signFrameworkVersions(t, reference, b, "-")
		mustRun(t, reference, "-s", "-", app)
		mustRun(t, reference, "--verify", "--strict", "--deep", app)
		data := layoutArchive(t, app)
		name := arch + ".tar"
		bundleWrite(t, dir, name, data)
		hashes[name] = hash(data)
		for _, input := range []string{"testdata/macho/unsigned-" + arch, "testdata/nested/unsigned-" + arch + ".dylib"} {
			inputs[input] = hash(nativeRead(t, filepath.Join(root, input)))
		}
	}
	host, _, _ := run(t, "/usr/bin/sw_vers")
	record := map[string]any{"schema": 1, "files": hashes, "inputs": inputs, "host": strings.TrimSpace(host), "codesign_sha256": hash(nativeRead(t, reference)), "source": "acceptance/framework_versions_test.go: TestRecordAppleFrameworkVersions", "metadata": "binary framework Info.plist via pinned howett.net/plist; XML parent", "framework_sign_arguments": []string{"-s", "-", "--timestamp=none", "--bundle-version=<A|B>", "-r", frameworkRequirement, "<framework>"}, "parent_sign_arguments": []string{"-s", "-", "<app>"}, "native_strict_deep_verified": true, "archive": "deterministic POSIX tar preserving symlink targets"}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	bundleWrite(t, dir, "manifest.json", append(data, '\n'))
}

func TestNativeFrameworkVersionFixtures(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			data := nativeRead(t, filepath.Join(root, "testdata/framework-versions", arch+".tar"))
			app := filepath.Join(t.TempDir(), "Outer.app")
			extractLayout(t, data, app)
			mustRun(t, binaryPath, "--verify", "--deep", app)
			portable := filepath.Join(t.TempDir(), "Outer.app")
			bundleFixture(t, portable, arch)
			b := frameworkVersionsFixture(t, filepath.Join(portable, "Contents/Frameworks"), arch, "binary")
			signFrameworkVersions(t, binaryPath, b, "-")
			mustRun(t, binaryPath, "-s", "-", portable)
			nativeEqual(t, "native multi-version parent archive", layoutArchive(t, portable), data)
			attest(t, map[string]any{"architecture": arch, "native_fixture_bytes_equal": true, "archive_sha256": hash(data)})
		})
	}
}

func verifyFrameworkVersionsArchive(t *testing.T, reference, archive string) {
	t.Helper()
	app := filepath.Join(t.TempDir(), "Outer.app")
	extractLayout(t, nativeRead(t, archive), app)
	mustRun(t, reference, "--verify", "--strict", "--deep", app)
	for _, version := range []string{"A", "B"} {
		mustRun(t, reference, "--verify", "--strict", "--deep", "--bundle-version="+version, filepath.Join(app, "Contents/Frameworks/Fixture.framework"))
	}
	if strings.HasPrefix(filepath.Base(archive), "signed-paths-") {
		for _, version := range []string{"A", "B", "Current"} {
			mustRun(t, reference, "--verify", "--strict", "--deep", filepath.Join(app, "Contents/Frameworks/Fixture.framework/Versions", version))
		}
	}
}
