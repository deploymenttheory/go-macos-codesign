package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
	"howett.net/plist"
)

var recursiveApps = []string{"", "Contents/Library/LoginItems/Login.app", "Contents/Library/LoginItems/Login.app/Contents/Helpers/Worker.app"}

func recursiveFixture(t *testing.T, app, arch, profile string) {
	t.Helper()
	for i, rel := range recursiveApps {
		child := filepath.Join(app, filepath.FromSlash(rel))
		if i == 2 {
			nestedFixture(t, child, arch)
		} else {
			bundleFixture(t, child, arch)
		}
		info := []byte(strings.ReplaceAll(bundleInfo, "org.example.bundle", fmt.Sprintf("org.example.level%d", i)))
		if profile == "mixed" && i == 1 {
			var values map[string]any
			if _, err := plist.Unmarshal(info, &values); err != nil {
				t.Fatal(err)
			}
			var err error
			info, err = plist.Marshal(values, plist.BinaryFormat)
			if err != nil {
				t.Fatal(err)
			}
		}
		bundleWrite(t, child, "Contents/Info.plist", info)
	}
}

func recursiveEqual(t *testing.T, got, want string) {
	t.Helper()
	for _, rel := range recursiveApps {
		for _, name := range []string{"Contents/Info.plist", "Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources"} {
			path := filepath.Join(filepath.FromSlash(rel), filepath.FromSlash(name))
			nativeEqual(t, path, nativeRead(t, filepath.Join(got, path)), nativeRead(t, filepath.Join(want, path)))
		}
	}
	for _, name := range nestedHelpers {
		path := filepath.Join(filepath.FromSlash(recursiveApps[2]), filepath.FromSlash(name))
		nativeEqual(t, path, nativeRead(t, filepath.Join(got, path)), nativeRead(t, filepath.Join(want, path)))
	}
}

func TestAppleNestedAppParity(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, profile := range []string{"xml", "mixed"} {
			for _, mode := range []string{"deep", "presigned", "override", "runtime"} {
				t.Run(arch+"/"+profile+"/"+mode, func(t *testing.T) {
					native, portable := filepath.Join(t.TempDir(), "Native.app"), filepath.Join(t.TempDir(), "Go.app")
					recursiveFixture(t, native, arch, profile)
					recursiveFixture(t, portable, arch, profile)
					args := []string{"-s", "-", "--timestamp=none"}
					if mode == "presigned" {
						for _, tc := range []struct{ program, app string }{{reference, native}, {binaryPath, portable}} {
							mustRun(t, tc.program, "-s", "-", "--deep", "-i", "org.example.preserved", filepath.Join(tc.app, filepath.FromSlash(recursiveApps[1])))
						}
					} else {
						args = append(args, "--deep")
					}
					if mode == "override" {
						args = append(args, "-i", "shared", `-r=designated => identifier shared`)
					}
					if mode == "runtime" {
						args = append(args, "-o", "runtime")
					}
					mustRun(t, reference, append(args, native)...)
					mustRun(t, binaryPath, append(args, portable)...)
					recursiveEqual(t, portable, native)
					mustRun(t, reference, "--verify", "--strict", "--deep", portable)
					mustRun(t, binaryPath, "--verify", "--deep", native)
					if mode == "deep" {
						for _, rel := range recursiveApps {
							nativeApp, goApp := filepath.Join(native, filepath.FromSlash(rel)), filepath.Join(portable, filepath.FromSlash(rel))
							for v := 0; v <= 4; v++ {
								flag := "-d" + strings.Repeat("v", v)
								_, want, wc := run(t, reference, flag, nativeApp)
								_, got, gc := run(t, binaryPath, flag, goApp)
								real, err := filepath.EvalSymlinks(filepath.Join(nativeApp, "Contents/MacOS/hello"))
								if err != nil {
									t.Fatal(err)
								}
								want = strings.ReplaceAll(want, real, "<executable>")
								goReal, err := filepath.EvalSymlinks(filepath.Join(goApp, "Contents/MacOS/hello"))
								if err != nil {
									t.Fatal(err)
								}
								got = strings.ReplaceAll(got, goReal, "<executable>")
								if got != want || gc != wc {
									t.Fatalf("display %s %s\nGo %s\nApple %s", rel, flag, got, want)
								}
							}
						}
					}
					attest(t, map[string]any{"architecture": arch, "profile": profile, "mode": mode, "bundles": 3, "mach_o_files": 6, "all_signature_and_envelope_bytes_equal": true, "native_deep_verified": true})
				})
			}
		}
	}
}

func TestPortableNestedApps(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, profile := range []string{"xml", "mixed"} {
			for _, identity := range []string{"adhoc", "rsa", "p256"} {
				t.Run(arch+"/"+profile+"/"+identity, func(t *testing.T) {
					app := filepath.Join(t.TempDir(), "Outer.app")
					recursiveFixture(t, app, arch, profile)
					id, verify := "-", []string{"--verify", "--deep"}
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
						if err := os.CopyFS(filepath.Join(export, "signed-bundle-recursive-"+profile+"-"+identity+"-"+arch+".app"), os.DirFS(app)); err != nil {
							t.Fatal(err)
						}
					}
					attest(t, map[string]any{"architecture": arch, "profile": profile, "identity": identity, "bundles": 3, "native_deep_verified": runtime.GOOS == "darwin"})
				})
			}
		}
	}
}

func TestNestedAppMutationParity(t *testing.T) {
	for _, change := range []string{"info", "resource", "envelope", "remove-envelope", "page", "missing-child", "added-child", "unsigned-child", "unsigned-grandchild", "grandchild-info", "grandchild-page", "valid-replacement", "wrong-identifier"} {
		t.Run(change, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "Outer.app")
			recursiveFixture(t, app, "arm64", "xml")
			mustRun(t, binaryPath, "-s", "-", "--deep", "-i", "shared", `-r=designated => identifier shared`, app)
			child, grand := filepath.Join(app, filepath.FromSlash(recursiveApps[1])), filepath.Join(app, filepath.FromSlash(recursiveApps[2]))
			switch change {
			case "info":
				p := filepath.Join(child, "Contents/Info.plist")
				bundleWrite(t, child, "Contents/Info.plist", bytes.ReplaceAll(nativeRead(t, p), []byte("org.example.level1"), []byte("org.example.modified")))
			case "resource":
				bundleWrite(t, child, "Contents/Resources/message.txt", []byte("changed"))
			case "envelope":
				bundleWrite(t, child, "Contents/_CodeSignature/CodeResources", []byte("malformed"))
			case "remove-envelope":
				if err := os.Remove(filepath.Join(child, "Contents/_CodeSignature/CodeResources")); err != nil {
					t.Fatal(err)
				}
			case "page", "grandchild-page":
				target := child
				if change == "grandchild-page" {
					target = grand
				}
				data := nativeRead(t, filepath.Join(target, "Contents/MacOS/hello"))
				data[4096] ^= 1
				bundleWrite(t, target, "Contents/MacOS/hello", data)
			case "missing-child":
				if err := os.RemoveAll(child); err != nil {
					t.Fatal(err)
				}
			case "added-child":
				bundleFixture(t, filepath.Join(app, "Contents/Helpers/Extra.app"), "arm64")
			case "unsigned-child":
				mustRun(t, binaryPath, "--remove-signature", child)
			case "unsigned-grandchild":
				mustRun(t, binaryPath, "--remove-signature", grand)
			case "grandchild-info":
				bundleWrite(t, grand, "Contents/Info.plist", []byte("malformed"))
			case "valid-replacement", "wrong-identifier":
				id := "shared"
				if change == "wrong-identifier" {
					id = "wrong"
				}
				mustRun(t, binaryPath, "-fs", "-", "--deep", "-i", id, "-r=designated => identifier "+id, "-o", "runtime", child)
			}
			for _, deep := range []bool{false, true} {
				valid := change == "valid-replacement" || !deep && (change == "resource" || change == "envelope" || change == "remove-envelope" || change == "page" || strings.HasPrefix(change, "grandchild-") || change == "unsigned-grandchild")
				args := []string{"--verify"}
				if deep {
					args = append(args, "--deep")
				}
				_, stderr, code := run(t, binaryPath, append(args, app)...)
				if (code == 0) != valid {
					t.Fatalf("Go deep=%v: %d %s", deep, code, stderr)
				}
				if runtime.GOOS == "darwin" {
					_, stderr, code = run(t, apple(t), append(args, "--strict", app)...)
					if (code == 0) != valid {
						t.Fatalf("Apple deep=%v: %d %s", deep, code, stderr)
					}
				}
			}
			attest(t, map[string]any{"mutation": change, "shallow_and_deep_checked": true, "native_checked": runtime.GOOS == "darwin"})
		})
	}
}

func TestShallowNestedMetadataParity(t *testing.T) {
	for _, slot := range []uint32{codesign.SlotRequirements, codesign.SlotEntitlements, codesign.SlotDEREntitlements} {
		t.Run(fmt.Sprint(slot), func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "Outer.app")
			nestedFixture(t, app, "arm64")
			mustRun(t, binaryPath, "-s", "-", "--deep", "-i", "shared", `-r=designated => identifier shared`, "--entitlements", filepath.Join(root, "testdata/entitlements.plist"), app)
			path := filepath.Join(app, nestedHelpers[0])
			data := nativeRead(t, path)
			r, err := codesign.InspectBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			for _, blob := range r.Architectures[0].Signature.Blobs {
				if blob.Slot == slot {
					p := bytes.Index(data, blob.Data)
					if p < 0 {
						t.Fatal("missing blob")
					}
					// Keep the framing; corrupt a signed payload byte.
					data[p+len(blob.Data)-2] ^= 1
					break
				}
			}
			bundleWrite(t, app, nestedHelpers[0], data)
			for _, deep := range []bool{false, true} {
				args := []string{"--verify"}
				if deep {
					args = append(args, "--deep")
				}
				if _, _, code := run(t, binaryPath, append(args, app)...); code == 0 {
					t.Fatal("Go accepted altered metadata")
				}
				if runtime.GOOS == "darwin" {
					if _, _, code := run(t, apple(t), append(args, "--strict", app)...); code == 0 {
						t.Fatal("Apple accepted altered metadata")
					}
				}
			}
		})
	}
}

func treeSnapshot(t *testing.T, app string) map[string]string {
	t.Helper()
	result := map[string]string{}
	if err := filepath.WalkDir(app, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(app, path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(rel)] = hash(nativeRead(t, path))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNestedAppLifecycle(t *testing.T) {
	for _, tool := range []string{"Go", "Apple"} {
		t.Run(tool, func(t *testing.T) {
			program := binaryPath
			if tool == "Apple" {
				program = apple(t)
			}
			app := filepath.Join(t.TempDir(), "Outer.app")
			recursiveFixture(t, app, "arm64", "mixed")
			before := treeSnapshot(t, app)
			if _, _, code := run(t, program, "-s", "-", "--deep", "--dryrun", app); code == 0 {
				t.Fatal("dryrun accepted unsigned child")
			}
			if !reflect.DeepEqual(before, treeSnapshot(t, app)) {
				t.Fatal("dryrun modified the tree")
			}
			grand := filepath.Join(app, filepath.FromSlash(recursiveApps[2]))
			mustRun(t, program, "-s", "-", "--deep", "-i", "keep", grand)
			preserved := treeSnapshot(t, grand)
			mustRun(t, program, "-s", "-", "--deep", app)
			if !reflect.DeepEqual(preserved, treeSnapshot(t, grand)) {
				t.Fatal("signed grandchild was replaced without force")
			}
			before = treeSnapshot(t, app)
			mustRun(t, program, "-fs", "-", "--deep", "--dryrun", "-i", "dryrun", app)
			if !reflect.DeepEqual(before, treeSnapshot(t, app)) {
				t.Fatal("signed dryrun modified tree")
			}
			mustRun(t, program, "-fs", "-", "--deep", "-i", "replacement", app)
			if reflect.DeepEqual(preserved, treeSnapshot(t, grand)) {
				t.Fatal("force retained grandchild")
			}
			preserved = treeSnapshot(t, grand)
			mustRun(t, program, "--remove-signature", "--deep", app)
			if !reflect.DeepEqual(preserved, treeSnapshot(t, grand)) {
				t.Fatal("removal changed descendants")
			}
			mustRun(t, program, "--verify", "--deep", filepath.Join(app, filepath.FromSlash(recursiveApps[1])))
			attest(t, map[string]any{"tool": tool, "unsigned_dryrun_rejected_without_mutation": true, "signed_dryrun_preserved": true, "grandchild_preserved_without_force": true, "force_replaces_descendants": true, "removal_preserves_descendants": true})
		})
	}
}

func TestRecordAppleNestedAppFixtures(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_RECORD_NESTED_APPS") != "1" {
		t.Skip("opt-in native recursive app recording")
	}
	reference := apple(t)
	dir := filepath.Join(root, "testdata/nested-apps")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "README.md" {
			t.Fatal("refusing to overwrite fixture directory", entry.Name())
		}
	}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		app := filepath.Join(t.TempDir(), "Outer.app")
		recursiveFixture(t, app, arch, "mixed")
		mustRun(t, reference, "-s", "-", "--deep", "--timestamp=none", app)
		mustRun(t, reference, "--verify", "--strict", "--deep", app)
		if err := os.CopyFS(filepath.Join(dir, arch+".app"), os.DirFS(app)); err != nil {
			t.Fatal(err)
		}
	}
	hashes := treeSnapshot(t, dir)
	delete(hashes, "README.md")
	host, stderr, code := run(t, "/usr/bin/sw_vers")
	if code != 0 {
		t.Fatal(stderr)
	}
	manifest := map[string]any{"schema": 1, "files": hashes, "host": strings.TrimSpace(host), "codesign_sha256": hash(nativeRead(t, reference)), "source": "acceptance/nested_app_test.go: TestRecordAppleNestedAppFixtures", "metadata": "XML parent/grandchild; binary child encoded by pinned howett.net/plist", "sign_arguments": []string{"-s", "-", "--deep", "--timestamp=none", "<outer-app>"}, "verify_arguments": []string{"--verify", "--strict", "--deep", "<outer-app>"}, "apps_per_fixture": 3, "mach_o_files_per_fixture": 6, "native_deep_strict_verified": true}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestNativeNestedAppFixtures(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			fixture := filepath.Join(root, "testdata/nested-apps", arch+".app")
			mustRun(t, binaryPath, "--verify", "--deep", fixture)
			app := filepath.Join(t.TempDir(), "Outer.app")
			recursiveFixture(t, app, arch, "mixed")
			mustRun(t, binaryPath, "-s", "-", "--deep", app)
			recursiveEqual(t, app, fixture)
			attest(t, map[string]any{"architecture": arch, "apps": 3, "native_fixture_bytes_equal": true})
		})
	}
}

func TestRecursiveAppTimestamps(t *testing.T) {
	server, ca, requests, mode := localTimestampAuthority(t)
	app := filepath.Join(t.TempDir(), "Outer.app")
	recursiveFixture(t, app, "universal", "mixed")
	id, cert := filepath.Join(root, "testdata/identities/rsa-identity.pem"), filepath.Join(root, "testdata/identities/rsa-cert.pem")
	args := []string{"-fs", id, "--deep", "--timestamp=" + server.URL, "--timestamp-root", ca}
	mustRun(t, binaryPath, append(args, app)...)
	if requests.Load() != 12 {
		t.Fatal("expected a timestamp per architecture in all six Mach-O files", requests.Load())
	}
	mustRun(t, binaryPath, "--verify", "--deep", "--trust", cert, "--timestamp-root", ca, app)
	// An ad-hoc outer signature must not bypass the children's separate TSA trust.
	mustRun(t, binaryPath, "-fs", "-", app)
	if _, _, code := run(t, binaryPath, "--verify", "--deep", "--trust", cert, app); code == 0 {
		t.Fatal("missing child TSA roots accepted")
	}
	mustRun(t, binaryPath, "--verify", "--deep", "--trust", cert, "--timestamp-root", ca, app)
	before, count := treeSnapshot(t, app), requests.Load()
	mustRun(t, binaryPath, append(append([]string{}, args...), "--dryrun", app)...)
	if requests.Load()-count != 12 || !reflect.DeepEqual(before, treeSnapshot(t, app)) {
		t.Fatal("timestamp dryrun did not construct all signatures or mutated files")
	}
	// Thin children make the first response complete an entire child signature
	// before the second child's TSA request fails.
	failed := filepath.Join(t.TempDir(), "Failed.app")
	recursiveFixture(t, failed, "arm64", "mixed")
	before = treeSnapshot(t, failed)
	mode.Store("second")
	count = requests.Load()
	if _, _, code := run(t, binaryPath, append(args, failed)...); code == 0 {
		t.Fatal("late TSA failure accepted")
	}
	if requests.Load()-count != 2 || !reflect.DeepEqual(before, treeSnapshot(t, failed)) {
		t.Fatal("failure after first TSA response did not preserve the complete tree")
	}
	attest(t, map[string]any{"local_independent_tsa": true, "timestamps_per_tree": 12, "child_tsa_trust_required": true, "dryrun_preserved_tree": true, "late_tsa_failure_preserved_tree": true})
}
