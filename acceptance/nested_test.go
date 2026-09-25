package acceptance

import (
	"bytes"
	"debug/macho"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"howett.net/plist"
)

var nestedHelpers = []string{"Contents/MacOS/helper", "Contents/Helpers/group/tool", "Contents/Frameworks/libfixture.dylib"}

func nestedFixture(t *testing.T, app, arch string) {
	t.Helper()
	bundleFixture(t, app, arch)
	for _, name := range nestedHelpers {
		input := "testdata/macho/unsigned-" + arch
		if strings.HasSuffix(name, ".dylib") {
			input = "testdata/nested/unsigned-" + arch + ".dylib"
		}
		bundleWrite(t, app, name, nativeRead(t, filepath.Join(root, input)))
	}
}

func TestRecordAppleNestedFixtures(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_RECORD_NESTED") != "1" {
		t.Skip("opt-in native nested code recording")
	}
	reference := apple(t)
	dir := filepath.Join(root, "testdata/nested")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "README.md" && entry.Name() != "library.c" {
			t.Fatal("refusing to overwrite fixture directory", entry.Name())
		}
	}
	compiler, stderr, code := run(t, "xcrun", "--find", "clang")
	if code != 0 {
		t.Fatal(stderr)
	}
	compiler = strings.TrimSpace(compiler)
	sdk, stderr, code := run(t, "xcrun", "--show-sdk-path")
	if code != 0 {
		t.Fatal(stderr)
	}
	sdk = strings.TrimSpace(sdk)
	version, _, _ := run(t, compiler, "--version")
	for _, arch := range []string{"arm64", "x86_64"} {
		mustRun(t, compiler, "-isysroot", sdk, "-arch", arch, "-dynamiclib", "-Wl,-no_adhoc_codesign", "-Wl,-headerpad,0x1000", "-Wl,-install_name,@rpath/libfixture.dylib", "-o", filepath.Join(dir, "unsigned-"+arch+".dylib"), filepath.Join(dir, "library.c"))
	}
	mustRun(t, "xcrun", "lipo", "-create", filepath.Join(dir, "unsigned-arm64.dylib"), filepath.Join(dir, "unsigned-x86_64.dylib"), "-output", filepath.Join(dir, "unsigned-universal.dylib"))
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		app := filepath.Join(t.TempDir(), "Nested.app")
		nestedFixture(t, app, arch)
		mustRun(t, reference, "-s", "-", "--deep", "--timestamp=none", app)
		mustRun(t, reference, "--verify", "--strict", "--deep", app)
		if err := os.CopyFS(filepath.Join(dir, arch+".app"), os.DirFS(app)); err != nil {
			t.Fatal(err)
		}
	}
	hashes := map[string]string{}
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() == "README.md" {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hashes[filepath.ToSlash(rel)] = hash(nativeRead(t, path))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := run(t, "/usr/bin/sw_vers")
	manifest := map[string]any{"schema": 1, "files": hashes, "host": strings.TrimSpace(host), "codesign_sha256": hash(nativeRead(t, reference)), "compiler": strings.TrimSpace(version), "compiler_sha256": hash(nativeRead(t, compiler)), "source": "acceptance/nested_test.go: TestRecordAppleNestedFixtures", "compile_arguments": []string{"-arch", "<architecture>", "-dynamiclib", "-Wl,-no_adhoc_codesign", "-Wl,-headerpad,0x1000", "-Wl,-install_name,@rpath/libfixture.dylib", "-o", "<output>", "library.c"}, "universal_arguments": []string{"lipo", "-create", "unsigned-arm64.dylib", "unsigned-x86_64.dylib", "-output", "unsigned-universal.dylib"}, "sign_arguments": []string{"-s", "-", "--deep", "--timestamp=none", "<bundle>"}, "verify_arguments": []string{"--verify", "--strict", "--deep", "<bundle>"}, "native_deep_strict_verified": true}
	manifest["sdk"] = sdk
	manifest["compile_arguments"] = append([]string{"-isysroot", "<sdk>"}, manifest["compile_arguments"].([]string)...)
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestNativeNestedFixtures(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			fixture := filepath.Join(root, "testdata/nested", arch+".app")
			mustRun(t, binaryPath, "--verify", "--deep", fixture)
			app := filepath.Join(t.TempDir(), "Nested.app")
			nestedFixture(t, app, arch)
			mustRun(t, binaryPath, "-s", "-", "--deep", app)
			for _, name := range append([]string{"Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources"}, nestedHelpers...) {
				nativeEqual(t, name, nativeRead(t, filepath.Join(app, name)), nativeRead(t, filepath.Join(fixture, name)))
			}
			attest(t, map[string]any{"architecture": arch, "native_fixture_bytes_equal": true, "nested_files": len(nestedHelpers)})
		})
	}
}

func TestAppleNestedParity(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mode := range []string{"presigned", "deep", "explicit", "override", "runtime"} {
			t.Run(arch+"/"+mode, func(t *testing.T) {
				native, portable := filepath.Join(t.TempDir(), "Native.app"), filepath.Join(t.TempDir(), "Go.app")
				nestedFixture(t, native, arch)
				nestedFixture(t, portable, arch)
				args := []string{"-s", "-", "--timestamp=none"}
				if mode == "presigned" {
					for _, helper := range nestedHelpers {
						mustRun(t, reference, append(args, filepath.Join(native, helper))...)
						mustRun(t, binaryPath, append(args, filepath.Join(portable, helper))...)
					}
				} else {
					args = append(args, "--deep")
				}
				if mode == "explicit" {
					args = append(args, `-r=designated => identifier "shared"`, "-i", "shared")
				}
				if mode == "override" {
					args = append(args, "-i", "org.example.override")
				}
				if mode == "runtime" {
					args = append(args, "-o", "runtime")
				}
				mustRun(t, reference, append(args, native)...)
				mustRun(t, binaryPath, append(args, portable)...)
				for _, name := range append([]string{"Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources"}, nestedHelpers...) {
					nativeEqual(t, name, nativeRead(t, filepath.Join(portable, name)), nativeRead(t, filepath.Join(native, name)))
				}
				mustRun(t, reference, "--verify", "--strict", "--deep", portable)
				mustRun(t, binaryPath, "--verify", "--deep", native)
				for v := 0; v <= 4; v++ {
					flag := "-d" + strings.Repeat("v", v)
					_, want, wc := run(t, reference, flag, native)
					_, got, gc := run(t, binaryPath, flag, portable)
					real, err := filepath.EvalSymlinks(filepath.Join(native, "Contents/MacOS/hello"))
					if err != nil {
						t.Fatal(err)
					}
					want = strings.ReplaceAll(want, real, "<executable>")
					portablePath, err := filepath.EvalSymlinks(filepath.Join(portable, "Contents/MacOS/hello"))
					if err != nil {
						t.Fatal(err)
					}
					got = strings.ReplaceAll(got, portablePath, "<executable>")
					if got != want || gc != wc {
						t.Fatalf("display %s\nGo:\n%s\nApple:\n%s", flag, got, want)
					}
				}
				attest(t, map[string]any{"architecture": arch, "mode": mode, "nested_executable_bytes_equal": true, "parent_executable_bytes_equal": true, "resource_envelope_bytes_equal": true, "display_levels": 5, "native_deep_verified": true})
			})
		}
	}
}

func TestPortableNestedBundles(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, identity := range []string{"adhoc", "rsa", "p256"} {
			t.Run(arch+"/"+identity, func(t *testing.T) {
				app := filepath.Join(t.TempDir(), "Nested.app")
				nestedFixture(t, app, arch)
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
					if err := os.CopyFS(filepath.Join(export, "signed-bundle-nested-"+identity+"-"+arch+".app"), os.DirFS(app)); err != nil {
						t.Fatal(err)
					}
				}
				attest(t, map[string]any{"architecture": arch, "identity": identity, "nested_files": len(nestedHelpers), "native_deep_verified": runtime.GOOS == "darwin"})
			})
		}
	}
}

func TestNestedMutationParity(t *testing.T) {
	for _, change := range []string{"page", "missing", "added", "unsigned", "wrong-identifier", "valid-replacement"} {
		t.Run(change, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "Nested.app")
			nestedFixture(t, app, "arm64")
			mustRun(t, binaryPath, "-s", "-", "--deep", "-i", "org.example.child", `-r=designated => identifier "org.example.child"`, app)
			helper := filepath.Join(app, nestedHelpers[0])
			data := nativeRead(t, helper)
			switch change {
			case "page":
				data[4096] ^= 1
				bundleWrite(t, app, nestedHelpers[0], data)
			case "missing":
				if err := os.Remove(helper); err != nil {
					t.Fatal(err)
				}
			case "added":
				bundleWrite(t, app, "Contents/Helpers/extra", data)
			case "unsigned":
				bundleWrite(t, app, nestedHelpers[0], nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-arm64")))
			case "wrong-identifier":
				mustRun(t, binaryPath, "-fs", "-", "-i", "changed", helper)
			case "valid-replacement":
				mustRun(t, binaryPath, "-fs", "-", "-i", "org.example.child", "-o", "runtime", helper)
			}
			for _, deep := range []bool{false, true} {
				valid := change == "valid-replacement" || change == "page" && !deep
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

func TestNestedSigningLifecycle(t *testing.T) {
	for _, tool := range []string{"Go", "Apple"} {
		t.Run(tool, func(t *testing.T) {
			program := binaryPath
			if tool == "Apple" {
				program = apple(t)
			}
			app := filepath.Join(t.TempDir(), "Nested.app")
			nestedFixture(t, app, "arm64")
			before := nativeRead(t, filepath.Join(app, nestedHelpers[0]))
			if _, _, code := run(t, program, "-s", "-", app); code == 0 {
				t.Fatal("sealed unsigned child")
			}
			if _, _, code := run(t, program, "-s", "-", "--deep", "--dryrun", app); code == 0 {
				t.Fatal("dryrun sealed unsigned on-disk child")
			}
			nativeEqual(t, "dryrun child", nativeRead(t, filepath.Join(app, nestedHelpers[0])), before)
			if _, err := os.Stat(filepath.Join(app, "Contents/_CodeSignature")); !os.IsNotExist(err) {
				t.Fatal("dryrun created signature directory", err)
			}
			mustRun(t, program, "-s", "-", filepath.Join(app, nestedHelpers[0]))
			signed := nativeRead(t, filepath.Join(app, nestedHelpers[0]))
			mustRun(t, program, "-s", "-", "--deep", "-i", "override", app)
			nativeEqual(t, "preserved signed child", nativeRead(t, filepath.Join(app, nestedHelpers[0])), signed)
			mustRun(t, program, "-fs", "-", "--deep", "-i", "replacement", app)
			if bytes.Equal(nativeRead(t, filepath.Join(app, nestedHelpers[0])), signed) {
				t.Fatal("force did not replace child")
			}
			signed = nativeRead(t, filepath.Join(app, nestedHelpers[0]))
			parent := nativeRead(t, filepath.Join(app, "Contents/MacOS/hello"))
			mustRun(t, program, "-s", "-", "--deep", "--force", "--dryrun", "-i", "dryrun", app)
			nativeEqual(t, "signed dryrun child", nativeRead(t, filepath.Join(app, nestedHelpers[0])), signed)
			nativeEqual(t, "signed dryrun parent", nativeRead(t, filepath.Join(app, "Contents/MacOS/hello")), parent)
			mustRun(t, program, "--remove-signature", "--deep", app)
			mustRun(t, program, "--verify", filepath.Join(app, nestedHelpers[0]))
			attest(t, map[string]any{"tool": tool, "unsigned_child_rejected": true, "dryrun_preserved": true, "existing_child_preserved": true, "force_replaces_child": true, "removal_preserves_child": true})
		})
	}
}

func TestNativeNestedSealRequirements(t *testing.T) {
	// A certificate child's canonical DR is checked against Apple's independent
	// dumper. No private keychain or native trust configuration is needed.
	for _, identity := range []string{"rsa", "p256"} {
		t.Run(identity, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "Nested.app")
			nestedFixture(t, app, "universal")
			mustRun(t, binaryPath, "-s", filepath.Join(root, "testdata/identities/"+identity+"-identity.pem"), "--deep", "--timestamp=none", app)
			var resources struct {
				Files map[string]struct {
					Requirement string `plist:"requirement"`
				} `plist:"files2"`
			}
			if _, err := plist.Unmarshal(nativeRead(t, filepath.Join(app, "Contents/_CodeSignature/CodeResources")), &resources); err != nil {
				t.Fatal(err)
			}
			for _, helper := range nestedHelpers {
				out, err, code := run(t, apple(t), "-d", "-r-", filepath.Join(app, helper))
				if code != 0 {
					t.Fatal(out, err)
				}
				want := resources.Files[strings.TrimPrefix(helper, "Contents/")].Requirement
				if want == "" || !strings.Contains(out+err, "designated => "+want+"\n") {
					t.Fatalf("seal %q differs from native designated requirement: %s %s", want, out, err)
				}
			}
		})
	}
}

func TestAppleDefaultMachOIdentifiers(t *testing.T) {
	reference := apple(t)
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, name := range []string{"helper", "libfrotz7.3.5.dylib", "mumble.77.plugin", "org.example.tool", "17"} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				native, portable := filepath.Join(t.TempDir(), name), filepath.Join(t.TempDir(), name)
				copyFixture(t, "unsigned-"+arch, native)
				copyFixture(t, "unsigned-"+arch, portable)
				mustRun(t, reference, "-s", "-", native)
				mustRun(t, binaryPath, "-s", "-", portable)
				nativeEqual(t, "default identifier", nativeRead(t, portable), nativeRead(t, native))
			})
		}
		if arch == "universal" {
			continue
		}
		t.Run(arch+"/no-uuid", func(t *testing.T) {
			data := nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+arch))
			f, err := macho.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			pos := 32
			for _, load := range f.Loads {
				raw := load.Raw()
				if f.ByteOrder.Uint32(raw) == 0x1b {
					end := 32 + int(f.Cmdsz)
					copy(data[pos:end], data[pos+len(raw):end])
					clear(data[end-len(raw) : end])
					f.ByteOrder.PutUint32(data[16:], f.Ncmd-1)
					f.ByteOrder.PutUint32(data[20:], f.Cmdsz-uint32(len(raw)))
					break
				}
				pos += len(raw)
			}
			native, portable := filepath.Join(t.TempDir(), "helper"), filepath.Join(t.TempDir(), "helper")
			for _, p := range []string{native, portable} {
				if err := os.WriteFile(p, data, 0755); err != nil {
					t.Fatal(err)
				}
			}
			mustRun(t, reference, "-s", "-", native)
			mustRun(t, binaryPath, "-s", "-", portable)
			nativeEqual(t, "load command fallback", nativeRead(t, portable), nativeRead(t, native))
		})
	}
	attest(t, map[string]any{"default_identifiers_byte_equal": 15, "no_uuid_fallback_byte_equal": 2})
}

func TestAppleNestedRequirementFormatting(t *testing.T) {
	reference := apple(t)
	for _, req := range []string{`always`, `never`, `identifier "123"`, `identifier "true"`, `identifier "é"`, `identifier "a\"b\\c"`, `! (always or never) and (never or always)`, `certificate leaf[subject.CN] = "Test CA"`, `certificate 1[field.1.2.840.113635.100.6.2.6] exists`, `anchor apple generic or certificate root = H"0000000000000000000000000000000000000000"`} {
		t.Run(req, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "Nested.app")
			nestedFixture(t, app, "arm64")
			mustRun(t, binaryPath, "-s", "-", "--deep", "-r=designated => "+req, app)
			var envelope map[string]any
			if _, err := plist.Unmarshal(nativeRead(t, filepath.Join(app, "Contents/_CodeSignature/CodeResources")), &envelope); err != nil {
				t.Fatal(err)
			}
			seal := envelope["files2"].(map[string]any)["MacOS/helper"].(map[string]any)["requirement"].(string)
			out, stderr, code := run(t, reference, "-d", "-r-", filepath.Join(app, nestedHelpers[0]))
			if code != 0 || !strings.Contains(out+stderr, "designated => "+seal+"\n") {
				t.Fatalf("Go %q\nApple %s %s", seal, out, stderr)
			}
		})
	}
}
