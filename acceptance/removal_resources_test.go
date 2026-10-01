package acceptance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

var removalResourceShapes = []string{"app-resource", "app-universal-resource", "framework-resource", "flat-framework-resource", "recursive-child-main", "recursive-child-resource", "recursive-grandchild-main", "recursive-grandchild-resource", "version-main", "version-resource"}

func removalResourceFixture(t *testing.T, dir, shape string) (string, map[string]string, string) {
	t.Helper()
	if strings.HasPrefix(shape, "version-") {
		operand := frameworkVersionsFixture(t, dir, "arm64", "xml")
		signFrameworkVersions(t, binaryPath, operand, "-")
		paths := map[string]string{"main": filepath.Join(operand, "Versions/B/Fixture"), "signature": filepath.Join(operand, "Versions/B/_CodeSignature/CodeResources")}
		target := filepath.Join(operand, "Versions/A/Fixture")
		if shape == "version-resource" {
			target = filepath.Join(operand, "Versions/A/Resources/message.txt")
		}
		return operand, paths, target
	}
	format, location, _ := strings.Cut(shape, "-")
	if strings.HasPrefix(shape, "app-universal-") {
		format, location = "app-universal", strings.TrimPrefix(shape, "app-universal-")
	}
	if strings.HasPrefix(shape, "flat-framework-") {
		format, location = "flat-framework", strings.TrimPrefix(shape, "flat-framework-")
	}
	operand, paths := sidebandBundleFixture(t, dir, format)
	return operand, paths, paths[location]
}

// A real data-read denial on an unrelated member must not deny shallow removal.
// Compare every code/resource byte with an independently unrestricted removal.
func TestRemovalUnreadableResources(t *testing.T) {
	for _, shape := range removalResourceShapes {
		t.Run(shape, func(t *testing.T) {
			dir := extractionDirectory(t)
			operand, _, _ := removalResourceFixture(t, dir, shape)
			wantOut, wantErr, wantStatus := run(t, binaryPath, "--remove-signature", operand)
			if wantStatus != 0 {
				t.Fatal(wantErr)
			}
			want := layoutArchive(t, operand)
			if err := os.RemoveAll(operand); err != nil {
				t.Fatal(err)
			}
			operand, paths, target := removalResourceFixture(t, dir, shape)
			before := layoutArchive(t, operand)
			targetBefore := nativeRead(t, target)
			original := accessFileInfo(t, target)
			restore, denied := denyRemovalDataRead(t, target)
			out, stderr, status := run(t, binaryPath, "--remove-signature", operand)
			restore()
			after := layoutArchive(t, operand)
			attest(t, map[string]any{"platform": runtime.GOOS, "operand": operand, "target": target, "denied_open": denied.Error(), "status": status, "stdout": out, "stderr": stderr, "before": hash(before), "after": hash(after), "control": hash(want)})
			if status != wantStatus || out != wantOut || stderr != wantErr {
				t.Fatalf("denied %d %q %q; control %d %q %q", status, out, stderr, wantStatus, wantOut, wantErr)
			}
			nativeEqual(t, "complete shallow removal", after, want)
			nativeEqual(t, "unrelated member", nativeRead(t, target), targetBefore)
			if !os.SameFile(original, accessFileInfo(t, target)) {
				t.Fatal("removal replaced unrelated member")
			}
			if _, err := os.Stat(paths["signature"]); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("outer envelope retained: %v", err)
			}
			if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
				bundleWrite(t, export, "shallow-removal-"+shape+".tar", after)
			}
		})
	}
}

// Native removal ignores unrelated layout restrictions imposed by signing.
func TestRemovalUnsealedMembers(t *testing.T) {
	for _, name := range []string{"extra", "Contents/Frameworks/F.unsupported/file", "Contents/CodeResources", "Contents/_CodeSignature/coderesources", "Contents/_MASReceipt/receipt"} {
		t.Run(name, func(t *testing.T) {
			dir := extractionDirectory(t)
			execute := func(exe string) []byte {
				operand, _, _ := removalResourceFixture(t, dir, "app-resource")
				bundleWrite(t, operand, name, []byte("unrelated member"))
				out, stderr, status := run(t, exe, "--remove-signature", operand)
				if status != 0 || out != "" || stderr != "" {
					t.Fatalf("%s removal %d %q %q", exe, status, out, stderr)
				}
				if !strings.HasPrefix(name, "Contents/_CodeSignature/") {
					nativeEqual(t, "unrelated layout member", nativeRead(t, filepath.Join(operand, name)), []byte("unrelated member"))
				}
				result := layoutArchive(t, operand)
				if err := os.RemoveAll(operand); err != nil {
					t.Fatal(err)
				}
				return result
			}
			got := execute(binaryPath)
			evidence := map[string]any{"go": hash(got)}
			if runtime.GOOS == "darwin" {
				want := execute(apple(t))
				nativeEqual(t, "unsealed removal", got, want)
				evidence["native"] = hash(want)
			}
			attest(t, evidence)
		})
	}
}

func denyRemovalDataRead(t *testing.T, target string) (func(), error) {
	t.Helper()
	original := accessFileInfo(t, target)
	restore := func() {}
	switch runtime.GOOS {
	case "darwin":
		mustRun(t, "/bin/chmod", "+a", "everyone deny read", target)
		restore = func() { mustRun(t, "/bin/chmod", "-N", target) }
	case "windows":
		mustRun(t, "icacls", target, "/deny", "*S-1-1-0:(RD)")
		restore = func() { mustRun(t, "icacls", target, "/remove:d", "*S-1-1-0") }
	case "linux":
		if err := os.Chmod(target, 0000); err != nil {
			t.Fatal(err)
		}
		restore = func() {
			if err := os.Chmod(target, original.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(restore)
	f, err := os.Open(target)
	if err == nil {
		f.Close()
		t.Fatal("resource denial is ineffective")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	return restore, err
}

func TestRemovalUnreadableExecutable(t *testing.T) {
	for _, shape := range []string{"standalone", "app", "framework", "recursive"} {
		t.Run(shape, func(t *testing.T) {
			dir := extractionDirectory(t)
			operand := filepath.Join(dir, "tool")
			target := operand
			if shape == "standalone" {
				copyFixture(t, "adhoc-universal", target)
			} else {
				var paths map[string]string
				operand, paths = sidebandBundleFixture(t, dir, shape)
				target = paths["main"]
			}
			before := signingSidebandBytes(t, operand, shape != "standalone")
			original := accessFileInfo(t, target)
			restore, denied := denyRemovalDataRead(t, target)
			// The public API must retain error identity as well as the CLI diagnostic.
			if err := codesign.RemoveSignature(context.Background(), operand); !errors.Is(err, os.ErrPermission) {
				t.Fatalf("lost permission cause: %v", err)
			}
			out, stderr, status := run(t, binaryPath, "--remove-signature", operand)
			restore()
			after := signingSidebandBytes(t, operand, shape != "standalone")
			attest(t, map[string]any{"platform": runtime.GOOS, "status": status, "stdout": out, "stderr": stderr, "denied_open": denied.Error(), "before": hash(before), "after": hash(after)})
			if status != 1 || out != "" || stderr != operand+": Permission denied\n" {
				t.Fatalf("failure: %d %q %q", status, out, stderr)
			}
			nativeEqual(t, "failed removal preserves operand", after, before)
			if !os.SameFile(original, accessFileInfo(t, target)) {
				t.Fatal("failed removal replaced executable")
			}
		})
	}
}

func verifyImportedRemovalResources(t *testing.T, dir, reference string) {
	t.Helper()
	expected := map[string][]byte{}
	for _, shape := range removalResourceShapes {
		operand, _, _ := removalResourceFixture(t, extractionDirectory(t), shape)
		mustRun(t, reference, "--remove-signature", operand)
		expected[shape] = layoutArchive(t, operand)
	}
	seen := map[string]int{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "shallow-removal-") {
			return nil
		}
		shape := strings.TrimSuffix(strings.TrimPrefix(d.Name(), "shallow-removal-"), ".tar")
		if expected[shape] == nil {
			t.Fatalf("unexpected shallow removal artifact: %s", path)
		}
		nativeEqual(t, "foreign shallow removal "+path, nativeRead(t, path), expected[shape])
		seen[shape]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range removalResourceShapes {
		if seen[shape] != 2 {
			t.Fatalf("expected Linux and Windows shallow removal artifacts for %s, got %d", shape, seen[shape])
		}
	}
	attest(t, map[string]any{"foreign_shallow_removal_cases": len(expected), "per_case_producers": seen})
}

func TestRemovalUnrelatedAliasesAndChildren(t *testing.T) {
	for _, kind := range []string{"malformed-child", "resource-symlink", "executable-hardlink", "envelope-hardlink"} {
		for _, deep := range []bool{false, true} {
			name := kind
			if deep {
				name += "/deep"
			}
			t.Run(name, func(t *testing.T) {
				dir := extractionDirectory(t)
				execute := func(exe string) []byte {
					operand, paths := sidebandBundleFixture(t, dir, "recursive")
					target := paths["child-resource"]
					if kind == "malformed-child" {
						bundleWrite(t, paths["child-root"], "Contents/Info.plist", []byte("invalid nested plist"))
					} else {
						if err := os.Remove(target); err != nil {
							t.Fatal(err)
						}
						switch kind {
						case "resource-symlink":
							outside := filepath.Join(dir, "outside-control")
							bundleWrite(t, dir, "outside-control", []byte("outside stays unchanged"))
							rel, err := filepath.Rel(filepath.Dir(target), outside)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.Symlink(rel, target); err != nil {
								t.Fatal(err)
							}
						case "executable-hardlink":
							if err := os.Link(paths["main"], target); err != nil {
								t.Fatal(err)
							}
						case "envelope-hardlink":
							// Darwin protects linking directly from a signature file.
							// Construct the same shared inode from the ordinary member,
							// as the existing envelope hard-link acceptance cases do.
							data := nativeRead(t, paths["signature"])
							if err := os.Remove(paths["signature"]); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(target, data, 0644); err != nil {
								t.Fatal(err)
							}
							if err := os.Link(target, paths["signature"]); err != nil {
								t.Fatal(err)
							}
						}
					}
					childBefore := layoutArchive(t, paths["child-root"])
					args := []string{"--remove-signature"}
					if deep {
						args = append(args, "--deep")
					}
					out, stderr, status := run(t, exe, append(args, operand)...)
					if status != 0 || out != "" || stderr != "" {
						t.Fatalf("%s removal: %d %q %q", exe, status, out, stderr)
					}
					nativeEqual(t, "unrelated child remains untouched", layoutArchive(t, paths["child-root"]), childBefore)
					if kind == "resource-symlink" {
						nativeEqual(t, "outside symlink target", nativeRead(t, filepath.Join(dir, "outside-control")), []byte("outside stays unchanged"))
					}
					result := layoutArchive(t, operand)
					if err := os.RemoveAll(operand); err != nil {
						t.Fatal(err)
					}
					return result
				}
				got := execute(binaryPath)
				evidence := map[string]any{"go": hash(got)}
				if runtime.GOOS == "darwin" {
					want := execute(apple(t))
					nativeEqual(t, "shallow aliases and children", got, want)
					evidence["native"] = hash(want)
				}
				attest(t, evidence)
			})
		}
	}
}
