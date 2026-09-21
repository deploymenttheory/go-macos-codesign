package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Deny creation only in the test directory, retaining source read/traverse access.
func denyExecutableDirectoryCreation(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("icacls", path, "/deny", "*S-1-1-0:(AD,WD)").CombinedOutput(); err != nil {
			t.Fatalf("deny directory creation: %v: %s", err, out)
		}
		t.Cleanup(func() {
			if out, err := exec.Command("icacls", path, "/remove:d", "*S-1-1-0").CombinedOutput(); err != nil {
				t.Errorf("restore directory permissions: %v: %s", err, out)
			}
		})
	} else {
		if err := os.Chmod(path, 0555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0755) })
	}
	probe := filepath.Join(path, "permission-probe")
	if err := os.Mkdir(probe, 0700); !errors.Is(err, os.ErrPermission) {
		if err == nil {
			_ = os.Remove(probe)
			t.Skip("host bypasses directory creation denial")
		}
		t.Fatal(err)
	}
}

func TestExecutableDirectoryFailure(t *testing.T) {
	for _, shape := range []string{"standalone", "parent", "first-child", "last-child", "grandchild", "helper"} {
		for _, dry := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/dry=%t", shape, dry), func(t *testing.T) {
				ctx := context.Background()
				app := testBundle(t)
				apps := map[string]string{"main": app}
				paths := map[string]string{"main": filepath.Join(app, "Contents/MacOS/hello")}
				operand, bad := app, "main"
				if shape == "standalone" {
					app = t.TempDir()
					paths["main"] = filepath.Join(app, "tool")
					if err := os.WriteFile(paths["main"], fixture(t, "unsigned-arm64"), 0755); err != nil {
						t.Fatal(err)
					}
					operand = paths["main"]
				} else {
					for _, name := range []string{"A", "B"} {
						apps[name] = nestedApp(t, app, "Contents/PlugIns/"+name+".app")
						paths[name] = filepath.Join(apps[name], "Contents/MacOS/hello")
					}
				}
				switch shape {
				case "first-child":
					bad = "A"
				case "last-child":
					bad = "B"
				case "grandchild":
					bad = "C"
					apps[bad] = nestedApp(t, apps["A"], "Contents/PlugIns/C.app")
					paths[bad] = filepath.Join(apps[bad], "Contents/MacOS/hello")
				case "helper":
					bad = "helper"
					bundleFile(t, app, "Contents/Helpers/helper", fixture(t, "unsigned-arm64"))
					paths[bad] = filepath.Join(app, "Contents/Helpers/helper")
				}
				if err := Sign(ctx, operand, SignOptions{Deep: true}); err != nil {
					t.Fatal(err)
				}
				before, envelopes := map[string][]byte{}, map[string][]byte{}
				neighbours := map[string]string{}
				for name, path := range paths {
					before[name] = readTestFile(t, path)
					neighbours[name] = filepath.Join(t.TempDir(), "neighbour")
					if err := os.Link(path, neighbours[name]); err != nil {
						t.Fatal(err)
					}
				}
				if shape != "standalone" {
					for name, path := range apps {
						envelopes[name] = readTestFile(t, filepath.Join(path, bundleResourcesPath))
						bundleFile(t, path, "Contents/Resources/changed", []byte("changed resource"))
						bundleFile(t, path, "Contents/_CodeSignature/CodeDirectory", []byte("stale"))
					}
				}
				denyExecutableDirectoryCreation(t, filepath.Dir(paths[bad]))
				err := Sign(ctx, operand, SignOptions{Force: true, Deep: true, DryRun: dry})
				if !errors.Is(err, os.ErrPermission) || err.Error() == "" {
					t.Fatalf("allocation denial: %v", err)
				}
				for name, path := range paths {
					ancestor := name == "main" && bad != "main" || shape == "grandchild" && name == "A"
					replaced := !dry && name != bad && !ancestor
					after, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					neighbour, err := os.Stat(neighbours[name])
					if err != nil || os.SameFile(after, neighbour) == replaced {
						t.Fatalf("%s replacement=%t: %v", name, replaced, err)
					}
					if !bytes.Equal(readTestFile(t, neighbours[name]), before[name]) || !replaced && !bytes.Equal(readTestFile(t, path), before[name]) {
						t.Fatalf("uncommitted bytes changed: %s", name)
					}
					if app := apps[name]; app != "" && shape != "standalone" {
						envelope := readTestFile(t, filepath.Join(app, bundleResourcesPath))
						if bytes.Equal(envelope, envelopes[name]) != (dry || ancestor) {
							t.Fatalf("%s envelope commit order", name)
						}
						_, err := os.Stat(filepath.Join(app, "Contents/_CodeSignature/CodeDirectory"))
						if replaced && !errors.Is(err, os.ErrNotExist) || !replaced && err != nil {
							t.Fatalf("%s cleanup order: %v", name, err)
						}
					}
				}
				assertNoBundleStaging(t, app)
			})
		}
	}
}

func TestDryRunAllocationCancellation(t *testing.T) {
	for _, bundle := range []bool{false, true} {
		t.Run(fmt.Sprintf("bundle=%t", bundle), func(t *testing.T) {
			app := testBundle(t)
			path := filepath.Join(app, "Contents/MacOS/hello")
			neighbour := filepath.Join(t.TempDir(), "neighbour")
			if err := os.Link(path, neighbour); err != nil {
				t.Fatal(err)
			}
			before := readTestFile(t, path)
			ctx := &cancelBeforeRename{Context: context.Background()}
			var err error
			if bundle {
				b, openErr := openAppBundle(app)
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer b.close()
				err = applyBundleWrites(ctx, []bundleWrite{{name: b.executable, data: []byte("uncommitted"), bundle: b}}, true)
			} else {
				err = writeFile(ctx, path, []byte("uncommitted"), true)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			after, _ := os.Stat(path)
			other, _ := os.Stat(neighbour)
			if !os.SameFile(after, other) || !bytes.Equal(readTestFile(t, path), before) {
				t.Fatal("cancelled dry-run changed source")
			}
			assertNoBundleStaging(t, app)
		})
	}
}
