package acceptance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnsignedNestedDryRun(t *testing.T) {
	for _, shape := range []string{"helper", "child", "grandchild"} {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, profile := range []string{"past", "future"} {
				for _, operation := range []string{"deep", "force", "shallow", "denied"} {
					t.Run(shape+"/"+arch+"/"+profile+"/"+operation, func(t *testing.T) {
						execute := func(exe string) ([]byte, map[string]any) {
							t.Helper()
							dir := t.TempDir()
							app := filepath.Join(dir, "Example.app")
							bundleFixture(t, app, arch)
							paths := []string{filepath.Join(app, "Contents/MacOS/hello")}
							if shape == "helper" {
								bundleWrite(t, app, "Contents/Helpers/tool", nativeRead(t, paths[0]))
								paths = append(paths, filepath.Join(app, "Contents/Helpers/tool"))
							} else {
								child := filepath.Join(app, "Contents/PlugIns/Child.app")
								bundleFixture(t, child, arch)
								paths = append(paths, filepath.Join(child, "Contents/MacOS/hello"))
								if shape == "grandchild" {
									grand := filepath.Join(child, "Contents/PlugIns/Grand.app")
									bundleFixture(t, grand, arch)
									paths = append(paths, filepath.Join(grand, "Contents/MacOS/hello"))
								}
							}
							if operation == "denied" {
								parent := filepath.Dir(paths[len(paths)-1])
								if err := os.Chmod(parent, 0555); err != nil {
									t.Fatal(err)
								}
								t.Cleanup(func() { _ = os.Chmod(parent, 0755) })
								probe := filepath.Join(parent, "probe")
								if err := os.Mkdir(probe, 0700); !errors.Is(err, os.ErrPermission) {
									if err == nil {
										_ = os.Remove(probe)
										t.Skip("host bypasses directory permissions")
									}
									t.Fatal(err)
								}
							}
							before := layoutArchive(t, app)
							seed := time.Unix(978307200, 234567890)
							if profile == "future" {
								seed = time.Now().Add(48 * time.Hour)
							}
							originals := make([]os.FileInfo, len(paths))
							neighbours := make([]string, len(paths))
							for i, path := range paths {
								neighbours[i] = filepath.Join(dir, fmt.Sprintf("neighbour-%d", i))
								if err := os.Link(path, neighbours[i]); err != nil {
									t.Fatal(err)
								}
								if err := os.Chtimes(path, seed, time.Unix(946684800, 123456789)); err != nil {
									t.Fatal(err)
								}
								var err error
								originals[i], err = os.Stat(path)
								if err != nil {
									t.Fatal(err)
								}
							}
							args := []string{"-s", "-", "--timestamp=none", "--dryrun"}
							if operation != "shallow" {
								args = append(args, "--deep")
							}
							if operation == "force" {
								args = append(args, "--force")
							}
							started := time.Now()
							stdout, stderr, status := run(t, exe, append(args, app)...)
							finished := time.Now()
							if status != 1 {
								t.Fatalf("%s: exit %d\n%s\n%s", exe, status, stdout, stderr)
							}
							effects := map[string]any{}
							for i, path := range paths {
								after, err := os.Stat(path)
								if err != nil {
									t.Fatal(err)
								}
								other, err := os.Stat(neighbours[i])
								if err != nil {
									t.Fatal(err)
								}
								accessed := i == len(paths)-1 && operation != "shallow"
								for _, info := range []os.FileInfo{after, other} {
									at := writerAccess(info)
									if accessed {
										if at.Before(started) || at.After(finished) {
											t.Fatalf("%s %s access outside operation", exe, path)
										}
									} else if !at.Equal(writerAccess(originals[i])) {
										t.Fatalf("%s untouched access: %s", exe, path)
									}
									if !os.SameFile(originals[i], info) || !info.ModTime().Equal(originals[i].ModTime()) || !writerBirth(info).Equal(writerBirth(originals[i])) || info.Mode() != originals[i].Mode() {
										t.Fatal("dry run changed executable identity or metadata")
									}
								}
								effects[filepath.ToSlash(strings.TrimPrefix(path, app+string(os.PathSeparator)))] = map[string]any{"accessed": accessed, "before": writerAccess(originals[i]), "after": writerAccess(after), "neighbour": writerAccess(other), "inode_preserved": true}
							}
							for i, path := range paths {
								nativeEqual(t, "hard-link bytes", nativeRead(t, neighbours[i]), nativeRead(t, path))
							}
							after := layoutArchive(t, app)
							nativeEqual(t, "unchanged dry-run tree", after, before)
							if err := filepath.WalkDir(app, func(path string, d os.DirEntry, err error) error {
								if err == nil && (strings.HasPrefix(d.Name(), ".apfs-replacement-") || strings.HasSuffix(d.Name(), ".cstemp")) {
									return fmt.Errorf("staging leaked: %s", path)
								}
								return err
							}); err != nil {
								t.Fatal(err)
							}
							return after, map[string]any{"argv": append(args, app), "stdout": stdout, "stderr": stderr, "exit": status, "started": started, "finished": finished, "tree_sha256": hash(after), "executables": effects, "staging_removed": true}
						}
						want, native := execute(apple(t))
						got, record := execute(binaryPath)
						nativeEqual(t, "complete dry-run tree", got, want)
						attest(t, map[string]any{"shape": shape, "architecture": arch, "profile": profile, "operation": operation, "native_compared": true, "native": native, "go": record})
					})
				}
			}
		}
	}
}
