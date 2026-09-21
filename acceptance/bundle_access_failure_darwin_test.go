package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBundleAccessFailureBoundaries(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, profile := range []string{"past", "future"} {
			for _, failure := range []string{"parent-envelope", "child-envelope", "parent-cleanup", "child-cleanup", "unsigned-dryrun", "unsigned-shallow"} {
				t.Run(arch+"/"+profile+"/"+failure, func(t *testing.T) {
					execute := func(exe string) ([]byte, map[string]any) {
						t.Helper()
						dir := t.TempDir()
						app := filepath.Join(dir, "Example.app")
						child := filepath.Join(app, "Contents/PlugIns/Child.app")
						bundleFixture(t, app, arch)
						bundleFixture(t, child, arch)
						mustRun(t, exe, "-fs", "-", "--deep", "--timestamp=none", app)
						apps := map[string]string{"main": app, "child": child}
						for _, path := range apps {
							bundleWrite(t, path, "Contents/Resources/message.txt", []byte("changed resource\n"))
						}
						bad := app
						if strings.HasPrefix(failure, "child-") {
							bad = child
						}
						switch {
						case strings.HasSuffix(failure, "envelope"):
							path := filepath.Join(bad, "Contents/_CodeSignature/CodeResources")
							if err := os.Remove(path); err != nil {
								t.Fatal(err)
							}
							if err := os.Mkdir(path, 0755); err != nil {
								t.Fatal(err)
							}
						case strings.HasSuffix(failure, "cleanup"):
							if err := os.Mkdir(filepath.Join(bad, "Contents/_CodeSignature/stale"), 0755); err != nil {
								t.Fatal(err)
							}
						default:
							mustRun(t, exe, "--remove-signature", child)
						}
						paths, neighbours := map[string]string{}, map[string]string{}
						originals := map[string]os.FileInfo{}
						originalBytes := map[string][]byte{}
						for name, path := range apps {
							paths[name] = filepath.Join(path, "Contents/MacOS/hello")
							neighbours[name] = filepath.Join(dir, name+"-neighbour")
							if err := os.Link(paths[name], neighbours[name]); err != nil {
								t.Fatal(err)
							}
							originalBytes[name] = nativeRead(t, paths[name])
						}
						before := layoutArchive(t, app)
						seed := time.Unix(978307200, 234567890)
						if profile == "future" {
							seed = time.Now().Add(48 * time.Hour)
						}
						for name, path := range paths {
							if err := os.Chtimes(path, seed, time.Unix(946684800, 123456789)); err != nil {
								t.Fatal(err)
							}
							st, err := os.Stat(path)
							if err != nil {
								t.Fatal(err)
							}
							originals[name] = st
						}
						args := []string{"-fs", "-", "--timestamp=none"}
						if failure != "unsigned-shallow" {
							args = append(args, "--deep")
						}
						if failure == "unsigned-dryrun" {
							args = append(args, "--dryrun")
						}
						started := time.Now()
						stdout, stderr, status := run(t, exe, append(args, app)...)
						finished := time.Now()
						if status != 1 {
							t.Fatalf("%s %v: exit %d\n%s\n%s", exe, args, status, stdout, stderr)
						}
						effects := map[string]any{}
						for name, path := range paths {
							after, err := os.Stat(path)
							if err != nil {
								t.Fatal(err)
							}
							other, err := os.Stat(neighbours[name])
							if err != nil {
								t.Fatal(err)
							}
							nativeAccess := failure == "parent-cleanup" || name == "child" && failure != "child-envelope" && failure != "unsigned-shallow"
							goAccess := !strings.HasPrefix(failure, "unsigned-")
							accessed := nativeAccess
							if exe == binaryPath {
								accessed = goAccess
							}
							replaced := failure == "parent-cleanup" || name == "child" && (failure == "parent-envelope" || failure == "child-cleanup")
							if os.SameFile(originals[name], after) == replaced || !os.SameFile(originals[name], other) {
								t.Fatalf("%s %s replacement want %t", exe, name, replaced)
							}
							at, sourceAt := writerAccess(after), writerAccess(other)
							copiedAccess := name == "main" && failure == "parent-cleanup" || name == "child" && failure == "child-cleanup"
							if accessed {
								if at.Before(started) || at.After(finished) || sourceAt.Before(started) || sourceAt.After(finished) {
									t.Fatalf("%s %s access outside operation", exe, name)
								}
								if replaced {
									if copiedAccess {
										if !at.Equal(sourceAt) {
											t.Fatal("native cleanup failure did not retain copied source access")
										}
									} else if !at.After(sourceAt) {
										t.Fatal("replacement access did not follow source")
									}
								}
							} else if !at.Equal(writerAccess(originals[name])) || !sourceAt.Equal(writerAccess(originals[name])) {
								t.Fatalf("%s %s untouched access changed", exe, name)
							}
							if !writerBirth(other).Equal(writerBirth(originals[name])) || !replaced && !writerBirth(after).Equal(writerBirth(originals[name])) {
								t.Fatal("uncommitted creation time changed")
							}
							access := map[string]any{"before": writerAccess(originals[name]), "after": at, "neighbour": sourceAt, "accessed": accessed, "native_accessed": nativeAccess, "known_read_difference": goAccess != nativeAccess, "native_replacement_copies_source_access": copiedAccess, "known_replacement_access_difference": false}
							effects[name] = map[string]any{"access": access, "inode_replaced": replaced, "neighbour_preserved": true}
							if !other.ModTime().Equal(originals[name].ModTime()) || !replaced && !after.ModTime().Equal(originals[name].ModTime()) {
								t.Fatal("uncommitted modification time changed")
							}
						}
						for name, path := range paths {
							nativeEqual(t, "neighbour bytes", nativeRead(t, neighbours[name]), originalBytes[name])
							if !effects[name].(map[string]any)["inode_replaced"].(bool) {
								nativeEqual(t, "uncommitted bytes", nativeRead(t, path), originalBytes[name])
							}
						}
						after := layoutArchive(t, app)
						if strings.HasPrefix(failure, "unsigned-") {
							nativeEqual(t, "failed construction tree", before, after)
						}
						if err := filepath.WalkDir(app, func(path string, d os.DirEntry, err error) error {
							if err == nil && (strings.HasPrefix(d.Name(), ".apfs-replacement-") || strings.HasSuffix(d.Name(), ".cstemp")) {
								return fmt.Errorf("staging leaked: %s", path)
							}
							return err
						}); err != nil {
							t.Fatal(err)
						}
						return after, map[string]any{"argv": append(args, app), "stdout": stdout, "stderr": stderr, "exit": status, "started": started, "finished": finished, "before_sha256": hash(before), "tree_sha256": hash(after), "executables": effects, "staging_removed": true}
					}
					want, native := execute(apple(t))
					got, record := execute(binaryPath)
					nativeEqual(t, "complete failure tree", got, want)
					attest(t, map[string]any{"architecture": arch, "profile": profile, "failure": failure, "native_compared": true, "go": record, "native": native, "filesystem_profile": "Darwin APFS allocation and commit failure boundaries"})
				})
			}
		}
	}
}
