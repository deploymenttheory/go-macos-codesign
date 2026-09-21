package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Stale files are outside the resource seal. Signing purges only the bundles it
// writes; removal affects only the selected bundle, including unsigned inputs.
func TestBundleSignatureCleanup(t *testing.T) {
	for _, kind := range append([]string{"app"}, bundleLayouts...) {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, operation := range []string{"sign", "resign", "remove", "remove-unsigned", "dryrun"} {
				t.Run(kind+"/"+arch+"/"+operation, func(t *testing.T) {
					execute := func(exe string) ([]byte, map[string]any) {
						dir := t.TempDir()
						app, _, envelope, resource, _ := writerBundle(t, dir, kind, arch)
						if operation != "sign" && operation != "remove-unsigned" {
							mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
						}
						meta := filepath.ToSlash(filepath.Dir(envelope))
						directories := []string{meta}
						if kind == "app" {
							directories = append(directories, "Contents/PlugIns/Child.app/Contents/_CodeSignature")
						}
						type staleLink struct {
							path, neighbour string
							info            os.FileInfo
							data            []byte
						}
						var links []staleLink
						for _, directory := range directories {
							for _, name := range []string{"CodeRequirements", "CodeSignature", "obsolete", ".stale"} {
								path := filepath.Join(app, directory, name)
								data := []byte("stale " + name + "\n")
								neighbour := filepath.Join(dir, fmt.Sprintf("neighbour-%d", len(links)))
								bundleWrite(t, dir, filepath.Base(neighbour), data)
								if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
									t.Fatal(err)
								}
								// Darwin restricts linking from signing sidecars. Link to them.
								if err := os.Link(neighbour, path); err != nil {
									t.Fatal(err)
								}
								info, err := os.Stat(path)
								if err != nil {
									t.Fatal(err)
								}
								// SameFile loads Windows IDs lazily. Capture both while
								// the name that cleanup will unlink still exists.
								other, err := os.Stat(neighbour)
								if err != nil || !os.SameFile(info, other) {
									t.Fatalf("initial stale hard link: %v", err)
								}
								links = append(links, staleLink{path, neighbour, info, data})
							}
						}
						if operation == "resign" {
							bundleWrite(t, app, resource, []byte("changed resource\n"))
						}
						before := layoutArchive(t, app)
						args := []string{"-fs", "-", "--deep", "--timestamp=none"}
						removing := strings.HasPrefix(operation, "remove")
						if removing {
							args = []string{"--remove-signature"}
						} else if operation == "dryrun" {
							args = append(args, "--dryrun")
						}
						stdout, stderr, status := run(t, exe, append(args, app)...)
						if status != 0 {
							t.Fatalf("%s: %d\n%s\n%s", exe, status, stdout, stderr)
						}
						for _, link := range links {
							st, err := os.Stat(link.neighbour)
							if err != nil || !os.SameFile(link.info, st) {
								t.Fatalf("stale neighbour inode changed: %v", err)
							}
							nativeEqual(t, "stale neighbour", nativeRead(t, link.neighbour), link.data)
							retained := operation == "dryrun" || removing && filepath.Dir(link.path) != filepath.Join(app, meta)
							st, err = os.Stat(link.path)
							if retained {
								if err != nil || !os.SameFile(link.info, st) {
									t.Fatalf("retained stale inode changed: %v", err)
								}
							} else if !os.IsNotExist(err) {
								t.Fatalf("stale file remains: %s: %v", link.path, err)
							}
						}
						if removing {
							entries, err := os.ReadDir(filepath.Join(app, meta))
							if err != nil || len(entries) != 0 {
								t.Fatal("signature directory must remain empty", entries, err)
							}
						}
						after := layoutArchive(t, app)
						if operation == "dryrun" {
							nativeEqual(t, "dry-run tree", after, before)
						} else if !removing {
							mustRun(t, binaryPath, "--verify", "--deep", app)
							if runtime.GOOS == "darwin" {
								mustRun(t, apple(t), "--verify", "--strict", "--deep", app)
							}
							if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" && exe == binaryPath {
								bundleWrite(t, export, "signed-bundle-cleanup-"+kind+"-"+arch+"-"+operation+".tar", after)
							}
						}
						return after, map[string]any{"argv": append(args, app), "stdout": stdout, "stderr": stderr, "exit": status, "before_sha256": hash(before), "tree_sha256": hash(after), "stale_neighbours_preserved": len(links)}
					}
					got, record := execute(binaryPath)
					evidence := map[string]any{"producer": runtime.GOOS, "layout": kind, "architecture": arch, "operation": operation, "go": record, "native_compared": runtime.GOOS == "darwin"}
					if runtime.GOOS == "darwin" {
						want, native := execute(apple(t))
						nativeEqual(t, "complete cleaned bundle tree", got, want)
						evidence["native"] = native
					}
					attest(t, evidence)
				})
			}
		}
	}
}

// Failure order is independent of architecture; the regular writer matrix keeps
// all three architectures. Every supported layout is exercised here on arm64.
func TestBundleSignatureCleanupNonRegular(t *testing.T) {
	for _, layout := range append([]string{"app"}, bundleLayouts...) {
		for _, kind := range []string{"directory", "populated-directory", "symlink", "broken-symlink", "outside-symlink"} {
			for _, operation := range []string{"sign", "resign", "remove", "remove-unsigned", "dryrun", "verify"} {
				t.Run(layout+"/"+kind+"/"+operation, func(t *testing.T) {
					execute := func(exe string) ([]byte, map[string]any) {
						dir := t.TempDir()
						app, mainName, envelope, resource, _ := writerBundle(t, dir, layout, "arm64")
						if operation != "sign" && operation != "remove-unsigned" {
							mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
						}
						stale := filepath.Join(app, filepath.Dir(envelope), "stale")
						if err := os.MkdirAll(filepath.Dir(stale), 0755); err != nil {
							t.Fatal(err)
						}
						outside := filepath.Join(dir, "outside")
						bundleWrite(t, dir, "outside", []byte("outside unchanged\n"))
						if kind == "directory" || kind == "populated-directory" {
							if err := os.Mkdir(stale, 0755); err != nil {
								t.Fatal(err)
							}
							if kind == "populated-directory" {
								bundleWrite(t, stale, "keep", []byte("directory unchanged\n"))
							}
						} else {
							target := filepath.Join(app, resource)
							switch kind {
							case "broken-symlink":
								target = filepath.Join(dir, "absent")
							case "outside-symlink":
								target = outside
							}
							rel, err := filepath.Rel(filepath.Dir(stale), target)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.Symlink(rel, stale); err != nil {
								t.Fatal(err)
							}
						}
						if operation == "resign" || operation == "dryrun" {
							bundleWrite(t, app, resource, []byte("changed resource\n"))
						}
						before := layoutArchive(t, app)
						main := filepath.Join(app, mainName)
						original, err := os.Stat(main)
						if err != nil {
							t.Fatal(err)
						}
						neighbour := filepath.Join(dir, "executable-neighbour")
						if err := os.Link(main, neighbour); err != nil {
							t.Fatal(err)
						}
						other, err := os.Stat(neighbour)
						if err != nil || !os.SameFile(original, other) {
							t.Fatalf("initial hard link: %v", err)
						}
						originalData := nativeRead(t, main)
						args := []string{"-fs", "-", "--deep", "--timestamp=none"}
						removing := strings.HasPrefix(operation, "remove")
						switch {
						case removing:
							args = []string{"--remove-signature"}
						case operation == "dryrun":
							args = append(args, "--dryrun")
						case operation == "verify":
							args = []string{"--verify", "--deep"}
						}
						stdout, stderr, status := run(t, exe, append(args, app)...)
						wantStatus := 1
						if operation == "dryrun" {
							wantStatus = 0
						}
						if status != wantStatus {
							t.Fatalf("%s exit %d want %d: %s %s", exe, status, wantStatus, stdout, stderr)
						}
						after := layoutArchive(t, app)
						current, err := os.Stat(main)
						if err != nil {
							t.Fatal(err)
						}
						replaced := !os.SameFile(original, current)
						wantReplacement := operation != "verify" && operation != "dryrun"
						if replaced != wantReplacement {
							t.Fatal("unexpected non-regular failure mutation", replaced)
						}
						if !wantReplacement {
							nativeEqual(t, "rejected or dry-run tree", after, before)
						}
						other, err = os.Stat(neighbour)
						if err != nil || !os.SameFile(original, other) {
							t.Fatalf("external hard link changed: %v", err)
						}
						nativeEqual(t, "external executable bytes", nativeRead(t, neighbour), originalData)
						nativeEqual(t, "external symlink target", nativeRead(t, outside), []byte("outside unchanged\n"))
						if _, err := os.Lstat(stale); err != nil {
							t.Fatal("stale entry removed", err)
						}
						if kind == "populated-directory" {
							nativeEqual(t, "directory contents", nativeRead(t, filepath.Join(stale, "keep")), []byte("directory unchanged\n"))
						}
						if removing {
							if _, err := os.Lstat(filepath.Join(app, envelope)); !os.IsNotExist(err) {
								t.Fatal("removal retained CodeResources before flush failure", err)
							}
						}
						return after, map[string]any{"argv": append(args, app), "stdout": stdout, "stderr": stderr, "exit": status, "inode_replaced": replaced, "before_sha256": hash(before), "tree_sha256": hash(after), "neighbour_preserved": true}
					}
					got, record := execute(binaryPath)
					evidence := map[string]any{"producer": runtime.GOOS, "layout": layout, "profile": kind, "operation": operation, "go": record, "native_compared": runtime.GOOS == "darwin", "remaining_differences": []string{"raw diagnostics", "broader permissions and named signature component failure ordering"}}
					if runtime.GOOS == "darwin" {
						want, native := execute(apple(t))
						nativeEqual(t, "complete non-regular cleanup failure tree", got, want)
						evidence["native"] = native
					}
					attest(t, evidence)
				})
			}
		}
	}
}

// A child flush failure stops the parent commit, while retaining the child's
// rewritten executable and envelope. A dry run preserves both bundles.
func TestBundleSignatureCleanupNestedFailure(t *testing.T) {
	for _, kind := range []string{"directory", "symlink"} {
		for _, operation := range []string{"resign", "dryrun"} {
			t.Run(kind+"/"+operation, func(t *testing.T) {
				execute := func(exe string) ([]byte, map[string]any) {
					app, main, _, resource, _ := writerBundle(t, t.TempDir(), "app", "arm64")
					mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
					child := filepath.Join(app, "Contents/PlugIns/Child.app")
					stale := filepath.Join(child, "Contents/_CodeSignature/stale")
					if kind == "directory" {
						if err := os.Mkdir(stale, 0755); err != nil {
							t.Fatal(err)
						}
					} else if err := os.Symlink("../Resources/message.txt", stale); err != nil {
						t.Fatal(err)
					}
					bundleWrite(t, app, resource, []byte("parent changed\n"))
					bundleWrite(t, child, "Contents/Resources/message.txt", []byte("child changed\n"))
					paths := []string{filepath.Join(app, main), filepath.Join(child, "Contents/MacOS/hello")}
					beforeInfo := make([]os.FileInfo, len(paths))
					for i, path := range paths {
						st, err := os.Stat(path)
						if err != nil || !os.SameFile(st, st) {
							t.Fatalf("original identity: %v", err)
						}
						beforeInfo[i] = st
					}
					before := layoutArchive(t, app)
					args := []string{"-fs", "-", "--deep", "--timestamp=none"}
					wantStatus := 1
					if operation == "dryrun" {
						args, wantStatus = append(args, "--dryrun"), 0
					}
					out, stderr, status := run(t, exe, append(args, app)...)
					if status != wantStatus {
						t.Fatalf("%s: %d: %s %s", exe, status, out, stderr)
					}
					for i, path := range paths {
						st, err := os.Stat(path)
						wantReplacement := i == 1 && operation == "resign"
						if err != nil || os.SameFile(beforeInfo[i], st) == wantReplacement {
							t.Fatalf("commit order at %s: %v", path, err)
						}
					}
					after := layoutArchive(t, app)
					if operation == "dryrun" {
						nativeEqual(t, "nested dry-run tree", after, before)
					}
					return after, map[string]any{"argv": append(args, app), "stdout": out, "stderr": stderr, "exit": status, "before_sha256": hash(before), "tree_sha256": hash(after), "parent_retained": true, "child_replaced": operation == "resign"}
				}
				got, record := execute(binaryPath)
				evidence := map[string]any{"producer": runtime.GOOS, "profile": kind, "operation": operation, "go": record, "native_compared": runtime.GOOS == "darwin"}
				if runtime.GOOS == "darwin" {
					want, native := execute(apple(t))
					nativeEqual(t, "complete nested cleanup failure tree", got, want)
					evidence["native"] = native
				}
				attest(t, evidence)
			})
		}
	}
}
