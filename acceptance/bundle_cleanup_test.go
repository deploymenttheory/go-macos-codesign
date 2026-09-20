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

func TestBundleSignatureCleanupNonRegular(t *testing.T) {
	for _, kind := range []string{"directory", "symlink"} {
		for _, operation := range []string{"sign", "remove", "dryrun", "verify"} {
			t.Run(kind+"/"+operation, func(t *testing.T) {
				execute := func(exe string) map[string]any {
					app := filepath.Join(t.TempDir(), "Example.app")
					bundleFixture(t, app, "arm64")
					mustRun(t, exe, "-s", "-", "--timestamp=none", app)
					stale := filepath.Join(app, "Contents/_CodeSignature/stale")
					if kind == "directory" {
						if err := os.Mkdir(stale, 0755); err != nil {
							t.Fatal(err)
						}
					} else if err := os.Symlink("../Resources/message.txt", stale); err != nil {
						t.Fatal(err)
					}
					before := layoutArchive(t, app)
					main := filepath.Join(app, "Contents/MacOS/hello")
					original, err := os.Stat(main)
					if err != nil {
						t.Fatal(err)
					}
					// Force lazy Windows identity capture before the operation.
					if !os.SameFile(original, original) {
						t.Fatal("cannot capture original executable identity")
					}
					args := []string{"-fs", "-", "--timestamp=none"}
					switch operation {
					case "remove":
						args = []string{"--remove-signature"}
					case "dryrun":
						args = append(args, "--dryrun")
					case "verify":
						args = []string{"--verify"}
					}
					stdout, stderr, status := run(t, exe, append(args, app)...)
					wantStatus := 1
					if exe != binaryPath && operation == "dryrun" {
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
					wantReplacement := exe != binaryPath && (operation == "sign" || operation == "remove")
					if replaced != wantReplacement {
						t.Fatal("unexpected non-regular failure mutation", replaced)
					}
					if !wantReplacement {
						nativeEqual(t, "rejected or dry-run tree", after, before)
					}
					return map[string]any{"argv": append(args, app), "stdout": stdout, "stderr": stderr, "exit": status, "inode_replaced": replaced, "before_sha256": hash(before), "tree_sha256": hash(after)}
				}
				evidence := map[string]any{"profile": kind, "operation": operation, "go": execute(binaryPath), "limitation": "Go rejects non-regular signature entries before writes; native sign/removal can fail after replacement and native dryrun succeeds"}
				if runtime.GOOS == "darwin" {
					evidence["native"] = execute(apple(t))
				}
				attest(t, evidence)
			})
		}
	}
}
