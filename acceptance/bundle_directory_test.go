package acceptance

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Directory metadata is independent of the Mach-O architecture. The existing
// writer matrix retains all three architecture profiles and byte comparisons.
func TestBundleDirectoryMetadata(t *testing.T) {
	for _, kind := range append([]string{"app", "physical"}, bundleLayouts...) {
		for _, operation := range []string{"new", "existing", "dryrun-new", "dryrun-existing", "remove"} {
			t.Run(kind+"/"+operation, func(t *testing.T) {
				execute := func(t *testing.T, exe string) ([]byte, map[string]any) {
					fixtureKind := kind
					if kind == "physical" {
						fixtureKind = "versioned"
					}
					var app, envelope string
					if kind == "app" {
						app = filepath.Join(t.TempDir(), "Example.app")
						bundleFixture(t, app, "arm64")
						envelope = "Contents/_CodeSignature/CodeResources"
					} else {
						app = layoutFixture(t, t.TempDir(), fixtureKind, "arm64", "xml")
						_, base, _, _ := layoutPaths(fixtureKind)
						envelope = base + "_CodeSignature/CodeResources"
						if fixtureKind == "framework" || fixtureKind == "versioned" {
							if err := os.Remove(filepath.Join(app, base+"helper")); err != nil {
								t.Fatal(err)
							}
						}
					}
					selected := app
					if kind == "physical" {
						selected = filepath.Join(app, "Versions/A")
					}
					dir := filepath.Dir(filepath.Join(app, filepath.FromSlash(envelope)))
					if operation == "remove" || operation == "dryrun-existing" {
						mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", selected)
					}
					existing := operation == "existing" || operation == "dryrun-existing" || operation == "remove"
					if existing {
						if err := os.MkdirAll(dir, 0755); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Chmod(app, 0750); err != nil {
						t.Fatal(err)
					}
					if fixtureKind == "versioned" {
						if err := os.Chmod(filepath.Join(app, "Versions/A"), 0751); err != nil {
							t.Fatal(err)
						}
					}
					if !existing && filepath.Dir(dir) != selected {
						if err := os.Chmod(filepath.Dir(dir), 0751); err != nil {
							t.Fatal(err)
						}
					}
					if existing {
						if err := os.Chmod(dir, 0711); err != nil {
							t.Fatal(err)
						}
					}
					before := layoutArchive(t, app)
					var old os.FileInfo
					if existing {
						f, err := os.Open(dir)
						if err != nil {
							t.Fatal(err)
						}
						old, err = f.Stat() // capture Windows file identity before mutation
						_ = f.Close()
						if err != nil {
							t.Fatal(err)
						}
					}
					args := []string{"-fs", "-", "--deep", "--timestamp=none"}
					if operation == "dryrun-new" || operation == "dryrun-existing" {
						args = append(args, "--dryrun")
					}
					if operation == "remove" {
						args = []string{"--remove-signature"}
					}
					out, stderr, status := run(t, exe, append(args, selected)...)
					if status != 0 {
						t.Fatalf("%s: %d %s %s", exe, status, out, stderr)
					}
					after := layoutArchive(t, app)
					if operation == "dryrun-new" || operation == "dryrun-existing" {
						nativeEqual(t, "dry-run tree", after, before)
					}
					info, err := os.Stat(dir)
					mode := "absent"
					if operation == "dryrun-new" {
						if !os.IsNotExist(err) {
							t.Fatalf("dry-run created metadata directory: %v", err)
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						mode = info.Mode().String()
						want := os.FileMode(0750)
						if kind == "physical" || kind == "versioned" {
							want = 0751
						}
						if existing {
							want = 0711
							if !os.SameFile(old, info) {
								t.Fatal("existing metadata directory replaced")
							}
						}
						if runtime.GOOS != "windows" && info.Mode().Perm() != want {
							t.Fatalf("directory mode %o; want %o", info.Mode().Perm(), want)
						}
					}
					if operation == "new" || operation == "existing" {
						mustRun(t, binaryPath, "--verify", "--deep", selected)
						if runtime.GOOS == "darwin" {
							mustRun(t, apple(t), "--verify", "--strict", "--deep", selected)
						}
					}
					return after, map[string]any{"argv": append(args, selected), "stdout": out, "stderr": stderr, "exit": status, "directory_mode": mode, "existing_directory_preserved": existing, "tree_sha256": hash(after)}
				}
				var goTree []byte
				record := map[string]any{"layout": kind, "operation": operation, "architecture": "arm64", "producer": runtime.GOOS}
				t.Run("go", func(t *testing.T) {
					var result map[string]any
					goTree, result = execute(t, binaryPath)
					record["go"] = result
				})
				if runtime.GOOS == "darwin" {
					t.Run("native", func(t *testing.T) {
						tree, result := execute(t, apple(t))
						record["native"] = result
						if goTree != nil {
							nativeEqual(t, "complete bundle tree", goTree, tree)
						}
					})
				}
				attest(t, record)
			})
		}
	}
}
