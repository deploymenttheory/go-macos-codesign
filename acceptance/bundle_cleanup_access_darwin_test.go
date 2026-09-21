package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBundleCleanupAccessTime(t *testing.T) {
	for _, kind := range append([]string{"app"}, bundleLayouts...) {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, profile := range []string{"past", "future"} {
				for _, operation := range []string{"sign", "resign", "readonly", "remove", "remove-unsigned", "dryrun"} {
					for _, entry := range []string{"directory", "symlink"} {
						t.Run(kind+"/"+arch+"/"+profile+"/"+operation+"/"+entry, func(t *testing.T) {
							execute := func(exe string) ([]byte, map[string]any) {
								t.Helper()
								dir := t.TempDir()
								app, main, envelope, _, executables := writerBundle(t, dir, kind, arch)
								if operation != "sign" && operation != "remove-unsigned" {
									mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
								}
								stale := filepath.Join(app, filepath.Dir(envelope), "stale")
								if err := os.MkdirAll(filepath.Dir(stale), 0755); err != nil {
									t.Fatal(err)
								}
								switch entry {
								case "directory":
									if err := os.Mkdir(stale, 0755); err != nil {
										t.Fatal(err)
									}
								case "symlink":
									if err := os.Symlink("absent", stale); err != nil {
										t.Fatal(err)
									}
								}
								type original struct {
									name, neighbour string
									info            os.FileInfo
									data            []byte
								}
								originals := make([]original, 0, len(executables))
								for i, name := range executables {
									path := filepath.Join(app, name)
									if operation == "readonly" {
										if err := os.Chmod(path, 0551); err != nil {
											t.Fatal(err)
										}
									}
									neighbour := filepath.Join(dir, fmt.Sprintf("neighbour-%d", i))
									if err := os.Link(path, neighbour); err != nil {
										t.Fatal(err)
									}
									originals = append(originals, original{name: name, neighbour: neighbour, data: nativeRead(t, path)})
								}
								before := layoutArchive(t, app)
								seed := time.Unix(978307200, 234567890)
								if profile == "future" {
									seed = time.Now().Add(48 * time.Hour)
								}
								for i, old := range originals {
									path := filepath.Join(app, old.name)
									if err := os.Chtimes(path, seed, time.Unix(946684800, 123456789)); err != nil {
										t.Fatal(err)
									}
									st, err := os.Stat(path)
									if err != nil {
										t.Fatal(err)
									}
									originals[i].info = st
								}
								removing, dryrun := strings.HasPrefix(operation, "remove"), operation == "dryrun"
								args := []string{"-fs", "-", "--deep", "--timestamp=none"}
								if removing {
									args = []string{"--remove-signature"}
								}
								if dryrun {
									args = append(args, "--dryrun")
								}
								started := time.Now()
								stdout, stderr, status := run(t, exe, append(args, app)...)
								finished := time.Now()
								wantStatus := 1
								if dryrun {
									wantStatus = 0
								}
								if status != wantStatus {
									t.Fatalf("%s %v: exit %d want %d\n%s\n%s", exe, args, status, wantStatus, stdout, stderr)
								}
								effects := map[string]any{}
								for _, old := range originals {
									after, err := os.Stat(filepath.Join(app, old.name))
									if err != nil {
										t.Fatal(err)
									}
									other, err := os.Stat(old.neighbour)
									if err != nil {
										t.Fatal(err)
									}
									accessed := !removing || old.name == main
									replaced := accessed && !dryrun
									copied := replaced && old.name == main
									at, sourceAt := writerAccess(after), writerAccess(other)
									if accessed {
										if at.Before(started) || at.After(finished) || sourceAt.Before(started) || sourceAt.After(finished) {
											t.Fatalf("%s %s access outside operation", exe, old.name)
										}
										if copied && !at.Equal(sourceAt) {
											t.Fatalf("%s %s cleanup failure refreshed copied access: %v != %v", exe, old.name, at, sourceAt)
										}
										if replaced && !copied && !at.After(sourceAt) {
											t.Fatalf("%s %s successful descendant did not refresh access", exe, old.name)
										}
									} else if !at.Equal(writerAccess(old.info)) || !sourceAt.Equal(writerAccess(old.info)) {
										t.Fatalf("%s %s untouched access changed", exe, old.name)
									}
									if os.SameFile(old.info, after) == replaced || !os.SameFile(old.info, other) {
										t.Fatalf("%s %s replacement want %t", exe, old.name, replaced)
									}
									if after.Mode() != old.info.Mode() || other.Mode() != old.info.Mode() || !other.ModTime().Equal(old.info.ModTime()) || !writerBirth(other).Equal(writerBirth(old.info)) {
										t.Fatalf("%s neighbour metadata changed", old.name)
									}
									if !replaced && (!after.ModTime().Equal(old.info.ModTime()) || !writerBirth(after).Equal(writerBirth(old.info))) {
										t.Fatalf("%s uncommitted timestamps changed", old.name)
									}
									if replaced && (!writerBirth(after).Equal(old.info.ModTime()) || after.ModTime().Before(started) || after.ModTime().After(finished)) {
										t.Fatalf("%s replacement timestamps incorrect", old.name)
									}
									effects[old.name] = map[string]any{"accessed": accessed, "inode_replaced": replaced, "copied_source_access": copied, "before_access": writerAccess(old.info), "after_access": at, "neighbour_access": sourceAt, "neighbour_preserved": true}
								}
								for _, old := range originals {
									nativeEqual(t, "external neighbour", nativeRead(t, old.neighbour), old.data)
								}
								after := layoutArchive(t, app)
								if dryrun {
									nativeEqual(t, "dry-run tree", after, before)
								}
								return after, map[string]any{"argv": append(args, app), "stdout": stdout, "stderr": stderr, "exit": status, "started": started, "finished": finished, "before_sha256": hash(before), "tree_sha256": hash(after), "executables": effects}
							}
							want, native := execute(apple(t))
							got, record := execute(binaryPath)
							nativeEqual(t, "complete cleanup-access tree", got, want)
							attest(t, map[string]any{"layout": kind, "architecture": arch, "profile": profile, "operation": operation, "entry": entry, "go": record, "native": native, "native_compared": true, "filesystem_profile": "Darwin APFS replacement access after signature cleanup"})
						})
					}
				}
			}
		}
	}
}
