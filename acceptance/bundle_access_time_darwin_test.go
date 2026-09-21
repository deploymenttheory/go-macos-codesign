package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writerAccess(info os.FileInfo) time.Time {
	access := info.Sys().(*syscall.Stat_t).Atimespec
	return time.Unix(access.Sec, access.Nsec)
}

func TestBundleExecutableAccessTime(t *testing.T) {
	for _, kind := range append([]string{"app"}, bundleLayouts...) {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, profile := range []string{"past", "future"} {
				for _, operation := range []string{"sign", "readonly", "resign", "remove", "remove-unsigned", "dryrun", "dryrun-unsigned"} {
					t.Run(kind+"/"+arch+"/"+profile+"/"+operation, func(t *testing.T) {
						execute := func(exe string) ([]byte, map[string]any) {
							dir := t.TempDir()
							app, main, _, _, executables := writerBundle(t, dir, kind, arch)
							switch operation {
							case "resign", "remove", "dryrun":
								mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
							case "dryrun-unsigned":
								// Keep valid nested seals while testing an unsigned outer bundle.
								mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
								mustRun(t, exe, "--remove-signature", app)
							}
							type original struct {
								name, neighbour string
								info            os.FileInfo
								data            []byte
							}
							originals := make([]original, 0, len(executables))
							for i, name := range executables {
								path := filepath.Join(app, filepath.FromSlash(name))
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
							access := time.Unix(978307200, 234567890)
							if profile == "future" {
								access = time.Now().Add(48 * time.Hour)
							}
							for i, old := range originals {
								path := filepath.Join(app, filepath.FromSlash(old.name))
								if err := os.Chtimes(path, access, time.Unix(946684800, 123456789)); err != nil {
									t.Fatal(err)
								}
								info, err := os.Stat(path)
								if err != nil {
									t.Fatal(err)
								}
								originals[i].info = info
							}
							args := []string{"-fs", "-", "--deep", "--timestamp=none"}
							removing, dryrun := strings.HasPrefix(operation, "remove"), strings.HasPrefix(operation, "dryrun")
							if removing {
								args = []string{"--remove-signature"}
							}
							if dryrun {
								args = append(args, "--dryrun")
							}
							started := time.Now()
							out, stderr, status := run(t, exe, append(args, app)...)
							finished := time.Now()
							if status != 0 {
								t.Fatalf("%s %q: %d\n%s\n%s", exe, args, status, out, stderr)
							}
							effects := map[string]any{}
							// Snapshot access times before reading output bytes or verifying signatures.
							for _, old := range originals {
								after, err := os.Stat(filepath.Join(app, filepath.FromSlash(old.name)))
								if err != nil {
									t.Fatal(err)
								}
								other, err := os.Stat(old.neighbour)
								if err != nil {
									t.Fatal(err)
								}
								accessed := !removing || old.name == main
								rewritten := accessed && !dryrun
								at, neighbourAt := writerAccess(after), writerAccess(other)
								if accessed {
									for _, value := range []time.Time{at, neighbourAt} {
										if value.Before(started) || value.After(finished) {
											t.Fatalf("%s access %v outside [%v, %v]", old.name, value, started, finished)
										}
									}
									if rewritten && !at.After(neighbourAt) {
										t.Fatalf("%s replacement access %v did not follow source access %v", old.name, at, neighbourAt)
									}
								} else if !at.Equal(writerAccess(old.info)) || !neighbourAt.Equal(writerAccess(old.info)) {
									t.Fatalf("untouched descendant access changed: %s", old.name)
								}
								if os.SameFile(old.info, after) == rewritten || !os.SameFile(old.info, other) {
									t.Fatalf("executable or neighbour identity changed: %s", old.name)
								}
								if !rewritten && (!after.ModTime().Equal(old.info.ModTime()) || !writerBirth(after).Equal(writerBirth(old.info))) {
									t.Fatalf("untouched write timestamps changed: %s", old.name)
								}
								if !other.ModTime().Equal(old.info.ModTime()) || !writerBirth(other).Equal(writerBirth(old.info)) {
									t.Fatalf("neighbour write timestamps changed: %s", old.name)
								}
								effects[old.name] = map[string]any{"accessed": accessed, "inode_replaced": rewritten, "before_access": writerAccess(old.info), "after_access": at, "neighbour_access": neighbourAt, "neighbour_preserved": true}
							}
							for _, old := range originals {
								nativeEqual(t, "external neighbour", nativeRead(t, old.neighbour), old.data)
							}
							after := layoutArchive(t, app)
							if dryrun {
								nativeEqual(t, "dry-run tree", after, before)
							}
							if !removing && operation != "dryrun-unsigned" {
								mustRun(t, apple(t), "--verify", "--strict", "--deep", app)
							}
							return after, map[string]any{"argv": append(args, app), "stdout": out, "stderr": stderr, "exit": status, "started": started, "finished": finished, "tree_sha256": hash(after), "executables": effects}
						}
						got, record := execute(binaryPath)
						want, native := execute(apple(t))
						nativeEqual(t, "complete access-time tree", got, want)
						attest(t, map[string]any{"layout": kind, "architecture": arch, "profile": profile, "operation": operation, "go": record, "native": native, "native_compared": true, "filesystem_profile": "Darwin APFS executable mapped-read access"})
					})
				}
			}
		}
	}
}
