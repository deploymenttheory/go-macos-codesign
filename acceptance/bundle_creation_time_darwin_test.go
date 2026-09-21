package acceptance

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func setWriterTimes(t *testing.T, path string, modified time.Time) {
	t.Helper()
	var timestamps [48]byte
	for i, value := range []time.Time{time.Unix(915148800, 987654321), modified, time.Unix(978307200, 234567890)} {
		binary.LittleEndian.PutUint64(timestamps[i*16:], uint64(value.Unix()))
		binary.LittleEndian.PutUint64(timestamps[i*16+8:], uint64(value.Nanosecond()))
	}
	list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_CRTIME | unix.ATTR_CMN_MODTIME | unix.ATTR_CMN_ACCTIME}
	if err := unix.Setattrlist(path, &list, timestamps[:], 0); err != nil {
		t.Fatal(err)
	}
}

func writerBirth(info os.FileInfo) time.Time {
	birth := info.Sys().(*syscall.Stat_t).Birthtimespec
	return time.Unix(birth.Sec, birth.Nsec)
}

func TestBundleExecutableCreationTime(t *testing.T) {
	for _, kind := range append([]string{"app"}, bundleLayouts...) {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, profile := range []string{"past", "future"} {
				for _, operation := range []string{"sign", "resign", "remove", "remove-unsigned", "dryrun"} {
					t.Run(kind+"/"+arch+"/"+profile+"/"+operation, func(t *testing.T) {
						execute := func(exe string) ([]byte, map[string]any) {
							dir := t.TempDir()
							app, main, envelope, _, executables := writerBundle(t, dir, kind, arch)
							if operation == "resign" || operation == "remove" || operation == "dryrun" {
								mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
							}
							modified := time.Unix(946684800, 123456789)
							if profile == "future" {
								modified = time.Now().Add(48 * time.Hour)
							}
							type original struct {
								name, neighbour string
								info            os.FileInfo
								data            []byte
							}
							originals := make([]original, 0, len(executables))
							for i, name := range executables {
								path := filepath.Join(app, filepath.FromSlash(name))
								setWriterTimes(t, path, modified)
								neighbour := filepath.Join(dir, fmt.Sprintf("neighbour-%d", i))
								if err := os.Link(path, neighbour); err != nil {
									t.Fatal(err)
								}
								info, err := os.Stat(path)
								if err != nil {
									t.Fatal(err)
								}
								originals = append(originals, original{name, neighbour, info, nativeRead(t, path)})
							}
							envelopePath := filepath.Join(app, filepath.FromSlash(envelope))
							envelopeBefore, err := os.Stat(envelopePath)
							if err != nil && !os.IsNotExist(err) {
								t.Fatal(err)
							}
							before := layoutArchive(t, app)
							args := []string{"-fs", "-", "--deep", "--timestamp=none"}
							removing := strings.HasPrefix(operation, "remove")
							if removing {
								args = []string{"--remove-signature"}
							}
							if operation == "dryrun" {
								args = append(args, "--dryrun")
							}
							started := time.Now()
							out, stderr, status := run(t, exe, append(args, app)...)
							finished := time.Now()
							if status != 0 {
								t.Fatalf("%s %q: %d\n%s\n%s", exe, args, status, out, stderr)
							}
							effects := map[string]any{}
							for _, old := range originals {
								after, err := os.Stat(filepath.Join(app, filepath.FromSlash(old.name)))
								if err != nil {
									t.Fatal(err)
								}
								other, err := os.Stat(old.neighbour)
								if err != nil {
									t.Fatal(err)
								}
								rewritten := operation != "dryrun" && (!removing || old.name == main)
								birth, expected := writerBirth(after), "preserved"
								if !rewritten {
									if !birth.Equal(writerBirth(old.info)) || !after.ModTime().Equal(old.info.ModTime()) {
										t.Fatalf("untouched executable times changed: %s", old.name)
									}
								} else if profile == "past" {
									expected = "source modification time"
									if !birth.Equal(old.info.ModTime()) {
										t.Fatalf("%s birth %v; want %v", old.name, birth, old.info.ModTime())
									}
								} else {
									expected = "new time during operation"
									if birth.Before(started) || birth.After(finished) {
										t.Fatalf("%s birth %v outside [%v, %v]", old.name, birth, started, finished)
									}
								}
								if os.SameFile(old.info, after) == rewritten || !os.SameFile(old.info, other) {
									t.Fatalf("executable or neighbour identity changed: %s", old.name)
								}
								if !writerBirth(old.info).Equal(writerBirth(other)) || !old.info.ModTime().Equal(other.ModTime()) {
									t.Fatalf("neighbour timestamps changed: %s", old.name)
								}
								nativeEqual(t, "external neighbour", nativeRead(t, old.neighbour), old.data)
								effects[old.name] = map[string]any{"expected_creation_time": expected, "before_birth": writerBirth(old.info), "before_modified": old.info.ModTime(), "after_birth": birth, "after_modified": after.ModTime(), "inode_replaced": rewritten, "neighbour_preserved": true}
							}
							if envelopeBefore != nil && !removing {
								after, err := os.Stat(envelopePath)
								if err != nil || !os.SameFile(envelopeBefore, after) || !writerBirth(envelopeBefore).Equal(writerBirth(after)) {
									t.Fatalf("existing envelope identity or creation time changed: %v", err)
								}
							}
							after := layoutArchive(t, app)
							if operation == "dryrun" {
								nativeEqual(t, "dry-run tree", after, before)
							}
							if !removing {
								mustRun(t, apple(t), "--verify", "--strict", "--deep", app)
							}
							return after, map[string]any{"argv": append(args, app), "stdout": out, "stderr": stderr, "exit": status, "started": started, "finished": finished, "tree_sha256": hash(after), "executables": effects}
						}
						got, record := execute(binaryPath)
						want, native := execute(apple(t))
						nativeEqual(t, "complete creation-time tree", got, want)
						attest(t, map[string]any{"layout": kind, "architecture": arch, "profile": profile, "operation": operation, "go": record, "native": native, "native_compared": true, "filesystem_profile": "Darwin APFS executable creation time"})
					})
				}
			}
		}
	}
}
