package acceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type writerMetadata struct {
	Mode           uint32
	UID, GID       uint32
	Flags          uint32
	Birth          syscall.Timespec
	ACL, Attribute string
}

func bundleWriterMetadata(t *testing.T, path string) writerMetadata {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	s := st.Sys().(*syscall.Stat_t)
	out, stderr, status := run(t, "/bin/ls", "-lde", path)
	if status != 0 {
		t.Fatal(stderr)
	}
	_, acl, _ := bytes.Cut([]byte(out), []byte{'\n'})
	data := make([]byte, 128)
	n, err := unix.Getxattr(path, "org.example.writer", data)
	if err != nil {
		t.Fatal(err)
	}
	return writerMetadata{uint32(st.Mode()), s.Uid, s.Gid, s.Flags, s.Birthtimespec, string(acl), string(data[:n])}
}

// Preserve raw filesystem observations without asserting equality for native
// write/access/change times, which depend on when each independent run executes.
func bundleWriterStat(t *testing.T, path string) any {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"device": st.Dev, "inode": st.Ino, "links": st.Nlink, "size": st.Size, "access": st.Atimespec, "modified": st.Mtimespec, "changed": st.Ctimespec, "birth": st.Birthtimespec}
}

func TestBundleWriterNativeMetadata(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, operation := range []string{"sign", "readonly", "resign", "remove", "dryrun"} {
			t.Run(arch+"/"+operation, func(t *testing.T) {
				record := map[string]any{"architecture": arch, "operation": operation}
				for _, exe := range []string{binaryPath, apple(t)} {
					app := filepath.Join(t.TempDir(), "Example.app")
					bundleFixture(t, app, arch)
					main := filepath.Join(app, "Contents/MacOS/hello")
					envelope := filepath.Join(app, "Contents/_CodeSignature/CodeResources")
					if operation == "resign" || operation == "remove" || operation == "dryrun" {
						mustRun(t, exe, "-s", "-", "--timestamp=none", app)
					} else {
						bundleWrite(t, app, "Contents/_CodeSignature/CodeResources", []byte("old"))
					}
					for _, p := range []string{main, envelope} {
						mustRun(t, "/bin/chmod", "+a", "everyone allow read", p)
						if err := unix.Setxattr(p, "org.example.writer", []byte("retained metadata"), 0); err != nil {
							t.Fatal(err)
						}
						if err := unix.Chflags(p, unix.UF_HIDDEN); err != nil {
							t.Fatal(err)
						}
					}
					// Measure source ACL preservation and directory inheritance separately.
					mustRun(t, "/bin/chmod", "+a", "everyone allow read,file_inherit,directory_inherit", filepath.Dir(main))
					if operation == "readonly" {
						if err := os.Chmod(main, 0551); err != nil {
							t.Fatal(err)
						}
					}
					beforeMain, beforeEnvelope := bundleWriterMetadata(t, main), bundleWriterMetadata(t, envelope)
					beforeStat := map[string]any{"main": bundleWriterStat(t, main), "envelope": bundleWriterStat(t, envelope)}
					args := []string{"-fs", "-", "--timestamp=none"}
					if operation == "remove" {
						args = []string{"--remove-signature"}
					}
					if operation == "dryrun" {
						args = append(args, "--dryrun")
					}
					out, stderr, status := run(t, exe, append(args, app)...)
					if status != 0 {
						t.Fatalf("%s: %d\n%s\n%s", exe, status, out, stderr)
					}
					afterStat := map[string]any{"main": bundleWriterStat(t, main)}
					afterMain := bundleWriterMetadata(t, main)
					commonBefore, commonAfter := beforeMain, afterMain
					commonBefore.Birth, commonAfter.Birth = syscall.Timespec{}, syscall.Timespec{}
					commonBefore.ACL, commonAfter.ACL = "", ""
					if !reflect.DeepEqual(commonBefore, commonAfter) {
						t.Fatalf("%s %s executable metadata: %#v -> %#v", exe, operation, beforeMain, afterMain)
					}
					if exe == binaryPath || operation == "dryrun" {
						if !reflect.DeepEqual(beforeMain, afterMain) {
							t.Fatalf("source metadata not preserved: %#v -> %#v", beforeMain, afterMain)
						}
					} else if !strings.HasPrefix(afterMain.ACL, beforeMain.ACL) || !strings.Contains(afterMain.ACL, "inherited allow read") {
						t.Fatalf("native ACL inheritance changed: %#v -> %#v", beforeMain, afterMain)
					}
					if operation != "remove" {
						afterStat["envelope"] = bundleWriterStat(t, envelope)
						afterEnvelope := bundleWriterMetadata(t, envelope)
						if !reflect.DeepEqual(beforeEnvelope, afterEnvelope) {
							t.Fatalf("%s envelope metadata: %#v -> %#v", exe, beforeEnvelope, afterEnvelope)
						}
						mustRun(t, apple(t), "--verify", "--strict", app)
					}
					producer := "go"
					if exe == apple(t) {
						producer = "native"
					}
					record[producer] = map[string]any{"argv": append(args, app), "stdout": out, "stderr": stderr, "exit": status, "before": beforeStat, "after": afterStat, "main_metadata_before": beforeMain, "main_metadata_after": afterMain, "existing_envelope_metadata": beforeEnvelope, "common_metadata_preserved": true, "source_acl_preserved": beforeMain.ACL == afterMain.ACL, "source_birthtime_preserved": beforeMain.Birth == afterMain.Birth}
				}
				record["remaining_differences"] = []string{"native executable ACL inheritance", "native executable creation-time behavior"}
				attest(t, record)
			})
		}
	}
}
