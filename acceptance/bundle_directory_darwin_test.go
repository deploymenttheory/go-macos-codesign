package acceptance

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func directoryACL(t *testing.T, path string) string {
	t.Helper()
	out, stderr, status := run(t, "/bin/ls", "-lde", path)
	if status != 0 {
		t.Fatal(stderr)
	}
	_, entries, _ := bytes.Cut([]byte(out), []byte{'\n'})
	return string(entries)
}

func TestBundleDirectoryNativeSecurity(t *testing.T) {
	for _, profile := range []string{"stat", "root-acl", "parent-acl", "both-acls", "inherited-root-acl", "existing", "dryrun", "remove"} {
		t.Run(profile, func(t *testing.T) {
			record := map[string]any{"profile": profile, "architecture": "arm64"}
			for _, exe := range []string{binaryPath, apple(t)} {
				parent := t.TempDir()
				if profile == "inherited-root-acl" {
					mustRun(t, "/bin/chmod", "+a", "everyone allow readattr,directory_inherit", parent)
				}
				app := filepath.Join(parent, "Example.app")
				bundleFixture(t, app, "arm64")
				contents := filepath.Join(app, "Contents")
				dir := filepath.Join(contents, "_CodeSignature")
				main := filepath.Join(contents, "MacOS/hello")
				if profile == "inherited-root-acl" {
					mustRun(t, "/bin/chmod", "-N", contents)
				}
				rootACL := profile == "root-acl" || profile == "both-acls"
				parentACL := profile == "parent-acl" || profile == "both-acls"
				if rootACL {
					mustRun(t, "/bin/chmod", "+a", "everyone allow read,file_inherit,directory_inherit", app)
				}
				if parentACL {
					mustRun(t, "/bin/chmod", "+a", "everyone allow execute,file_inherit,directory_inherit", contents)
				}
				existing := profile == "existing" || profile == "remove"
				if existing {
					mustRun(t, exe, "-s", "-", "--timestamp=none", app)
					mustRun(t, "/bin/chmod", "+a", "everyone allow readattr", dir)
					if err := os.Chmod(dir, 0711); err != nil {
						t.Fatal(err)
					}
					if err := unix.Chflags(dir, unix.UF_NODUMP); err != nil {
						t.Fatal(err)
					}
					if err := unix.Setxattr(dir, "org.example.directory", []byte("existing"), 0); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Chmod(app, 0750); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chflags(app, unix.UF_HIDDEN); err != nil {
					t.Fatal(err)
				}
				if err := unix.Setxattr(app, "org.example.directory", []byte("source"), 0); err != nil {
					t.Fatal(err)
				}
				rootInfo, err := os.Stat(app)
				if err != nil {
					t.Fatal(err)
				}
				src := rootInfo.Sys().(*syscall.Stat_t)
				beforeMain := nativeRead(t, main)
				beforeACL := ""
				if existing {
					beforeACL = directoryACL(t, dir)
				}
				args := []string{"-fs", "-", "--timestamp=none"}
				if profile == "dryrun" {
					args = append(args, "--dryrun")
				}
				if profile == "remove" {
					args = []string{"--remove-signature"}
				}
				out, stderr, status := run(t, exe, append(args, app)...)
				if status != 0 {
					t.Fatalf("%s: %d %s %s", exe, status, out, stderr)
				}
				result := map[string]any{"argv": append(args, app), "stdout": out, "stderr": stderr, "exit": status, "source_acl": directoryACL(t, app), "source_stat": bundleWriterStat(t, app)}
				if profile == "dryrun" {
					if _, err := os.Stat(dir); !os.IsNotExist(err) {
						t.Fatalf("dry-run metadata directory: %v", err)
					}
					nativeEqual(t, "dry-run executable", nativeRead(t, main), beforeMain)
				} else {
					info, err := os.Stat(dir)
					if err != nil {
						t.Fatal(err)
					}
					dst := info.Sys().(*syscall.Stat_t)
					wantMode, wantFlags := os.FileMode(0750), uint32(unix.UF_HIDDEN)
					if existing {
						wantMode, wantFlags = 0711, unix.UF_NODUMP
					}
					if info.Mode().Perm() != wantMode || dst.Uid != src.Uid || dst.Gid != src.Gid || dst.Flags != wantFlags {
						t.Fatalf("directory metadata: %#v; source %#v", dst, src)
					}
					acl := directoryACL(t, dir)
					if existing {
						if acl != beforeACL {
							t.Fatalf("existing ACL: %q; want %q", acl, beforeACL)
						}
					} else {
						if strings.Contains(acl, " allow list,") != (rootACL && exe == apple(t)) {
							t.Fatalf("explicit source ACL profile: %q", acl)
						}
						if strings.Contains(acl, "inherited allow search") != parentACL {
							t.Fatalf("inherited parent ACL profile: %q", acl)
						}
						if strings.Contains(acl, "readattr") {
							t.Fatalf("source inherited ACE copied: %q", acl)
						}
					}
					var attr [32]byte
					n, err := unix.Getxattr(dir, "org.example.directory", attr[:])
					if existing {
						if err != nil || string(attr[:n]) != "existing" {
							t.Fatalf("existing xattr: %q %v", attr[:n], err)
						}
					} else if !errors.Is(err, unix.ENOATTR) {
						t.Fatalf("source xattr copied: %q %v", attr[:n], err)
					}
					result["directory_stat"], result["directory_acl"] = bundleWriterStat(t, dir), acl
					if profile != "remove" {
						envelopeACL := directoryACL(t, filepath.Join(dir, "CodeResources"))
						if !existing && strings.Contains(envelopeACL, "inherited allow read") != (rootACL && exe == apple(t)) {
							t.Fatalf("envelope inherited ACL: %q", envelopeACL)
						}
						result["envelope_acl"] = envelopeACL
						mustRun(t, apple(t), "--verify", "--strict", app)
					}
				}
				producer := "go"
				if exe == apple(t) {
					producer = "native"
				}
				record[producer] = result
			}
			record["remaining_differences"] = []string{"copying explicit source ACL entries to new signature directories and subsequent envelope inheritance"}
			attest(t, record)
		})
	}
}
