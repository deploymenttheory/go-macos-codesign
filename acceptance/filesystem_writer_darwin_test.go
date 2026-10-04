package acceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Exercise the actual mounted filesystem, including the rooted bundle writer.
// Portable writer tests and foreign-producer verification remain separate gates.
func TestMountedFilesystemWriterParity(t *testing.T) {
	for _, filesystem := range []string{"APFS", "HFS+"} {
		t.Run(filesystem, func(t *testing.T) {
			dir := t.TempDir()
			image, mount := filepath.Join(dir, "volume.dmg"), filepath.Join(dir, "mount")
			if err := os.Mkdir(mount, 0700); err != nil {
				t.Fatal(err)
			}
			mustRun(t, "/usr/bin/hdiutil", "create", "-size", "128m", "-fs", filesystem, "-volname", "CodesignWriter", image)
			mustRun(t, "/usr/bin/hdiutil", "attach", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
			t.Cleanup(func() { mustRun(t, "/usr/bin/hdiutil", "detach", mount) })
			var stat unix.Statfs_t
			if err := unix.Statfs(mount, &stat); err != nil {
				t.Fatal(err)
			}
			actualFS := string(bytes.TrimRight(stat.Fstypename[:], "\x00"))
			wanted := "apfs"
			if filesystem == "HFS+" {
				wanted = "hfs"
			}
			if actualFS != wanted {
				t.Fatalf("mounted %q, expected %q", actualFS, wanted)
			}
			for _, kind := range []string{"standalone", "bundle"} {
				for _, arch := range []string{"arm64", "x86_64", "universal"} {
					for _, profile := range []string{"ordinary", "readonly", "deny-write"} {
						for _, operation := range []string{"sign", "dryrun", "remove"} {
							t.Run(kind+"/"+arch+"/"+profile+"/"+operation, func(t *testing.T) {
								outputs := make([][]byte, 0, 2)
								record := map[string]any{"filesystem": actualFS, "kind": kind, "architecture": arch, "profile": profile, "operation": operation}
								for _, exe := range []string{apple(t), binaryPath} {
									work, err := os.MkdirTemp(mount, "case-")
									if err != nil {
										t.Fatal(err)
									}
									target := filepath.Join(work, "hello")
									main := target
									if kind == "bundle" {
										target = filepath.Join(work, "Example.app")
										bundleFixture(t, target, arch)
										main = filepath.Join(target, "Contents/MacOS/hello")
									} else {
										copyFixture(t, "unsigned-"+arch, target)
									}
									// Both producers start from independently native-signed removal input.
									if operation == "remove" {
										mustRun(t, apple(t), "-s", "-", "--timestamp=none", "-i", "phase02", target)
									}
									if profile == "readonly" {
										if err := os.Chmod(main, 0555); err != nil {
											t.Fatal(err)
										}
									}
									if profile == "deny-write" {
										mustRun(t, "/bin/chmod", "+a", "everyone deny write", main)
									}
									neighbour := filepath.Join(work, "neighbour")
									if err := os.Link(main, neighbour); err != nil {
										t.Fatal(err)
									}
									before, err := os.Stat(main)
									if err != nil {
										t.Fatal(err)
									}
									original := nativeRead(t, main)
									treeBefore := layoutArchive(t, work)
									args := []string{"-fs", "-", "--timestamp=none", "-i", "phase02"}
									switch operation {
									case "remove":
										args = []string{"--remove-signature"}
									case "dryrun":
										args = append(args, "--dryrun")
									}
									stdout, stderr, status := run(t, exe, append(args, target)...)
									if status != 0 {
										t.Fatalf("%s %v exited %d: %s%s", exe, args, status, stdout, stderr)
									}
									after, err := os.Stat(main)
									if err != nil {
										t.Fatal(err)
									}
									other, err := os.Stat(neighbour)
									if err != nil || !os.SameFile(before, other) || os.SameFile(before, after) != (operation == "dryrun") || before.Mode() != after.Mode() {
										t.Fatalf("incorrect replacement identity/mode: %v", err)
									}
									nativeEqual(t, "hard-link neighbour", nativeRead(t, neighbour), original)
									tree := layoutArchive(t, work)
									if bytes.Contains(tree, []byte(".apfs-replacement-")) {
										t.Fatal("replacement staging leaked")
									}
									if operation == "dryrun" {
										nativeEqual(t, "dry-run tree", tree, treeBefore)
									}
									if operation == "sign" {
										mustRun(t, apple(t), "--verify", "--strict", target)
										mustRun(t, binaryPath, "--verify", "--strict", target)
									}
									producer := "native"
									if exe == binaryPath {
										producer = "go"
									}
									record[producer] = map[string]any{"argv": append(args, target), "stdout": stdout, "stderr": stderr, "exit": status, "tree_sha256": hash(tree), "inode_replaced": !os.SameFile(before, after)}
									outputs = append(outputs, tree)
									// Retain diagnostics in the transcript, normalizing only fixture paths.
									record[producer+"_stdout"] = strings.ReplaceAll(stdout, target, "<target>")
									record[producer+"_stderr"] = strings.ReplaceAll(stderr, target, "<target>")
									if err := os.RemoveAll(work); err != nil {
										t.Fatal(err)
									}
								}
								nativeEqual(t, "native complete filesystem tree", outputs[1], outputs[0])
								if record["go_stdout"] != record["native_stdout"] || record["go_stderr"] != record["native_stderr"] {
									t.Fatalf("different diagnostics: %#v", record)
								}
								attest(t, record)
							})
						}
					}
				}
			}
		})
	}
}
