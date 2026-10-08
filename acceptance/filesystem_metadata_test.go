package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Real volumes exercise production filesystem selection. A private provider
// override would establish codec behavior, not codesign CLI acceptance.
func metadataVolume(t *testing.T, filesystem string) string {
	t.Helper()
	work := extractionDirectory(t)
	mount := filepath.Join(work, "mount")
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(work, "metadata.img")
	command := func(exe string, args ...string) {
		t.Helper()
		t.Logf("START metadata volume command: %s %q", exe, args)
		mustRun(t, exe, args...)
		t.Logf("END metadata volume command: %s", exe)
	}
	switch runtime.GOOS {
	case "darwin":
		format := "MS-DOS FAT32"
		if filesystem == "exfat" {
			format = "ExFAT"
		}
		image = filepath.Join(work, "metadata.dmg")
		command("hdiutil", "create", "-size", "128m", "-fs", format, "-volname", "METADATA", image)
		out, diagnostic, status := run(t, "hdiutil", "attach", "-plist", "-nobrowse", "-owners", "off", "-mountpoint", mount, image)
		if status != 0 {
			t.Fatalf("attach: status=%d stdout=%s stderr=%s", status, out, diagnostic)
		}
		device := mount
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			err := detachTestImage(ctx, func() (int, error) {
				t.Logf("START metadata volume detach: %s", device)
				cmd := exec.CommandContext(ctx, "hdiutil", "detach", device)
				cmd.WaitDelay = time.Second
				data, err := cmd.CombinedOutput()
				status := -1
				if cmd.ProcessState != nil {
					status = cmd.ProcessState.ExitCode()
				}
				t.Logf("END metadata volume detach: status=%d error=%v output=%s", status, err, data)
				return status, err
			}, waitForImageDetach)
			if err != nil {
				t.Errorf("metadata volume cleanup: %v", err)
			}
		})
		backing, err := attachedTestDevice([]byte(out))
		if err != nil {
			t.Fatal(err)
		}
		device = backing
	case "linux":
		f, err := os.Create(image)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Truncate(128 << 20); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		if filesystem == "exfat" {
			command("mkfs.exfat", image)
		} else {
			command("mkfs.fat", "-F", "32", image)
		}
		options := fmt.Sprintf("loop,uid=%d,gid=%d,umask=0077", os.Getuid(), os.Getgid())
		command("sudo", "-n", "mount", "-o", options, image, mount)
		t.Cleanup(func() { command("sudo", "-n", "umount", mount) })
	case "windows":
		image = filepath.Join(work, "metadata.vhd")
		if strings.ContainsAny(image, "\"\r\n") {
			t.Fatal("invalid diskpart image path")
		}
		letter := ""
		for ch := 'R'; ch <= 'Z'; ch++ {
			if _, err := os.Stat(string(ch) + ":\\"); os.IsNotExist(err) {
				letter = string(ch)
				break
			}
		}
		if letter == "" {
			t.Fatal("no unused drive letter for temporary metadata volume")
		}
		// Every diskpart operation selects this newly created VHD by full filename;
		// no command selects or formats an existing host disk.
		script := fmt.Sprintf("create vdisk file=\"%s\" maximum=128 type=expandable\r\nselect vdisk file=\"%s\"\r\nattach vdisk\r\ncreate partition primary\r\nformat fs=%s quick\r\nassign letter=%s\r\nexit\r\n", image, image, filesystem, letter)
		setup := filepath.Join(work, "create.txt")
		if err := os.WriteFile(setup, []byte(script), 0600); err != nil {
			t.Fatal(err)
		}
		cleanup := filepath.Join(work, "detach.txt")
		if err := os.WriteFile(cleanup, []byte(fmt.Sprintf("select vdisk file=\"%s\"\r\ndetach vdisk\r\nexit\r\n", image)), 0600); err != nil {
			t.Fatal(err)
		}
		// Microsoft requires at least 15 seconds between scripted invocations.
		// Register cleanup before setup so a partially attached private VHD is
		// still released when a later setup command fails.
		finished := time.Now()
		t.Cleanup(func() {
			if remaining := 15*time.Second - time.Since(finished); remaining > 0 {
				t.Logf("waiting %s before diskpart cleanup", remaining)
				if err := waitForImageDetach(context.Background(), remaining); err != nil {
					t.Error(err)
				}
			}
			command("diskpart", "/s", cleanup)
		})
		out, diagnostic, status := run(t, "diskpart", "/s", setup)
		finished = time.Now()
		if status != 0 {
			t.Fatalf("diskpart setup: status=%d stdout=%s stderr=%s", status, out, diagnostic)
		}
		t.Logf("diskpart setup: %s %s", out, diagnostic)
		mount = letter + ":\\"
	default:
		t.Fatal("metadata volume provisioning unavailable on", runtime.GOOS)
	}
	// A mounted-directory placeholder must never masquerade as a FAT volume.
	target := filepath.Join(mount, "selection")
	if err := os.WriteFile(target, []byte("selection"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	view, err := hostdata.FilesystemMetadataForFile(context.Background(), file)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if runtime.GOOS != "darwin" && !view.UsesAppleDouble() {
		view.Close()
		file.Close()
		t.Fatal("production filesystem selection did not identify FAT storage")
	}
	if err = view.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(target); err != nil {
		t.Fatal(err)
	}
	return mount
}

func TestFilesystemMetadataCLI(t *testing.T) {
	for _, filesystem := range []string{"fat32", "exfat"} {
		t.Run(filesystem, func(t *testing.T) {
			volume := metadataVolume(t, filesystem)
			for _, operation := range []string{"verify", "strip", "remove"} {
				t.Run(operation, func(t *testing.T) {
					dir, err := os.MkdirTemp(volume, "case-")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := os.RemoveAll(dir); err != nil {
							t.Error(err)
						}
					})
					t.Chdir(dir)
					data := nativeRead(t, filepath.Join(root, "testdata/macho/adhoc-arm64"))
					args := []string{"--verify", "--strict=sideband", "--verbose=1"}
					want := 1
					if operation == "strip" {
						args = []string{"-f", "-s", "-", "--strip-disallowed-xattrs"}
						want = 0
					}
					if operation == "remove" {
						data = []byte("#!/bin/sh\nexit 0\n")
						args = []string{"--remove-signature"}
						want = 0
					}
					seedKind := "strip"
					if operation == "remove" {
						seedKind = "remove"
					}
					wire := filesystemSeedInputs(t)[seedKind]
					// Keep basenames identical: codesign derives its default identifier
					// from the operand name, independently of metadata storage.
					for _, name := range []string{"fixture", "native/fixture"} {
						if err = os.MkdirAll(filepath.Dir(name), 0700); err != nil {
							t.Fatal(err)
						}
						if err = os.WriteFile(name, data, 0700); err != nil {
							t.Fatal(err)
						}
						// Match the native capture harness: remove any host-created carrier
						// before installing this explicit input, rather than truncate a cached
						// native carrier inode. Operation-produced metadata remains observable.
						carrier := filepath.Join(filepath.Dir(name), "._"+filepath.Base(name))
						if err = os.Remove(carrier); err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
						if err = os.WriteFile(carrier, wire, 0600); err != nil {
							t.Fatal(err)
						}
					}
					out, stderr, status := run(t, binaryPath, append(args, "fixture")...)
					nout, nerr, nstatus := "", "", -1
					if runtime.GOOS == "darwin" {
						nout, nerr, nstatus = run(t, apple(t), append(args, "native/fixture")...)
					}
					goCarrier, goCarrierErr := os.ReadFile("._fixture")
					nativeCarrier, nativeCarrierErr := os.ReadFile("native/._fixture")
					attest(t, map[string]any{"filesystem": filesystem, "operation": operation, "stage": "operation-result", "input_carrier": wire,
						"go_carrier": goCarrier, "go_carrier_read_error": fmt.Sprint(goCarrierErr), "native_carrier": nativeCarrier,
						"native_carrier_read_error": fmt.Sprint(nativeCarrierErr), "exit": status, "stdout": out, "stderr": stderr,
						"native_exit": nstatus, "native_stdout": nout, "native_stderr": nerr, "native_compared": runtime.GOOS == "darwin"})
					if status != want {
						t.Fatalf("status=%d want=%d stdout=%q stderr=%q; native=%d %q %q", status, want, out, stderr, nstatus, nout, nerr)
					}
					if runtime.GOOS == "darwin" && (nstatus != status || strings.ReplaceAll(nout, "native/fixture", "fixture") != out || strings.ReplaceAll(nerr, "native/fixture", "fixture") != stderr) {
						t.Fatalf("native mismatch: Go=%d %q %q native=%d %q %q", status, out, stderr, nstatus, nout, nerr)
					}
					f, err := os.Open("fixture")
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					view, err := hostdata.FilesystemMetadataForFile(context.Background(), f)
					if err != nil {
						t.Fatal(err)
					}
					defer view.Close()
					retained, present, err := view.Read(context.Background(), "com.example.retained", 100)
					if err != nil || !present || string(retained) != "retained" {
						t.Fatal("unrelated attribute lost", retained, present, err)
					}
					if operation == "strip" {
						for _, name := range []string{appledouble.FinderInfoName, appledouble.ResourceForkName} {
							if _, present, err := view.Size(context.Background(), name); err != nil || present {
								t.Fatal("prohibited metadata remains", name, present, err)
							}
						}
						mustRun(t, binaryPath, "--verify", "--strict=sideband", "fixture")
						if runtime.GOOS == "darwin" {
							mustRun(t, apple(t), "--verify", "--strict=sideband", "fixture")
						}
					} else {
						if !bytes.Equal(nativeRead(t, "fixture"), data) {
							t.Fatal("data fork changed")
						}
					}
					if operation == "remove" {
						if _, present, err := view.Size(context.Background(), "com.apple.cs.CodeDirectory"); err != nil || present {
							t.Fatal("signature attribute remains", present, err)
						}
					}
					result := filesystemCLIOutcome(t, filesystem, operation, "fixture", out, stderr, status)
					if runtime.GOOS == "darwin" {
						native := filesystemCLIOutcome(t, filesystem, operation, "native/fixture", nout, nerr, nstatus)
						if !reflect.DeepEqual(result, native) {
							for _, path := range []string{"fixture", "native/fixture"} {
								out, diagnostic, status := run(t, apple(t), "--display", "--verbose=4", path)
								t.Log("native display", path, status, out, diagnostic)
							}
							t.Fatalf("native filesystem output differs: data %s/%s carrier %s/%s", hash(result.Data), hash(native.Data), hash(result.Carrier), hash(native.Carrier))
						}
					}
					if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
						wire, err := json.Marshal(result)
						if err != nil {
							t.Fatal(err)
						}
						bundleWrite(t, export, "filesystem-cli-"+filesystem+"-"+operation+".json", wire)
					}
					attest(t, map[string]any{"filesystem": filesystem, "operation": operation, "exit": status, "stdout": out, "stderr": stderr, "native_compared": runtime.GOOS == "darwin", "retained_attribute": string(retained)})
				})
			}
		})
	}
}

func filesystemCaseDirectory(t *testing.T, volume string) string {
	t.Helper()
	dir, err := os.MkdirTemp(volume, "case-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func installFilesystemCarrier(t *testing.T, path string, wire []byte) {
	t.Helper()
	carrier := filepath.Join(filepath.Dir(path), "._"+filepath.Base(path))
	if err := os.Remove(carrier); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(carrier, wire, 0600); err != nil {
		t.Fatal(err)
	}
}
