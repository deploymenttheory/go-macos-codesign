package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This opt-in research probe intentionally observes a native failure. Ordinary
// CI reads the pinned record and never repeatedly crashes the reference tool.
func TestRecordDMGCertificateDryRunFailure(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_RECORD_DMG_DRYRUN") != "1" {
		t.Skip("opt-in native certificate failure recording")
	}
	cases := []map[string]any{}
	for _, algorithm := range []string{"rsa", "p256"} {
		keychain := nativeTestKeychain(t, algorithm)
		for _, state := range []string{"unsigned", "signed"} {
			path := filepath.Join(t.TempDir(), "image.dmg")
			seedDryRunDMG(t, apple(t), path, "apfs", state)
			before := nativeRead(t, path)
			info := accessFileInfo(t, path)
			args := []string{"--keychain", keychain, "-fs", "Public codesign test identity " + algorithm, "--timestamp=none", "--dryrun", path}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			cmd := exec.CommandContext(ctx, apple(t), args...)
			output, err := cmd.CombinedOutput()
			cancel()
			if err == nil || cmd.ProcessState == nil {
				t.Fatalf("expected native termination: %v %s", err, output)
			}
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGSEGV && status.Signal() != syscall.SIGBUS {
				t.Fatalf("unexpected native failure: %v %v %s", status, err, output)
			}
			after := accessFileInfo(t, path)
			if !os.SameFile(info, after) || !info.ModTime().Equal(after.ModTime()) || !bytes.Equal(before, nativeRead(t, path)) {
				t.Fatal("native certificate failure changed input")
			}
			args[1] = "<temporary-public-test-keychain>"
			args[len(args)-1] = "<temporary-image>"
			cases = append(cases, map[string]any{"algorithm": algorithm, "state": state, "arguments": args, "signal": status.Signal().String(), "signal_number": int(status.Signal()), "exit": cmd.ProcessState.ExitCode(), "output": strings.ReplaceAll(string(output), path, "<temporary-image>"), "input_sha256": hash(before), "bytes_inode_mtime_preserved": true, "identity_sha256": hash(nativeRead(t, filepath.Join(root, "testdata/identities", algorithm+"-identity.pem")))})
		}
	}
	host, err := exec.Command("/usr/bin/sw_vers").Output()
	if err != nil {
		t.Fatal(err)
	}
	record := map[string]any{"schema": 1, "scope": "Opt-in native certificate DMG dry-run failure observations. Public test identities only. Production returns ErrUnsupported before writing rather than emulating native memory faults; certificate dry-run parity remains unimplemented.", "recorded_at": time.Now().UTC(), "host": strings.TrimSpace(string(host)), "codesign_sha256": hash(nativeRead(t, apple(t))), "driver": "acceptance/dmg_dryrun_darwin_test.go", "driver_sha256": hash(nativeRead(t, filepath.Join(root, "acceptance/dmg_dryrun_darwin_test.go"))), "cases": cases}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "spec/apple-dmg-dryrun-certificate.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDMGDryRunWritePermissions(t *testing.T) {
	for _, state := range []string{"unsigned", "signed"} {
		for _, denial := range []string{"file", "directory"} {
			t.Run(state+"/"+denial, func(t *testing.T) {
				var outputs [][]byte
				for _, exe := range []string{binaryPath, apple(t)} {
					dir := t.TempDir()
					path := filepath.Join(dir, "image.dmg")
					seedDryRunDMG(t, exe, path, "zlib", state)
					before := nativeRead(t, path)
					info := accessFileInfo(t, path)
					target, mode := path, os.FileMode(0o444)
					if denial == "directory" {
						target, mode = dir, 0o555
					}
					if err := os.Chmod(target, mode); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(target, 0o755) })
					out, stderr, status := run(t, exe, append(dmgDryRunArgs("plain"), path)...)
					want := 0
					if denial == "file" {
						want = 1
					}
					if status != want {
						t.Fatalf("%s denial %s: %d %s%s", exe, denial, status, out, stderr)
					}
					after := accessFileInfo(t, path)
					data := nativeRead(t, path)
					if !os.SameFile(info, after) {
						t.Fatal("dry run replaced inode")
					}
					if want == 1 && (!bytes.Equal(before, data) || !info.ModTime().Equal(after.ModTime())) {
						t.Fatal("denied write changed input")
					}
					if want == 0 {
						assertUnsignedDMG(t, exe, path)
					}
					outputs = append(outputs, data)
				}
				nativeEqual(t, "permission result", outputs[0], outputs[1])
				attest(t, map[string]any{"state": state, "denial": denial, "native_compared": true, "byte_equal": true, "inode_preserved": true})
			})
		}
	}
}
