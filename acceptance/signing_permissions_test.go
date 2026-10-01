package acceptance

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Exercise the published SDK's replacement contract through the actual CLI on
// every host. A write denial on readable source code must not deny writing its
// private replacement. Assert that the denial is effective before signing.
func TestSigningWriteDeniedSource(t *testing.T) {
	for _, shape := range []string{"standalone", "app", "recursive"} {
		for _, dry := range []bool{false, true} {
			name := shape + map[bool]string{false: "/sign", true: "/dryrun"}[dry]
			t.Run(name, func(t *testing.T) {
				dir := extractionDirectory(t)
				seed := func() (string, string) {
					if shape == "standalone" {
						path := filepath.Join(dir, "tool")
						copyFixture(t, "unsigned-universal", path)
						return path, path
					}
					operand, paths := sidebandBundleFixture(t, dir, shape)
					if shape == "recursive" {
						return operand, paths["child-main"]
					}
					return operand, paths["main"]
				}
				args := []string{"-fs", "-", "--deep", "-i", "org.example.permissions"}
				if dry {
					args = append(args, "--dryrun")
				}
				operand, _ := seed()
				wantOut, wantErr, wantStatus := run(t, binaryPath, append(args, operand)...)
				if wantStatus != 0 {
					t.Fatalf("unrestricted control: %s", wantErr)
				}
				want := signingSidebandBytes(t, operand, shape != "standalone")
				if err := os.RemoveAll(operand); err != nil {
					t.Fatal(err)
				}
				operand, target := seed()
				switch runtime.GOOS {
				case "darwin":
					mustRun(t, "/bin/chmod", "+a", "everyone deny write", target)
					t.Cleanup(func() { mustRun(t, "/bin/chmod", "-N", target) })
				case "windows":
					mustRun(t, "icacls", target, "/deny", "*S-1-1-0:(WD)")
					t.Cleanup(func() { mustRun(t, "icacls", target, "/remove:d", "*S-1-1-0") })
				case "linux":
					if err := os.Chmod(target, 0444); err != nil {
						t.Fatal(err)
					}
				}
				f, err := os.OpenFile(target, os.O_WRONLY, 0)
				if err == nil {
					f.Close()
					t.Fatal("source denial is ineffective")
				}
				if !errors.Is(err, os.ErrPermission) {
					t.Fatal(err)
				}
				before := signingSidebandBytes(t, operand, shape != "standalone")
				out, stderr, status := run(t, binaryPath, append(args, operand)...)
				after := signingSidebandBytes(t, operand, shape != "standalone")
				attest(t, map[string]any{"platform": runtime.GOOS, "args": append(args, operand), "denied_open": err.Error(), "status": status, "stdout": out, "stderr": stderr, "before": hash(before), "after": hash(after), "control": hash(want)})
				if status != wantStatus || out != wantOut || stderr != wantErr {
					t.Fatalf("denied-source %d %q %q; unrestricted %d %q %q", status, out, stderr, wantStatus, wantOut, wantErr)
				}
				nativeEqual(t, "write-denied source result", after, want)
				if dry {
					nativeEqual(t, "dry-run source", after, before)
				} else {
					mustRun(t, binaryPath, "--verify", "--deep", operand)
				}
			})
		}
	}
}
