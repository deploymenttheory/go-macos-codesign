package acceptance

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestSigningSidebandRelativeNested(t *testing.T) {
	for _, location := range []string{"child-root", "child-main", "grandchild-main"} {
		t.Run(location, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			b, paths := sidebandBundleFixture(t, dir, "recursive")
			target := paths[location]
			metadata := appledouble.File{FinderInfo: [32]byte{1}}
			setSidebandObject(t, target, metadata)
			operand := filepath.Base(b)
			args := []string{"-fs", "-", "--deep", "--verbose=1"}
			before := layoutArchive(t, b)
			out, stderr, status := run(t, binaryPath, append(append([]string{}, args...), operand)...)
			want := operand + ": replacing existing signature\n" + operand + ": resource fork, Finder information, or similar detritus not allowed\nIn subcomponent: " + filepath.Join(b, filepath.FromSlash(recursiveApps[1])) + "\n"
			if runtime.GOOS == "linux" {
				if status != 0 {
					t.Fatal(status, out, stderr)
				}
				mustRun(t, binaryPath, "--verify", "--deep", operand)
			} else if status != 1 || out != "" || stderr != want {
				t.Fatal(status, out, stderr, want)
			}
			if runtime.GOOS != "linux" {
				nativeEqual(t, "failed tree preserved", before, layoutArchive(t, b))
			}
			if runtime.GOOS == "darwin" {
				setSidebandObject(t, target, metadata)
				nout, nerr, nstatus := run(t, apple(t), append(args, operand)...)
				if nout != out || nerr != stderr || nstatus != status {
					t.Fatal(nstatus, nout, nerr)
				}
				nativeEqual(t, "native failed tree preserved", before, layoutArchive(t, b))
			}
			attest(t, map[string]any{"operand": operand, "location": location, "status": status, "stdout": out, "stderr": stderr, "native_compared": runtime.GOOS == "darwin"})
		})
	}
}
