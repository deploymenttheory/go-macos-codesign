package acceptance

import (
	"encoding/json"
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
			encoded, err := metadata.Encode()
			if err != nil {
				t.Fatal(err)
			}
			bundleWrite(t, dir, "metadata.ad", encoded)
			rel, err := filepath.Rel(b, target)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := json.Marshal(map[string]string{filepath.ToSlash(rel): "metadata.ad"})
			if err != nil {
				t.Fatal(err)
			}
			bundleWrite(t, dir, "metadata.json", manifest)
			operand := filepath.Base(b)
			args := []string{"-fs", "-", "--deep", "--verbose=1"}
			before := layoutArchive(t, b)
			out, stderr, status := run(t, binaryPath, append(append([]string{}, args...), "--appledouble-map", "metadata.json", operand)...)
			want := operand + ": replacing existing signature\n" + operand + ": resource fork, Finder information, or similar detritus not allowed\nIn subcomponent: " + filepath.Join(b, filepath.FromSlash(recursiveApps[1])) + "\n"
			if status != 1 || out != "" || stderr != want {
				t.Fatal(status, out, stderr, want)
			}
			nativeEqual(t, "failed tree preserved", before, layoutArchive(t, b))
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
