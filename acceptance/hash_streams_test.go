package acceptance

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Every host signs and verifies the same bundle corpus. The macOS runner also
// compares complete executable/envelope bytes against native ad-hoc signing.
func TestHashStreamBundleParity(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, size := range []int{65535, 65536, 65537, 131089} {
			t.Run(fmt.Sprintf("%s/%d", arch, size), func(t *testing.T) {
				data := make([]byte, size)
				for i := range data {
					x := uint64(i) + 1<<32 + 1
					data[i] = byte((x^x>>17^x>>32)*29 + 7)
				}
				makeBundle := func(name string) string {
					app := filepath.Join(t.TempDir(), name+".app")
					bundleFixture(t, app, arch)
					bundleWrite(t, app, "Contents/Resources/stream", data)
					return app
				}
				actual := makeBundle("Stream")
				args := []string{"-s", "-", "-i", "org.example.stream", "--timestamp=none"}
				mustRun(t, binaryPath, append(args, actual)...)
				mustRun(t, binaryPath, "--verify", "--strict", actual)
				for _, name := range []string{"Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources"} {
					got, err := os.ReadFile(filepath.Join(actual, name))
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("Go %s sha256=%s", name, hash(got))
				}
				if runtime.GOOS == "darwin" {
					reference := apple(t)
					expected := makeBundle("Stream")
					mustRun(t, reference, append(args, expected)...)
					mustRun(t, reference, "--verify", "--strict", actual)
					for _, name := range []string{"Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources"} {
						want, err := os.ReadFile(filepath.Join(expected, name))
						if err != nil {
							t.Fatal(err)
						}
						got, err := os.ReadFile(filepath.Join(actual, name))
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(want, got) {
							t.Fatalf("native bytes differ: %s", name)
						}
						t.Logf("Apple %s sha256=%s (byte equal)", name, hash(want))
					}
				}
			})
		}
	}
}
