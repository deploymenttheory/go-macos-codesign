package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/bsdflags"
)

func TestPreserveAFSCEnvelopeNative(t *testing.T) {
	compressionEnvelopeNative(t, "")
}

func compressionEnvelopeNative(t *testing.T, parent string) {
	t.Helper()
	native := apple(t)
	var module struct{ Dir string }
	out, diagnostic, exit := run(t, "go", "list", "-m", "-json", "github.com/deploymenttheory/go-apfs-v2")
	if exit != 0 {
		t.Fatal(diagnostic)
	}
	if err := json.Unmarshal([]byte(out), &module); err != nil {
		t.Fatal(err)
	}
	producer := filepath.Join(t.TempDir(), "producer")
	observer := filepath.Join(t.TempDir(), "observer")
	mustRun(t, "clang", "-Wall", "-Wextra", "-framework", "CoreFoundation", filepath.Join(module.Dir, "testdata/appledouble/native/decmpfs-formats.c"), "-o", producer)
	mustRun(t, "clang", "-Wall", "-Wextra", filepath.Join(root, "testdata/research/compressed-signing.c"), "-o", observer)
	type outcome struct {
		Flags                             uint32 `json:"flags"`
		Size                              int64  `json:"size"`
		Exit                              int
		MainReplaced                      bool
		Stdout, Stderr                    string
		Data, Attribute, Fork, Executable []byte
	}
	for _, codec := range []string{"3", "7", "11"} {
		for _, profile := range []string{"ordinary", "deny-read", "deny-write", "deny-readextattr", "deny-writeextattr"} {
			for _, operation := range []string{"resign", "dryrun"} {
				t.Run(codec+"/"+profile+"/"+operation, func(t *testing.T) {
					var results [2]outcome
					for i, tool := range []string{native, binaryPath} {
						base := compressionCaseDirectory(t, parent)
						app := filepath.Join(base, "Example.app")
						bundleFixture(t, app, "arm64")
						for j := range 200 {
							if err := os.WriteFile(filepath.Join(app, "Contents/Resources", fmt.Sprintf("control-%03d", j)), []byte("compression envelope control"), 0644); err != nil {
								t.Fatal(err)
							}
						}
						mustRun(t, native, "-s", "-", "--timestamp=none", "-i", "envelope.original", app)
						envelope := filepath.Join(app, "Contents/_CodeSignature/CodeResources")
						before := nativeRead(t, envelope)
						if len(before) <= 16384 {
							t.Fatal("envelope does not reach compression eligibility", len(before))
						}
						mustRun(t, producer, "produce", codec, envelope, filepath.Join(base, "produced"))
						observed, diagnostic, exit := run(t, observer, envelope, filepath.Join(base, "before"))
						var initial outcome
						if err := json.Unmarshal([]byte(observed), &initial); err != nil || exit != 0 || initial.Flags&0x20 == 0 {
							t.Fatalf("compression setup: %s %s %v", observed, diagnostic, err)
						}
						if !bytes.Equal(before, nativeRead(t, envelope)) {
							t.Fatal("producer changed logical envelope bytes")
						}
						main := filepath.Join(app, "Contents/MacOS/hello")
						identity, err := os.Stat(main)
						if err != nil {
							t.Fatal(err)
						}
						if profile != "ordinary" {
							mustRun(t, "/bin/chmod", "+a", "everyone deny "+strings.TrimPrefix(profile, "deny-"), envelope)
						}
						args := []string{"-f", "-s", "-", "--timestamp=none", "-i", "envelope.replacement", "--preserve-afsc"}
						if operation == "dryrun" {
							args = append(args, "--dryrun")
						}
						stdout, stderr, code := run(t, tool, append(args, app)...)
						t.Logf("tool=%s profile=%s operation=%s exit=%d stdout=%q stderr=%q", tool, profile, operation, code, stdout, stderr)
						// Observe operation state before relaxing the test-owned ACL.
						// Reading storage is deliberately denied in readextattr cases.
						state, err := os.Stat(envelope)
						if err != nil {
							t.Fatal(err)
						}
						flags, ok := bsdflags.Flags(state)
						if !ok {
							t.Fatal("missing native BSD flags")
						}
						if profile != "ordinary" {
							mustRun(t, "/bin/chmod", "-N", envelope)
						}
						prefix := filepath.Join(base, "after")
						out, diagnostic, exit := run(t, observer, envelope, prefix)
						if exit != 0 {
							t.Fatal(diagnostic)
						}
						if err := json.Unmarshal([]byte(out), &results[i]); err != nil {
							t.Fatal(err)
						}
						results[i].Exit = code
						results[i].Stdout = strings.ReplaceAll(stdout, app, "<app>")
						results[i].Stderr = strings.ReplaceAll(stderr, app, "<app>")
						if results[i].Flags != flags || results[i].Size != state.Size() {
							t.Fatal("ACL cleanup changed compression state")
						}
						results[i].Data, results[i].Executable = nativeRead(t, envelope), nativeRead(t, main)
						for suffix, value := range map[string]*[]byte{".attr": &results[i].Attribute, ".fork": &results[i].Fork} {
							data, err := os.ReadFile(prefix + suffix)
							if err != nil && !os.IsNotExist(err) {
								t.Fatal(err)
							}
							*value = data
						}
						after, err := os.Stat(main)
						if err != nil {
							t.Fatal(err)
						}
						results[i].MainReplaced = !os.SameFile(identity, after)
					}
					a, b := results[0], results[1]
					if a.Stdout != b.Stdout || a.Stderr != b.Stderr {
						t.Fatalf("native/Go diagnostics differ: stdout=%q/%q stderr=%q/%q", a.Stdout, b.Stdout, a.Stderr, b.Stderr)
					}
					if a.Exit != b.Exit || a.Flags != b.Flags || a.Size != b.Size || a.MainReplaced != b.MainReplaced {
						t.Fatalf("native/Go exit=%d/%d flags=%#x/%#x size=%d/%d main replaced=%t/%t", a.Exit, b.Exit, a.Flags, b.Flags, a.Size, b.Size, a.MainReplaced, b.MainReplaced)
					}
					for name, pair := range map[string][2][]byte{"envelope": {a.Data, b.Data}, "attribute": {a.Attribute, b.Attribute}, "fork": {a.Fork, b.Fork}, "main": {a.Executable, b.Executable}} {
						if !bytes.Equal(pair[0], pair[1]) {
							t.Fatal("native/Go bytes differ", name)
						}
					}
				})
			}
		}
	}
}
