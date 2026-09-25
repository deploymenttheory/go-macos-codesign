package acceptance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFileListOutputLifecycle(t *testing.T) {
	for _, mode := range []string{"create", "append", "symlink", "hardlink", "repeated", "missing-parent", "directory", "empty", "sign-missing-parent", "sign-directory", "multiple-display", "multiple-sign", "certificate-first", "certificate-failure", "unsigned-stop", "unsigned-continue", "verify-ignored"} {
		t.Run(mode, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			var goErr, goOut string
			var after []byte
			for i, exe := range fileListPrograms(t) {
				for _, name := range []string{"inputs", "outputs"} {
					if err := os.RemoveAll(name); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(name, 0755); err != nil {
						t.Fatal(err)
					}
				}
				inputDir := filepath.Join(dir, "inputs")
				path, _ := certificateExtractionInput(t, inputDir, "arm64", "adhoc")
				if strings.HasPrefix(mode, "certificate") {
					if err := os.WriteFile(path, nativeRead(t, filepath.Join(root, "testdata/certificate-layout/rsa-arm64")), 0755); err != nil {
						t.Fatal(err)
					}
				}
				initial := nativeRead(t, path)
				second := filepath.Join(inputDir, "second")
				if err := os.WriteFile(second, initial, 0755); err != nil {
					t.Fatal(err)
				}
				destination := filepath.Join("outputs", "list")
				args := []string{"-d"}
				operands := []string{path}
				expected := ""
				expectedCode := 0
				expectedErr := "Executable=" + path + "\n"
				var original os.FileInfo
				if mode == "append" || mode == "symlink" || mode == "hardlink" {
					if err := os.WriteFile(destination, []byte("existing\n"), 0600); err != nil {
						t.Fatal(err)
					}
					f, err := os.Open(destination)
					if err != nil {
						t.Fatal(err)
					}
					original, err = f.Stat()
					if err != nil {
						t.Fatal(err)
					}
					if err = f.Close(); err != nil {
						t.Fatal(err)
					}
					expected = "existing\n"
					if mode == "symlink" || mode == "hardlink" {
						old := filepath.Join("outputs", "target")
						if err := os.Rename(destination, old); err != nil {
							t.Fatal(err)
						}
						if mode == "symlink" {
							layoutLink(t, dir, "outputs/list", "target")
						} else if err := os.Link(old, destination); err != nil {
							t.Fatal(err)
						}
					}
				}
				switch mode {
				case "repeated":
					args = append(args, "--file-list=outputs/unused")
				case "missing-parent", "sign-missing-parent", "certificate-first":
					destination = filepath.Join("outputs", "missing", "list")
				case "directory", "sign-directory":
					if err := os.Mkdir(destination, 0755); err != nil {
						t.Fatal(err)
					}
				case "empty":
					destination = ""
				case "multiple-display", "multiple-sign":
					operands = append(operands, second)
				case "unsigned-stop", "unsigned-continue":
					copyFixture(t, "unsigned-arm64", path)
					initial = nativeRead(t, path)
					operands = append(operands, second)
					expectedCode = 1
					expectedErr = path + ": code object is not signed at all\n"
					if mode == "unsigned-continue" {
						args = append(args, "--continue")
						expectedErr += "Executable=" + second + "\n"
					}
				case "verify-ignored":
					args = []string{"--verify"}
					expectedErr = ""
				}
				signing := strings.HasPrefix(mode, "sign-") || mode == "multiple-sign"
				if signing {
					args = []string{"-fs", "-", "-i", "org.example.changed"}
					expectedErr = path + ": replacing existing signature\n"
				}
				if mode == "multiple-display" {
					expectedErr += "Executable=" + second + "\n"
				}
				if mode == "multiple-sign" {
					expectedErr += second + ": replacing existing signature\n"
				}
				if mode == "certificate-first" {
					args = append(args, "--extract-certificates=outputs/cert")
				}
				if mode == "certificate-failure" {
					args = append(args, "--extract-certificates=outputs/missing/cert")
					expectedCode = 1
					expectedErr += path + ": No such file or directory\n"
				}
				outputFails := strings.Contains(mode, "missing-parent") || strings.Contains(mode, "directory") || mode == "empty" || mode == "certificate-first"
				if outputFails {
					expectedCode = 1
					why := "No such file or directory"
					if strings.Contains(mode, "directory") {
						why = "Is a directory"
					}
					if destination != "" {
						expectedErr += destination + ": "
					}
					expectedErr += why + "\n"
					// Opening the list terminates the process despite --continue. The second
					// target's display/signature is an independently observable stopping point.
					args = append(args, "--continue")
					operands = append(operands, second)
				}
				args = append(args, "--file-list="+destination)
				args = append(args, operands...)
				out, stderr, code := run(t, exe, args...)
				if code != expectedCode || out != "" || stderr != expectedErr {
					t.Fatalf("%s: exit=%d stdout=%q stderr=%q want exit=%d stderr=%q", exe, code, out, stderr, expectedCode, expectedErr)
				}
				if i == 0 {
					goOut, goErr = out, stderr
				} else if out != goOut || stderr != goErr {
					t.Fatal("native output differs")
				}
				if !outputFails && mode != "certificate-failure" && mode != "unsigned-stop" && mode != "verify-ignored" {
					if mode == "unsigned-continue" {
						expected += second + "\n"
					} else {
						for _, operand := range operands {
							expected += operand + "\n"
						}
					}
					if got := string(nativeRead(t, destination)); got != expected {
						t.Fatalf("list=%q want=%q", got, expected)
					}
					if original != nil {
						f, err := os.Open(destination)
						if err != nil {
							t.Fatal(err)
						}
						st, err := f.Stat()
						if err != nil {
							t.Fatal(err)
						}
						_ = f.Close()
						if !os.SameFile(original, st) || original.Mode() != st.Mode() {
							t.Fatal("append replaced identity/mode", original, st)
						}
					}
				} else if !outputFails {
					if _, err := os.Stat(destination); !os.IsNotExist(err) {
						t.Fatal("unexpected list", err)
					}
				}
				if mode == "repeated" {
					if _, err := os.Stat("outputs/unused"); !os.IsNotExist(err) {
						t.Fatal("earlier option created output", err)
					}
				}
				if signing {
					if string(nativeRead(t, path)) == string(initial) {
						t.Fatal("signing was not completed before file-list failure")
					}
				} else {
					nativeEqual(t, "first input preserved", nativeRead(t, path), initial)
				}
				if mode != "multiple-sign" {
					if mode == "unsigned-stop" || mode == "unsigned-continue" { // second retains the initially signed fixture
						if string(nativeRead(t, second)) == string(initial) {
							t.Fatal("second unexpectedly unsigned")
						}
					} else {
						nativeEqual(t, "second input preserved", nativeRead(t, second), initial)
					}
				}
				if mode == "certificate-first" {
					for _, name := range []string{"outputs/cert0"} {
						if len(nativeRead(t, name)) == 0 {
							t.Fatal("missing preceding certificate", name)
						}
					}
				}
				// The list contains OS-specific absolute fixture paths; compare all bytes to
				// native above, then hash the unchanged or newly signed inputs separately.
				current := layoutArchive(t, "inputs")
				if i == 0 {
					after = current
				} else {
					nativeEqual(t, "file-list lifecycle input effects", current, after)
				}
			}
			attest(t, map[string]any{"mode": mode, "native_compared": runtime.GOOS == "darwin", "exact_output": true, "input_sha256": hash(after), "side_effects_checked": true})
		})
	}
}
