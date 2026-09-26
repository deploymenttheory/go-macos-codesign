package acceptance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestRequirementSetCompilation(t *testing.T) {
	var evidence struct {
		Native struct {
			Cases map[string]struct {
				Source string
				Exit   int
				Hex    string `json:"compiled_hex"`
			}
		}
	}
	if err := json.Unmarshal(nativeRead(t, filepath.Join(root, "spec/apple-requirement-sets.json")), &evidence); err != nil {
		t.Fatal(err)
	}
	for name, record := range evidence.Native.Cases {
		t.Run(name, func(t *testing.T) {
			got, err := codesign.CompileRequirements(record.Source)
			if (err == nil) != (record.Exit == 0) {
				t.Fatalf("compile status differs: %v", err)
			}
			want, e := hex.DecodeString(record.Hex)
			if e != nil {
				t.Fatal(e)
			}
			if err == nil {
				nativeEqual(t, "pinned native bytes", got, want)
			}
			nativeOut, nativeErr := "", ""
			if runtime.GOOS == "darwin" {
				path := filepath.Join(t.TempDir(), "compiled")
				var code int
				nativeOut, nativeErr, code = run(t, "/usr/bin/csreq", "-r", "="+record.Source, "-b", path)
				if code != record.Exit {
					t.Fatalf("current native status changed: %d %q %q", code, nativeOut, nativeErr)
				}
				if code == 0 {
					nativeEqual(t, "current native bytes", got, nativeRead(t, path))
				}
			}
			attest(t, map[string]any{"source": record.Source, "exit": record.Exit, "compiled_sha256": hash(got), "native_compared": runtime.GOOS == "darwin", "native_stdout": nativeOut, "native_stderr": nativeErr, "pinned_reference_compared": true})
		})
	}
}

func TestRequirementSetSigning(t *testing.T) {
	const source = "# unordered and repeated\nplugin => never; host => never guest => never designated => never library => always designated => always;"
	compiled, err := codesign.CompileRequirements(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"arm64", "x86_64", "universal", "app", "framework", "dmg"} {
		for _, form := range []string{"inline", "source-file", "binary-file"} {
			t.Run(format+"/"+form, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				argument := "=" + source
				if form != "inline" {
					argument = filepath.Join(dir, "requirements")
					data := []byte(source)
					if form == "binary-file" {
						data = compiled
					}
					if e := os.WriteFile(argument, data, 0644); e != nil {
						t.Fatal(e)
					}
				}
				programs := []string{binaryPath}
				if runtime.GOOS == "darwin" {
					programs = append(programs, apple(t))
				}
				var goAfter, goBefore []byte
				var goOut, goErr, goText, goDisplay string
				for i, exe := range programs {
					workspace := filepath.Join(dir, "fixture")
					if e := os.RemoveAll(workspace); e != nil {
						t.Fatal(e)
					}
					if e := os.Mkdir(workspace, 0755); e != nil {
						t.Fatal(e)
					}
					path, _ := certificateExtractionInput(t, workspace, format, "adhoc")
					before := layoutArchive(t, workspace)
					out, stderr, code := run(t, exe, "-f", "-s", "-", "-i", "org.example.extract", "-r", argument, path)
					if code != 0 {
						t.Fatalf("sign exit=%d stdout=%q stderr=%q", code, out, stderr)
					}
					after := layoutArchive(t, workspace)
					report, e := codesign.Verify(context.Background(), path, codesign.VerifyOptions{})
					if e != nil {
						t.Fatal(e)
					}
					for _, arch := range report.Architectures {
						nativeEqual(t, "embedded set", signatureBlob(arch.Signature, codesign.SlotRequirements), compiled)
					}
					text, display, status := run(t, exe, "-d", "-r-", path)
					if status != 0 {
						t.Fatalf("display: %d %q", status, display)
					}
					if runtime.GOOS == "darwin" {
						mustRun(t, apple(t), "--verify", "--strict", path)
					}
					if i == 0 {
						goAfter, goBefore = after, before
						goOut, goErr, goText, goDisplay = out, stderr, text, display
					} else {
						nativeEqual(t, "initial input", before, goBefore)
						nativeEqual(t, "complete signed tree", after, goAfter)
						nativeEqual(t, "sign stdout", []byte(out), []byte(goOut))
						nativeEqual(t, "sign stderr", []byte(stderr), []byte(goErr))
						nativeEqual(t, "requirement text", []byte(text), []byte(goText))
						nativeEqual(t, "display stderr", []byte(display), []byte(goDisplay))
					}
				}
				attest(t, map[string]any{"format": format, "form": form, "input_sha256": hash(goBefore), "signed_tree_sha256": hash(goAfter), "requirements_sha256": hash(compiled), "text_sha256": hash([]byte(goText)), "stdout": goOut, "stderr": goErr, "requirement_text": goText, "native_compared": len(programs) == 2, "portable_verified": true, "native_strict_verified": len(programs) == 2, "complete_bytes_equal": len(programs) == 2})
			})
		}
	}
}

func TestRequirementSetRejectedSource(t *testing.T) {
	for name, source := range map[string]string{"arrow": "host = > always", "empty": "host =>", "kind": "unknown => always", "comma": "host => always, guest => never", "comment": "host => always /*", "literal": "designated => identifier \"unfinished"} {
		for _, form := range []string{"inline", "file"} {
			t.Run(name+"/"+form, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				copyFixture(t, "unsigned-arm64", "first")
				copyFixture(t, "unsigned-x86_64", "second")
				argument := "=" + source
				if form == "file" {
					argument = "requirements"
					if err := os.WriteFile(argument, []byte(source), 0644); err != nil {
						t.Fatal(err)
					}
				}
				before := layoutArchive(t, dir)
				programs := []string{binaryPath}
				if runtime.GOOS == "darwin" {
					programs = append(programs, apple(t))
				}
				var goErr, nativeErr string
				for i, exe := range programs {
					out, stderr, code := run(t, exe, "-s", "-", "--continue", "-r", argument, "first", "second")
					if code != 1 || out != "" || stderr == "" {
						t.Fatalf("rejection: %d %q %q", code, out, stderr)
					}
					nativeEqual(t, "rejected source preserves all operands", layoutArchive(t, dir), before)
					if i == 0 {
						goErr = stderr
					} else {
						nativeErr = stderr
					}
				}
				attest(t, map[string]any{"source": source, "form": form, "exit": 1, "input_sha256": hash(before), "all_operands_preserved": true, "native_compared": len(programs) == 2, "stderr": goErr, "native_stderr": nativeErr, "exact_diagnostic_claimed": false})
			})
		}
	}
}
