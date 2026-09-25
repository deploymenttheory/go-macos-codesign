package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

const extractedXMLHeader = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0">`

func entitlementInput(t *testing.T, dir, format, value string) string {
	t.Helper()
	path, _ := certificateExtractionInput(t, dir, format, "adhoc")
	if value != "absent" {
		if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Force: true, ForceLibraryEntitlements: true, Identifier: "org.example.extract", Entitlements: []byte(`<plist version="1.0"><dict>` + value + `</dict></plist>`)}); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestEntitlementExtraction(t *testing.T) {
	profiles := []struct {
		name, value string
		invalidText bool
	}{
		{"absent", "absent", false}, {"empty", "", false},
		{"bool", "<key>test</key><true/>", false},
		{"integer", "<key>max</key><integer>9223372036854775807</integer><key>min</key><integer>-9223372036854775808</integer>", false},
		{"string", `<key>a&amp;&quot;</key><string>&lt;&amp;&gt;&quot;&apos;你好😀</string><key>empty</key><string></string>`, false},
		{"nested", "<key>test</key><dict><key>array</key><array><array><string>one</string></array><dict><key>b</key><false/></dict></array><key>empty</key><dict></dict></dict>", false},
		{"bool-array", "<key>test</key><array><true/><false/></array>", false},
		{"int-array", "<key>test</key><array><integer>1</integer><integer>-2</integer></array>", false},
		{"string-array", "<key>test</key><array><string>one</string><string></string></array>", false},
		{"empty-array", "<key>test</key><array></array>", false},
		{"mixed-string-bool", "<key>test</key><array><string>one</string><false/></array>", true},
		{"mixed-bool-string", "<key>test</key><array><false/><string>one</string></array>", true},
		{"mixed-int-bool", "<key>test</key><array><integer>1</integer><true/></array>", true},
		{"mixed-string-int", "<key>test</key><array><string>one</string><integer>1</integer></array>", true},
		{"string-dict", "<key>test</key><array><string>one</string><dict></dict></array>", false},
		{"dict-bool", "<key>test</key><array><dict></dict><true/></array>", false},
		{"separated-mixed", "<key>test</key><array><string>one</string><dict></dict><false/></array>", true},
	}
	for _, format := range []string{"arm64", "x86_64", "universal", "app", "framework", "dmg"} {
		for _, profile := range profiles {
			if format != "arm64" && profile.name != "bool" {
				continue
			}
			for _, mode := range []string{"text", "xml"} {
				t.Run(format+"/"+profile.name+"/"+mode, func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					path := entitlementInput(t, dir, format, profile.value)
					before := layoutArchive(t, dir)
					dest := "-"
					if mode == "xml" {
						dest = ":-"
					}
					args := []string{"-d", "--entitlements=" + dest, path}
					programs := []string{binaryPath}
					if runtime.GOOS == "darwin" {
						programs = append(programs, apple(t))
					}
					var goOut, goErr, nativeOut, nativeErr string
					status := 0
					if profile.invalidText && mode == "text" {
						status = 65
					}
					for i, exe := range programs {
						out, stderr, code := run(t, exe, args...)
						if code != status {
							t.Fatalf("%s exit %d want %d stdout=%q stderr=%q", exe, code, status, out, stderr)
						}
						if mode == "xml" && profile.name != "absent" {
							want := extractedXMLHeader + "<dict>" + profile.value + "</dict></plist>\n"
							nativeEqual(t, "XML", []byte(out), []byte(want))
						}
						if profile.name == "absent" || status != 0 {
							if out != "" {
								t.Fatal("unexpected output", out)
							}
						}
						if i == 0 {
							goOut, goErr = out, stderr
						} else {
							nativeOut, nativeErr = out, stderr
							nativeEqual(t, "stdout", []byte(out), []byte(goOut))
							nativeEqual(t, "stderr", []byte(stderr), []byte(goErr))
						}
						nativeEqual(t, "input preserved", layoutArchive(t, dir), before)
					}
					attest(t, map[string]any{"format": format, "profile": profile.name, "mode": mode, "exit": status, "stdout": goOut, "stderr": goErr, "native_stdout": nativeOut, "native_stderr": nativeErr, "output_sha256": hash([]byte(goOut)), "input_sha256": hash(before), "native_compared": len(programs) == 2, "input_preserved": true})
				})
			}
		}
	}
}

func TestEntitlementOutputLifecycle(t *testing.T) {
	for _, mode := range []string{"create", "overwrite", "hardlink", "symlink", "missing-parent", "directory", "colon-empty", "absent", "absent-existing", "mixed", "mixed-open-failure", "repeated", "empty-argument", "file-list", "file-list-failure", "multiple", "mixed-continue", "verbose", "json", "certificate-first", "certificate-failure", "certificate-success", "text-file", "multiple-stdout", "absent-multiple"} {
		t.Run(mode, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			value := "<key>test</key><true/>"
			if strings.HasPrefix(mode, "absent") {
				value = "absent"
			}
			if strings.HasPrefix(mode, "mixed") {
				value = "<key>test</key><array><string>one</string><false/></array>"
			}
			path := entitlementInput(t, dir, "arm64", value)
			if strings.HasPrefix(mode, "certificate-") {
				cert, _ := codesign.LoadIdentityPEM(nativeRead(t, filepath.Join(root, "testdata/identities/rsa-identity.pem")), nil)
				if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Force: true, Identity: cert, SigningTime: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC), Entitlements: []byte(`<plist><dict><key>test</key><true/></dict></plist>`)}); err != nil {
					t.Fatal(err)
				}
			}
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			var goOut, goErr, nativeOut, nativeErr string
			var after []byte
			var status int
			for i, exe := range programs {
				if err := os.RemoveAll("out"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir("out", 0755); err != nil {
					t.Fatal(err)
				}
				destination := "out/result"
				args := []string{"-d"}
				wantStatus := 0
				var saved os.FileInfo
				existing := mode == "overwrite" || mode == "hardlink" || mode == "symlink" || mode == "absent-existing" || mode == "mixed"
				if existing {
					if err := os.WriteFile("out/original", []byte("keep or truncate this output\n"), 0600); err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "hardlink":
						if err := os.Link("out/original", destination); err != nil {
							t.Fatal(err)
						}
					case "symlink":
						if err := os.Symlink("original", destination); err != nil {
							t.Fatal(err)
						}
					default:
						if err := os.Rename("out/original", destination); err != nil {
							t.Fatal(err)
						}
					}
					f, err := os.Open(destination)
					if err != nil {
						t.Fatal(err)
					}
					saved, err = f.Stat()
					_ = f.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
				switch mode {
				case "missing-parent", "mixed-open-failure":
					destination = "out/missing/result"
					wantStatus = 1
				case "directory":
					destination = "out"
					wantStatus = 1
				case "colon-empty":
					destination = ":"
					wantStatus = 1
				case "mixed", "mixed-continue":
					wantStatus = 65
				case "empty-argument":
					destination = ""
					wantStatus = 1
				case "repeated":
					args = append(args, "--entitlements=out/ignored")
				case "file-list":
					args = append(args, "--file-list=-")
					destination = ":-"
				case "file-list-failure":
					args = append(args, "--file-list=out/missing/list")
					destination = ":-"
					wantStatus = 1
				case "verbose":
					args[0] = "-dvvvv"
					destination = ":-"
				case "json":
					if exe != binaryPath {
						continue
					}
					args = append(args, "--json")
					destination = ":-"
				case "multiple-stdout":
					destination = ":-"
				case "certificate-failure":
					args = append(args, "--extract-certificates=out/missing/cert", "--file-list=out/list")
					destination = ":-"
					wantStatus = 1
				case "certificate-success":
					args = append(args, "--extract-certificates=out/cert", "--file-list=out/list")
					destination = ":-"
				case "certificate-first":
					args = append(args, "--extract-certificates=out/cert", "--file-list=out/list")
					destination = ":out/missing/result"
					wantStatus = 1
				}
				if mode != "text-file" && !strings.HasPrefix(mode, "mixed") && destination != "" && !strings.HasPrefix(destination, ":") {
					destination = ":" + destination
				}
				args = append(args, "--entitlements="+destination, path)
				if mode == "multiple" || mode == "multiple-stdout" || mode == "absent-multiple" {
					args = append(args, path)
				}
				if mode == "mixed-continue" {
					args = append(args, "--continue", path)
				}
				before := nativeRead(t, path)
				out, stderr, code := run(t, exe, args...)
				if code != wantStatus {
					t.Fatalf("%s exit=%d want=%d stdout=%q stderr=%q args=%v", exe, code, wantStatus, out, stderr, args)
				}
				nativeEqual(t, "input preserved", nativeRead(t, path), before)
				if saved != nil {
					info, err := os.Stat("out/result")
					if err != nil || !os.SameFile(saved, info) || info.Mode().Perm() != saved.Mode().Perm() {
						t.Fatal("output identity/mode changed", err)
					}
				}
				tree := layoutArchive(t, "out")
				if i == 0 {
					goOut, goErr, status, after = out, stderr, code, tree
				} else {
					nativeOut, nativeErr = out, stderr
					nativeEqual(t, "stdout", []byte(out), []byte(goOut))
					nativeEqual(t, "stderr", []byte(stderr), []byte(goErr))
					nativeEqual(t, "output tree", tree, after)
				}
			}
			attest(t, map[string]any{"mode": mode, "exit": status, "stdout": goOut, "stderr": goErr, "native_stdout": nativeOut, "native_stderr": nativeErr, "output_sha256": hash([]byte(goOut)), "tree_sha256": hash(after), "native_compared": runtime.GOOS == "darwin" && mode != "json", "portable_extension": mode == "json", "input_preserved": true})
		})
	}
}

func entitlementMutate(t *testing.T, input []byte, arch, state string) []byte {
	t.Helper()
	data := bytes.Clone(input)
	report, err := codesign.InspectBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	a, err := report.SelectArchitecture(arch)
	if err != nil {
		t.Fatal(err)
	}
	signature := data[a.Offset+a.SignatureOffset:]
	slots := map[uint32][]byte{}
	indices := map[uint32][]byte{}
	for i := uint32(0); i < binary.BigEndian.Uint32(signature[8:]); i++ {
		entry := signature[12+i*8:]
		slot, off := binary.BigEndian.Uint32(entry), binary.BigEndian.Uint32(entry[4:])
		size := binary.BigEndian.Uint32(signature[off+4:])
		slots[slot] = signature[off : off+size]
		indices[slot] = entry
	}
	cd := slots[codesign.SlotDirectory]
	bind := func(slot uint32) {
		sum := sha256.Sum256(slots[slot])
		offset := binary.BigEndian.Uint32(cd[16:]) - slot*32
		copy(cd[offset:], sum[:])
	}
	hide := func(slot uint32) { binary.BigEndian.PutUint32(indices[slot], 0x7770+slot) }
	switch state {
	case "xml-tamper":
		b := slots[5]
		b[len(b)-10] ^= 1
	case "der-tamper":
		b := slots[7]
		b[len(b)-1] ^= 1
	case "der-malformed-bound":
		slots[7][8] = 0x71
		bind(7)
	case "der-only":
		hide(5)
	case "xml-only":
		hide(7)
		binary.BigEndian.PutUint32(cd[24:], 5)
	case "xml-only-tamper":
		hide(7)
		binary.BigEndian.PutUint32(cd[24:], 5)
		b := slots[5]
		b[len(b)-10] ^= 1
	case "missing-der-bound":
		hide(7)
	case "unbound-der":
		off := binary.BigEndian.Uint32(cd[16:])
		clear(cd[off-7*32 : off-6*32])
	case "page-tamper":
		data[a.Offset+0x1000] ^= 1
	case "false":
		b := slots[7]
		b[len(b)-1] = 0
		bind(7)
	default:
		t.Fatal("unknown state", state)
	}
	return data
}

func TestEntitlementSignatureState(t *testing.T) {
	for _, state := range []string{"xml-tamper", "der-tamper", "der-malformed-bound", "der-only", "xml-only", "xml-only-tamper", "missing-der-bound", "unbound-der", "page-tamper"} {
		for _, mode := range []string{"xml", "text"} {
			t.Run(state+"/"+mode, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				path := entitlementInput(t, dir, "arm64", "<key>test</key><true/>")
				input := entitlementMutate(t, nativeRead(t, path), "", state)
				if err := os.WriteFile(path, input, 0755); err != nil {
					t.Fatal(err)
				}
				wantStatus := 0
				if state == "der-malformed-bound" && mode == "text" {
					wantStatus = 65
				}
				programs := []string{binaryPath}
				if runtime.GOOS == "darwin" {
					programs = append(programs, apple(t))
				}
				var goOut, goErr, nativeOut, nativeErr string
				var after []byte
				for i, exe := range programs {
					if err := os.WriteFile("out", []byte("preserve-prefix"), 0600); err != nil {
						t.Fatal(err)
					}
					dest := "out"
					if mode == "xml" {
						dest = ":" + dest
					}
					out, stderr, code := run(t, exe, "-d", "--entitlements="+dest, path)
					if code != wantStatus || out != "" {
						t.Fatalf("%s %d %q %q", exe, code, out, stderr)
					}
					if i == 0 {
						goOut, goErr, after = out, stderr, nativeRead(t, "out")
					} else {
						nativeOut, nativeErr = out, stderr
						nativeEqual(t, "stderr", []byte(stderr), []byte(goErr))
						nativeEqual(t, "entitlements", nativeRead(t, "out"), after)
					}
					nativeEqual(t, "input unchanged", nativeRead(t, path), input)
				}
				attest(t, map[string]any{"state": state, "mode": mode, "exit": wantStatus, "stdout": goOut, "stderr": goErr, "native_stdout": nativeOut, "native_stderr": nativeErr, "output_sha256": hash(after), "input_sha256": hash(input), "input_preserved": true, "native_compared": len(programs) == 2})
			})
		}
	}
}

func TestEntitlementArchitectureSelection(t *testing.T) {
	for _, arch := range []string{"default", "arm64", "x86_64"} {
		t.Run(arch, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			path := entitlementInput(t, dir, "universal", "<key>test</key><true/>")
			input := entitlementMutate(t, nativeRead(t, path), "x86_64", "false")
			if err := os.WriteFile(path, input, 0755); err != nil {
				t.Fatal(err)
			}
			args := []string{"-d", "--entitlements=:-"}
			if arch != "default" {
				args = append(args, "-a", arch)
			}
			args = append(args, path)
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			var goOut, goErr, nativeOut, nativeErr string
			want := "true"
			if arch == "x86_64" {
				want = "false"
			}
			for i, exe := range programs {
				out, stderr, code := run(t, exe, args...)
				if code != 0 || !strings.Contains(out, "<"+want+"/>") {
					t.Fatal(code, out, stderr)
				}
				if i == 0 {
					goOut, goErr = out, stderr
				} else {
					nativeOut, nativeErr = out, stderr
					nativeEqual(t, "stdout", []byte(out), []byte(goOut))
					nativeEqual(t, "stderr", []byte(stderr), []byte(goErr))
				}
				nativeEqual(t, "input unchanged", nativeRead(t, path), input)
			}
			attest(t, map[string]any{"architecture": arch, "exit": 0, "stdout": goOut, "stderr": goErr, "native_stdout": nativeOut, "native_stderr": nativeErr, "output_sha256": hash([]byte(goOut)), "input_sha256": hash(input), "input_preserved": true, "native_compared": len(programs) == 2})
		})
	}
}
