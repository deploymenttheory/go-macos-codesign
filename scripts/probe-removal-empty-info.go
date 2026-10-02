//go:build ignore

// Capture absent/empty metadata discovery using disposable generic signatures.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func present(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	must(err)
	return true
}
func signature(path string) bool {
	_, err := exec.Command("/usr/bin/xattr", "-p", "com.apple.cs.CodeDirectory", path).Output()
	return err == nil
}
func main() {
	dir, err := os.MkdirTemp("", "codesign-empty-info-")
	must(err)
	defer os.RemoveAll(dir)
	var cases []map[string]any
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, state := range []string{"missing", "empty", "empty-dictionary"} {
			for _, location := range []string{"declared", "stem", "absent"} {
				operand, base, info, main := filepath.Join(dir, "A.app"), "Contents/", "Contents/Info.plist", "Contents/MacOS/hello"
				if shape != "app" {
					operand, base = filepath.Join(dir, "A.framework"), ""
					if shape == "framework" {
						base = "Versions/A/"
					}
					info, main = base+"Resources/Info.plist", base+"hello"
				}
				if location == "stem" {
					main = base + "A"
					if shape == "app" {
						main = base + "MacOS/A"
					}
				}
				for _, path := range []string{filepath.Dir(info), filepath.Dir(main), base + "_CodeSignature"} {
					must(os.MkdirAll(filepath.Join(operand, path), 0755))
				}
				if shape == "framework" {
					for name, target := range map[string]string{"Versions/Current": "A", "A": "Versions/Current/A", "Resources": "Versions/Current/Resources"} {
						must(os.Symlink(target, filepath.Join(operand, name)))
					}
				}
				write := func(name string, b []byte) { must(os.WriteFile(filepath.Join(operand, name), b, 0755)) }
				write(base+"_CodeSignature/CodeResources", []byte("envelope"))
				if state != "missing" {
					var b []byte
					if state == "empty-dictionary" {
						b = []byte("<plist><dict/></plist>")
					}
					write(info, b)
				}
				if location != "absent" {
					write(main, []byte("generic executable\n"))
				}
				before := map[string]os.FileInfo{}
				for _, name := range []string{info, main} {
					path := filepath.Join(operand, name)
					if present(path) {
						before[name], err = os.Stat(path)
						must(err)
						must(exec.Command("/usr/bin/xattr", "-w", "com.apple.cs.CodeDirectory", "attached signature", path).Run())
					}
				}
				out, err := exec.Command("/usr/bin/codesign", "--remove-signature", operand).CombinedOutput()
				status := 0
				if err != nil {
					status = err.(*exec.ExitError).ExitCode()
				}
				files := map[string]any{}
				for name, original := range before {
					path := filepath.Join(operand, name)
					after, err := os.Stat(path)
					must(err)
					files[name] = map[string]any{"sha256": hash(read(path)), "same_inode": os.SameFile(original, after), "signature": signature(path)}
				}
				cases = append(cases, map[string]any{"shape": shape, "state": state, "location": location, "info": info, "main": main, "status": status, "output": strings.ReplaceAll(string(out), operand, "$BUNDLE"), "files": files, "envelope": present(filepath.Join(operand, base+"_CodeSignature/CodeResources"))})
				must(os.RemoveAll(operand))
			}
		}
	}
	host, err := exec.Command("/usr/bin/sw_vers").Output()
	must(err)
	record := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/probe-removal-empty-info.go")), "native_sha256": hash(read("/usr/bin/codesign")), "macos": string(host), "cases": cases}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("testdata/bundle-removal/empty-info.json", append(b, '\n'), 0644))
	fmt.Println("captured", len(cases), "absent/empty metadata cases")
}
