//go:build ignore

// Capture native bundle-removal selection without keys or keychain access.
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
func read(p string) []byte   { b, e := os.ReadFile(p); must(e); return b }
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func main() {
	base, e := os.MkdirTemp("", "bundle-removal-")
	must(e)
	defer os.RemoveAll(base)
	var records []map[string]any
	source := read("testdata/bundles/arm64.app/Contents/Info.plist")
	for _, scenario := range []string{"missing", "missing-key", "empty-key", "bad-key", "legacy-key", "stem", "no-id", "no-type", "installer", "directory", "root", "contents", "historical-directory", "malformed-info", "readsecurity", "readattr", "read", "readextattr", "write", "writeextattr"} {
		app := filepath.Join(base, "A.app")
		must(os.CopyFS(app, os.DirFS("testdata/bundles/arm64.app")))
		main := filepath.Join(app, "Contents/MacOS/hello")
		info := filepath.Join(app, "Contents/Info.plist")
		s := string(source)
		switch scenario {
		case "missing":
			must(os.Remove(main))
		case "missing-key", "stem":
			s = strings.ReplaceAll(s, "<key>CFBundleExecutable</key><string>hello</string>", "")
			if scenario == "stem" {
				must(os.Rename(main, filepath.Join(app, "Contents/MacOS/A")))
			}
		case "empty-key":
			s = strings.ReplaceAll(s, "<string>hello</string>", "<string></string>")
		case "bad-key":
			s = strings.ReplaceAll(s, "<string>hello</string>", "<integer>1</integer>")
		case "legacy-key":
			s = strings.ReplaceAll(s, "CFBundleExecutable", "NSExecutable")
		case "no-id":
			s = strings.ReplaceAll(s, "CFBundleIdentifier", "OtherIdentifier")
		case "no-type":
			s = strings.ReplaceAll(s, "CFBundlePackageType", "OtherType")
		case "installer":
			s = strings.ReplaceAll(s, "</dict>", "<key>IFMajorVersion</key><integer>1</integer></dict>")
			must(os.Remove(main))
		case "directory":
			must(os.Remove(main))
			must(os.Mkdir(main, 0755))
		case "root":
			must(os.Rename(main, filepath.Join(app, "hello")))
		case "contents":
			must(os.Rename(main, filepath.Join(app, "Contents/hello")))
		case "historical-directory":
			must(os.Mkdir(filepath.Join(app, "Contents/Mac OS X"), 0755))
			must(os.Rename(main, filepath.Join(app, "Contents/Mac OS X/hello")))
		case "malformed-info":
			s = "not a plist"
		}
		must(os.WriteFile(info, []byte(s), 0644))
		must(exec.Command("/usr/bin/xattr", "-w", "com.apple.cs.CodeDirectory", "info-signature", info).Run())
		before := digest(read(info))
		if strings.HasPrefix(scenario, "read") || strings.HasPrefix(scenario, "write") {
			must(exec.Command("/bin/chmod", "+a", "everyone deny "+scenario, main).Run())
		}
		root, e := os.OpenRoot(app)
		must(e)
		_, discoveryErr := root.Lstat("Contents/MacOS/hello")
		must(root.Close())
		out, err := exec.Command("/usr/bin/codesign", "--remove-signature", app).CombinedOutput()
		status := 0
		if err != nil {
			status = err.(*exec.ExitError).ExitCode()
		}
		must(exec.Command("/bin/chmod", "-RN", app).Run())
		_, attrErr := exec.Command("/usr/bin/xattr", "-p", "com.apple.cs.CodeDirectory", info).Output()
		_, envelopeErr := os.Stat(filepath.Join(app, "Contents/_CodeSignature/CodeResources"))
		records = append(records, map[string]any{"scenario": scenario, "status": status, "output": strings.ReplaceAll(string(out), base, "$PROBE"), "info_signature_removed": attrErr != nil, "envelope_removed": os.IsNotExist(envelopeErr), "info_before_sha256": before, "info_after_sha256": digest(read(info)), "go_rooted_stat_permission_denied": os.IsPermission(discoveryErr)})
		must(os.RemoveAll(app))
	}
	host, e := exec.Command("/usr/bin/sw_vers").Output()
	must(e)
	result := map[string]any{"schema": 1, "driver_sha256": digest(read("scripts/probe-bundle-removal.go")), "fixture_info_sha256": digest(source), "native_sha256": digest(read("/usr/bin/codesign")), "macos": string(host), "cases": records}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.MkdirAll("testdata/bundle-removal", 0755))
	must(os.WriteFile("testdata/bundle-removal/native.json", append(b, '\n'), 0644))
	fmt.Println("captured", len(records), "native discovery cases")
}
