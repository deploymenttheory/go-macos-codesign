//go:build ignore

// Capture platform plist selection with disposable generic signatures, no keys.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
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
func run(name string, args ...string) []byte {
	b, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%s %v: %v: %s", name, args, err, b))
	}
	return b
}
func hash(path string) string {
	b, err := os.ReadFile(path)
	must(err)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func plist(name string) []byte {
	return []byte("<plist><dict><key>CFBundleExecutable</key><string>" + name + "</string></dict></plist>")
}
func main() {
	output := flag.String("out", "testdata/bundle-removal/platform-info-research.json", "capture output path")
	flag.Parse()
	dir, err := os.MkdirTemp("", "platform-info-")
	must(err)
	defer os.RemoveAll(dir)
	var cases []map[string]any
	for _, scenario := range []string{"macos", "macosx", "macos-only", "empty-macos", "missing-target", "key-macos", "key-windows", "directory", "read", "readattr", "readsecurity", "readextattr", "write", "writeextattr"} {
		func() {
			app := filepath.Join(dir, "A.app")
			must(os.MkdirAll(filepath.Join(app, "Contents/MacOS"), 0755))
			must(os.MkdirAll(filepath.Join(app, "Contents/_CodeSignature"), 0755))
			defer os.RemoveAll(app)
			defer run("/bin/chmod", "-RN", app)
			files := map[string][]byte{"Contents/Info.plist": plist("normal"), "Contents/Info-macos.plist": plist("platform"), "Contents/MacOS/normal": []byte("normal"), "Contents/MacOS/platform": []byte("platform")}
			acl := ""
			switch scenario {
			case "macos":
			case "macos-only":
				delete(files, "Contents/Info.plist")
			case "empty-macos":
				files["Contents/Info-macos.plist"] = nil
			case "missing-target":
				delete(files, "Contents/MacOS/platform")
			case "macosx":
				files["Contents/Info-macosx.plist"] = files["Contents/Info-macos.plist"]
				delete(files, "Contents/Info-macos.plist")
			case "key-macos", "key-windows":
				delete(files, "Contents/Info-macos.plist")
				suffix := strings.TrimPrefix(scenario, "key-")
				files["Contents/Info.plist"] = []byte("<plist><dict><key>CFBundleExecutable</key><string>normal</string><key>CFBundleExecutable-" + suffix + "</key><string>platform</string></dict></plist>")
			case "directory":
				delete(files, "Contents/Info-macos.plist")
				must(os.Mkdir(filepath.Join(app, "Contents/Info-macos.plist"), 0755))
			default:
				acl = scenario
			}
			before := map[string]string{}
			identities := map[string]os.FileInfo{}
			for name, data := range files {
				path := filepath.Join(app, name)
				must(os.WriteFile(path, data, 0755))
				run("/usr/bin/xattr", "-w", "com.apple.cs.CodeDirectory", "attached", path)
				before[name] = hash(path)
				identities[name], err = os.Stat(path)
				must(err)
			}
			envelope := filepath.Join(app, "Contents/_CodeSignature/CodeResources")
			must(os.WriteFile(envelope, []byte("envelope"), 0644))
			if acl != "" {
				run("/bin/chmod", "+a", "everyone deny "+acl, filepath.Join(app, "Contents/Info-macos.plist"))
			}
			out, nativeErr := exec.Command("/usr/bin/codesign", "--remove-signature", app).CombinedOutput()
			status := 0
			if nativeErr != nil {
				var exit *exec.ExitError
				if !errors.As(nativeErr, &exit) {
					panic(nativeErr)
				}
				status = exit.ExitCode()
			}
			// Remove test ACLs before observation so attribute-read denial cannot
			// masquerade as a removed signature. This never changes the xattrs.
			run("/bin/chmod", "-RN", app)
			selected := ""
			after := map[string]any{}
			for name := range files {
				path := filepath.Join(app, name)
				names := strings.Fields(string(run("/usr/bin/xattr", path)))
				present := false
				for _, attr := range names {
					if attr == "com.apple.cs.CodeDirectory" {
						present = true
					}
				}
				if !present {
					if selected != "" {
						panic("multiple selections")
					}
					selected = name
				}
				st, err := os.Stat(path)
				must(err)
				same := os.SameFile(identities[name], st)
				if !same || hash(path) != before[name] {
					panic("native modified data or identity")
				}
				after[name] = map[string]any{"sha256": hash(path), "signature_present": present, "same_identity": same}
			}
			want, wantStatus := "Contents/MacOS/platform", 0
			switch scenario {
			case "macosx", "key-windows", "directory", "read":
				want = "Contents/MacOS/normal"
			case "empty-macos", "missing-target":
				want = "Contents/Info-macos.plist"
			case "readattr":
				want, wantStatus = "", 1
			}
			if selected != want || status != wantStatus {
				panic(fmt.Sprintf("%s: selected %s status %d: %s", scenario, selected, status, out))
			}
			_, err = os.Stat(envelope)
			envelopePresent := err == nil
			if err != nil && !os.IsNotExist(err) {
				panic(err)
			}
			if envelopePresent != (status != 0) {
				panic("unexpected envelope effect")
			}
			cases = append(cases, map[string]any{"name": scenario, "status": status, "output": strings.ReplaceAll(string(out), app, "<BUNDLE>"), "selected": selected, "before_sha256": before, "after": after, "envelope_present": envelopePresent})
		}()
	}
	record := map[string]any{"schema": 1, "macos": string(run("/usr/bin/sw_vers")), "codesign_sha256": hash("/usr/bin/codesign"), "source_sha256": hash("scripts/probe-removal-platform-info.go"), "cases": cases}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.MkdirAll(filepath.Dir(*output), 0755))
	must(os.WriteFile(*output, append(b, '\n'), 0644))
	fmt.Println("Captured and checked", len(cases), "native platform plist discovery cases")
}
