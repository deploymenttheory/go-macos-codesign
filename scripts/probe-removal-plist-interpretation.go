//go:build ignore

// Capture removal selection independently with the host's codesign binary.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	b, e := exec.Command(name, args...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s %v: %v: %s", name, args, e, b))
	}
	return b
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

var sourceFiles = map[string]string{}

func read(p string) []byte {
	b, e := os.ReadFile(p)
	must(e)
	if !filepath.IsAbs(p) {
		sourceFiles[filepath.ToSlash(p)] = hash(b)
	}
	return b
}

type observation struct {
	SHA256    string
	SameInode bool `json:"same_inode"`
	Signature bool
}
type record struct {
	Shape, State, Base, Info, Platform, Selected string
	Files                                        map[string][]byte
	Directories                                  []string
	Links                                        map[string]string
	Status                                       int
	Output                                       string
	Envelope                                     bool
	After                                        map[string]observation
}

func main() {
	out := flag.String("out", "testdata/bundle-removal/plist-interpretation.json", "capture output")
	profile := flag.String("profile", "interpretation", "interpretation, encodings, utf32, utf32-grammar, xml-characters, unmarked, legacy, shift-jis, euc-jp, iso2022-jp or iso2022-extensions")
	flag.Parse()
	helpers, e := filepath.Glob("scripts/probe-plist-inputs-*.go")
	must(e)
	if len(helpers) != 5 {
		panic("incomplete native input sources")
	}
	for _, path := range append(helpers, "scripts/probe-removal-plist-interpretation.go", "go.mod", "go.sum") {
		read(path)
	}
	selectedInputs := inputs()
	if *profile == "encodings" {
		selectedInputs = encodingInputs()
	} else if *profile == "utf32" {
		selectedInputs = utf32Inputs(false)
	} else if *profile == "utf32-grammar" {
		selectedInputs = utf32Inputs(true)
	} else if *profile == "xml-characters" {
		selectedInputs = xmlCharacterInputs()
	} else if *profile == "unmarked" {
		selectedInputs = unmarkedInputs()
	} else if *profile == "legacy" {
		selectedInputs = legacyInputs()
	} else if *profile == "iso2022-extensions" {
		selectedInputs = iso2022ExtensionInputs()
	} else if *profile == "iso2022-jp" {
		selectedInputs = iso2022JPInputs()
	} else if *profile == "euc-jp" {
		selectedInputs = eucJPInputs()
	} else if *profile == "shift-jis" {
		selectedInputs = shiftJISInputs()
	} else if *profile != "interpretation" {
		panic("unknown profile")
	}
	d, e := os.MkdirTemp("", "plist-interpretation-")
	must(e)
	defer os.RemoveAll(d)
	var cases []record
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, input := range selectedInputs {
			for _, location := range []string{"ordinary", "platform"} {
				state := location + "-" + input.name
				func() {
					p := filepath.Join(d, "A.app")
					base := "Contents/"
					info := base + "Info.plist"
					main := base + "MacOS/"
					if shape != "app" {
						p = filepath.Join(d, "A.framework")
						base = ""
						if shape == "framework" {
							base = "Versions/A/"
						}
						info = base + "Resources/Info.plist"
						main = base
					}
					platform := strings.TrimSuffix(info, ".plist") + "-macos.plist"
					tc := record{Shape: shape, State: state, Base: base, Info: info, Platform: platform, Directories: []string{filepath.ToSlash(filepath.Dir(info)), main, base + "_CodeSignature"}, Links: map[string]string{}, After: map[string]observation{}}
					plist := func(n string) []byte {
						return []byte("<plist><dict><key>CFBundleExecutable</key><string>" + n + "</string></dict></plist>")
					}
					tc.Files = map[string][]byte{info: plist("normal"), main + "normal": []byte("normal"), main + "first": []byte("first"), main + "second": []byte("second")}
					selectedInfo := info
					if location == "platform" {
						selectedInfo = platform
					}
					executableName := "second"
					if strings.HasPrefix(input.name, "unicode-executable-") {
						executableName = "あ"
						tc.Files[main+executableName] = []byte("unicode executable")
					}
					tc.Files[selectedInfo] = input.data
					tc.Selected = selectedInfo
					if input.executable {
						tc.Selected = main + executableName
					}
					if input.name == "binary-duplicate" {
						tc.Selected = main + "first"
					}
					for _, dir := range tc.Directories {
						must(os.MkdirAll(filepath.Join(p, dir), 0755))
					}
					if shape == "framework" {
						tc.Links = map[string]string{"Versions/Current": "A", "Resources": "Versions/Current/Resources", "A": "Versions/Current/A"}
						for n, v := range tc.Links {
							must(os.Symlink(v, filepath.Join(p, n)))
						}
					}
					before := map[string]os.FileInfo{}
					for n, b := range tc.Files {
						f := filepath.Join(p, n)
						must(os.WriteFile(f, b, 0755))
						run("/usr/bin/xattr", "-w", "com.apple.cs.CodeDirectory", "attached signature", f)
						run("/usr/bin/xattr", "-w", "user.codesign-control", "unchanged", f)
						before[n], e = os.Stat(f)
						must(e)
					}
					envelope := filepath.Join(p, base+"_CodeSignature/CodeResources")
					must(os.WriteFile(envelope, []byte("envelope"), 0644))
					output, err := exec.Command("/usr/bin/codesign", "--remove-signature", p).CombinedOutput()
					if err != nil || len(output) != 0 {
						panic(fmt.Sprintf("%s/%s: %v: %s", shape, state, err, output))
					}
					for n, b := range tc.Files {
						f := filepath.Join(p, n)
						attrs := strings.Fields(string(run("/usr/bin/xattr", f)))
						present := false
						for _, attr := range attrs {
							if attr == "com.apple.cs.CodeDirectory" {
								present = true
							}
						}
						after, e := os.Stat(f)
						must(e)
						tc.After[n] = observation{hash(read(f)), os.SameFile(before[n], after), present}
						if tc.After[n].SHA256 != hash(b) || !tc.After[n].SameInode || present != (n != tc.Selected) {
							panic(fmt.Sprintf("%s/%s unexpected mutation: %s %#v", shape, state, n, tc.After[n]))
						}
						if string(run("/usr/bin/xattr", "-p", "user.codesign-control", f)) != "unchanged\n" {
							panic("control attribute changed")
						}
					}
					_, e = os.Stat(envelope)
					if !os.IsNotExist(e) {
						panic(fmt.Sprintf("envelope retained: %v", e))
					}
					cases = append(cases, tc)
					must(os.RemoveAll(p))
				}()
			}
		}
	}
	result := map[string]any{"schema": 1, "macos": string(run("/usr/bin/sw_vers")), "codesign_sha256": hash(read("/usr/bin/codesign")), "source_sha256": hash(read("scripts/probe-removal-plist-interpretation.go")), "source_files_sha256": sourceFiles, "cases": cases}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	must(os.WriteFile(*out, append(b, '\n'), 0644))
	fmt.Println("Captured and checked", len(cases), "native plist-interpretation cases")
}
