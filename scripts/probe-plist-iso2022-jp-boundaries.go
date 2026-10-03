//go:build ignore

// Capture the native property-list caller's 504-UTF-16-unit conversion boundary.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type observation struct {
	Name   string
	Input  []byte
	Status int
	Value  json.RawMessage
}
type capture struct {
	Schema int           `json:"schema"`
	Source string        `json:"source_sha256"`
	Native string        `json:"native_sha256"`
	MacOS  string        `json:"macos"`
	Cases  []observation `json:"cases"`
}

func main() {
	out := flag.String("out", "testdata/bundle-removal/plist-iso2022-jp-boundaries.json", "output")
	check := flag.Bool("check", false, "fresh comparison")
	flag.Parse()
	const reference = "testdata/bundle-removal/plist-iso2022-jp-boundaries.json"
	if *check {
		a, e := filepath.Abs(*out)
		must(e)
		b, e := filepath.Abs(reference)
		must(e)
		if a == b {
			panic("-check requires separate -out")
		}
	}
	dir, e := os.MkdirTemp("", "iso2022-boundaries-")
	must(e)
	defer os.RemoveAll(dir)
	mac, e := exec.Command("/usr/bin/sw_vers").Output()
	must(e)
	c := capture{Schema: 1, Source: hash(read("scripts/probe-plist-iso2022-jp-boundaries.go")), Native: hash(read("/usr/bin/plutil")), MacOS: string(mac)}
	states := []struct{ name, prefix, unit string }{{"ascii", "", "a"}, {"roman", "\x1b(J", "\\"}, {"kana", "\x1b(I", "!"}, {"jis0208", "\x1b$B", "\x24\x22"}, {"jis0212", "\x1b$(D", "\xa2\xaf"}, {"ascii-b", "\x1b(B", "a"}, {"ascii-h", "\x1b(H", "a"}, {"kana-right", "\x1b)I", "!"}, {"jis1978", "\x1b$@", "\x24\x22"}, {"jis-d", "\x1b$D", "\x24\x22"}}
	endings := []struct{ name, raw string }{{"none", ""}, {"ascii-b", "\x1b(B"}, {"ascii-h", "\x1b(H"}, {"roman", "\x1b(J"}, {"kana", "\x1b(I"}, {"kana-right", "\x1b)I"}, {"jis1978", "\x1b$@"}, {"jis0208", "\x1b$B"}, {"jis-d", "\x1b$D"}, {"jis0212", "\x1b$(D"}, {"final-scalar", "\x1b(Ba"}, {"escape", "\x1b"}, {"partial-escape", "\x1b("}, {"double-reset", "\x1b(B\x1b(B"}, {"reset-roman", "\x1b(B\x1b(J"}, {"roman-reset", "\x1b(J\x1b(B"}, {"reset-escape", "\x1b(B\x1b"}, {"reset-partial", "\x1b(B\x1b("}}
	for _, name := range []string{"iso-2022-jp", "iso_2022_jp", "iso2022jp", "csiso2022jp", "cp50221", "windows-50221"} {
		base := `<?xml encoding="` + name + `"?><dict><key>value</key><string>second</string></dict>`
		for _, st := range states {
			for _, units := range []int{503, 504, 505} {
				for _, end := range endings {
					input := []byte(base + st.prefix + strings.Repeat(st.unit, units-len(base)) + end.raw)
					o := observation{Name: fmt.Sprintf("%s/%s/%d/%s", name, st.name, units, end.name), Input: input}
					p := filepath.Join(dir, "Info.plist")
					must(os.WriteFile(p, input, 0600))
					value, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", p).CombinedOutput()
					if err != nil {
						ex, ok := err.(*exec.ExitError)
						if !ok || ex.ExitCode() != 1 {
							panic(fmt.Sprintf("%s: %v %s", o.Name, err, value))
						}
						o.Status = ex.ExitCode()
					} else {
						var got map[string]string
						must(json.Unmarshal(value, &got))
						if len(got) != 1 || got["value"] != "second" {
							panic("unexpected native root")
						}
						o.Value = bytes.TrimSpace(value)
					}
					c.Cases = append(c.Cases, o)
				}
			}
		}
	}
	if len(c.Cases) != 3240 {
		panic("incomplete boundary matrix")
	}
	if *check {
		var old capture
		must(json.Unmarshal(read(reference), &old))
		if c.Source != old.Source || !reflect.DeepEqual(c.Cases, old.Cases) {
			panic("native conversion boundary changed")
		}
	}
	data, e := json.MarshalIndent(c, "", "  ")
	must(e)
	must(os.WriteFile(*out, append(data, '\n'), 0644))
	fmt.Println("Captured 3,240 native conversion boundary cases")
}
