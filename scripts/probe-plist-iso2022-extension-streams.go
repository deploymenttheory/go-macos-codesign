//go:build ignore

// Retain complete native values for state transitions, control handling and
// conversion-buffer boundaries in the two ISO-2022-JP extension families.
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
	Value  map[string]string
}
type capture struct {
	Schema int           `json:"schema"`
	Source string        `json:"source_sha256"`
	Native string        `json:"native_sha256"`
	MacOS  string        `json:"macos"`
	Cases  []observation `json:"cases"`
}

func main() {
	out := flag.String("out", "testdata/bundle-removal/plist-iso2022-extension-streams.json", "capture output")
	check := flag.Bool("check", false, "compare all fresh native records")
	flag.Parse()
	const reference = "testdata/bundle-removal/plist-iso2022-extension-streams.json"
	if *check {
		a, e := filepath.Abs(*out)
		must(e)
		b, e := filepath.Abs(reference)
		must(e)
		if a == b {
			panic("-check requires separate -out")
		}
	}
	dir, e := os.MkdirTemp("", "iso-extensions-streams-")
	must(e)
	defer os.RemoveAll(dir)
	mac, e := exec.Command("/usr/bin/sw_vers").Output()
	must(e)
	c := capture{Schema: 1, Source: hash(read("scripts/probe-plist-iso2022-extension-streams.go")), Native: hash(read("/usr/bin/plutil")), MacOS: string(mac)}
	observe := func(name, stringInput string) {
		o := observation{Name: name, Input: []byte(stringInput)}
		p := filepath.Join(dir, "Info.plist")
		must(os.WriteFile(p, o.Input, 0600))
		b, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", p).CombinedOutput()
		if err != nil {
			ex, ok := err.(*exec.ExitError)
			if !ok || ex.ExitCode() != 1 {
				panic(fmt.Sprintf("%s: %v %s", name, err, b))
			}
			o.Status = 1
		} else {
			must(json.Unmarshal(bytes.TrimSpace(b), &o.Value))
			if len(o.Value) != 2 || o.Value["CFBundleExecutable"] != "second" {
				panic(fmt.Sprintf("native root changed %s: %s", name, b))
			}
		}
		c.Cases = append(c.Cases, o)
	}
	states := []struct{ name, prefix, unit string }{{"ascii", "", "a"}, {"roman", "\x1b(J", "\\"}, {"kana", "\x1b(I", "!"}, {"jis0208", "\x1b$B", "\x24\x22"}, {"jis0212", "\x1b$(D", "\x22\x2f"}, {"gb2312", "\x1b$A", "!!"}, {"ksc5601", "\x1b$(C", "!!"}, {"latin", "\x1b.A\x1bN", "\x1bN!"}, {"greek", "\x1b.F\x1bN", "\x1bN!"}, {"roman-h", "\x1b(H", "\\"}, {"jis1978", "\x1b$@", "\x24\x22"}, {"jis1990", "\x1b&@", "\x24\x22"}, {"ascii-b", "\x1b(B", "a"}, {"latin-designated", "\x1b.A", "a"}, {"greek-designated", "\x1b.F", "a"}}
	endings := []struct{ name, raw string }{{"none", ""}, {"ascii-b", "\x1b(B"}, {"roman-h", "\x1b(H"}, {"roman", "\x1b(J"}, {"kana", "\x1b(I"}, {"jis1978", "\x1b$@"}, {"jis0208", "\x1b$B"}, {"jis1990", "\x1b&@"}, {"jis0212", "\x1b$(D"}, {"gb2312", "\x1b$A"}, {"ksc5601", "\x1b$(C"}, {"latin", "\x1b.A"}, {"greek", "\x1b.F"}, {"ss2", "\x1bN"}, {"kana-right", "\x1b)I"}, {"jis-d", "\x1b$D"}, {"jis-long-b", "\x1b$(B"}, {"double-reset", "\x1b(B\x1b(B"}, {"escape", "\x1b"}, {"partial-escape", "\x1b("}}
	controls := []struct{ name, raw string }{{"nul", "\x00"}, {"si", "\x0f"}, {"so", "\x0e"}, {"cr", "\r"}, {"lf", "\n"}, {"cr-roman", "\r\\~"}, {"lf-roman", "\n\\~"}, {"high80", "\x80"}, {"highff", "\xff"}, {"mid-pair", "\x24\x1b(B"}, {"ss2-return", "\x1bN!\\"}, {"ss2-repeat", "\x1bN\x1bN!\\"}, {"ss2-redesignate", "\x1b.A\x1bN\x1b.F!\\"}, {"newline-clears-g2", "\x1b.A\n\x1bN!"}, {"ss2-g0-switch", "\x1b.A\x1bN\x1b(J!\\"}}
	for _, name := range []string{"iso-2022-jp-1", "iso_2022_jp_1", "iso2022jp1", "iso-2022-jp-2", "iso_2022_jp_2", "iso2022jp2", "csiso2022jp2"} {
		decl := `<?xml encoding="` + name + `"?>`
		prefix := decl + `<dict><key>CFBundleExecutable</key><string>second</string><key>value</key><string><![CDATA[x`
		suffix := "\x1b(B]]>y</string></dict>"
		root := decl + `<dict><key>CFBundleExecutable</key><string>second</string><key>value</key><string>second</string></dict>`
		for _, st := range states {
			for _, end := range endings {
				v := st.prefix + end.raw + "\\\x22"
				observe(name+"/transition/"+st.name+"/"+end.name+"/body", prefix+v+suffix)
				observe(name+"/transition/"+st.name+"/"+end.name+"/tail", root+v)
			}
			for _, ctrl := range controls {
				v := st.prefix + ctrl.raw
				observe(name+"/control/"+st.name+"/"+ctrl.name+"/body", prefix+v+suffix)
				observe(name+"/control/"+st.name+"/"+ctrl.name+"/tail", root+v)
			}
			for _, units := range []int{503, 504, 505} {
				for _, end := range endings {
					start := strings.TrimSuffix(st.prefix, "\x1bN")
					input := root + start + strings.Repeat(st.unit, units-len(root)) + end.raw
					observe(fmt.Sprintf("%s/buffer/%s/%d/%s", name, st.name, units, end.name), input)
				}
			}
		}
	}
	if len(c.Cases) != 13650 {
		panic(fmt.Sprint("incomplete inventory: ", len(c.Cases)))
	}
	data, e := json.MarshalIndent(c, "", "  ")
	must(e)
	must(os.WriteFile(*out, append(data, '\n'), 0644))
	if *check {
		var old capture
		must(json.Unmarshal(read(reference), &old))
		if old.Source != c.Source || !reflect.DeepEqual(old.Cases, c.Cases) {
			panic("native ISO-2022 extension streams changed")
		}
	}
	fmt.Println("Captured and checked 13,650 complete native extension streams")
}
