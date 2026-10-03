//go:build ignore

// Capture every single-byte scalar through the native property-list parser.
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
	"unicode/utf8"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(name string, args ...string) []byte {
	b, e := exec.Command(name, args...).CombinedOutput()
	must(e)
	return b
}

type codec struct {
	Name           string
	Prefix, Suffix []byte
	Scalars        []int32
}
type capture struct {
	Schema int     `json:"schema"`
	MacOS  string  `json:"macos"`
	Native string  `json:"native_sha256"`
	Source string  `json:"source_sha256"`
	Codecs []codec `json:"codecs"`
}

func main() {
	out := flag.String("out", "testdata/bundle-removal/plist-legacy-values.json", "capture output")
	check := flag.Bool("check", false, "require fresh native scalars to match retained evidence")
	flag.Parse()
	const reference = "testdata/bundle-removal/plist-legacy-values.json"
	if *check {
		a, e := filepath.Abs(*out)
		must(e)
		b, e := filepath.Abs(reference)
		must(e)
		if a == b {
			panic("-check requires a separate -out path")
		}
	}
	names := []string{"us-ascii", "ascii", "ANSI_X3.4-1968", "ISO-8859-1", "iso_8859-1", "latin1", "latin-1", "ISO_8859-1:1987", "l1"}
	for _, n := range []int{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16} {
		names = append(names, fmt.Sprintf("ISO-8859-%d", n))
	}
	for _, n := range []int{874, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258} {
		names = append(names, fmt.Sprintf("windows-%d", n), fmt.Sprintf("cp%d", n))
	}
	for _, n := range []int{437, 850, 852, 855, 860, 862, 863, 865, 866} {
		names = append(names, fmt.Sprintf("IBM%d", n))
	}
	names = append(names, "KOI8-R", "KOI8-U", "x-mac-cyrillic")
	dir, e := os.MkdirTemp("", "legacy-values-")
	must(e)
	defer os.RemoveAll(dir)
	c := capture{Schema: 1, MacOS: string(run("/usr/bin/sw_vers")), Native: hash(read("/usr/bin/plutil")), Source: hash(read("scripts/probe-removal-legacy-values.go"))}
	for _, name := range names {
		entry := codec{Name: strings.ToLower(name), Prefix: []byte(`<?xml version="1.0" encoding="` + name + `"?><dict><key>value</key><string><![CDATA[`), Suffix: []byte(`]]></string></dict>`)}
		for value := 0; value < 256; value++ {
			data := append(bytes.Clone(entry.Prefix), byte(value))
			data = append(data, entry.Suffix...)
			path := filepath.Join(dir, "Info.plist")
			must(os.WriteFile(path, data, 0600))
			out, e := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", path).CombinedOutput()
			scalar := int32(-1)
			if e != nil {
				ex, ok := e.(*exec.ExitError)
				if !ok || ex.ExitCode() != 1 {
					panic(fmt.Sprintf("native failure: %v %s", e, out))
				}
			} else {
				var decoded map[string]string
				must(json.Unmarshal(out, &decoded))
				s, ok := decoded["value"]
				if !ok || len(decoded) != 1 || !utf8.ValidString(s) || utf8.RuneCountInString(s) != 1 {
					panic(fmt.Sprintf("non-scalar %s/%02x: %s", name, value, out))
				}
				scalar, _ = utf8.DecodeRuneInString(s)
			}
			entry.Scalars = append(entry.Scalars, scalar)
		}
		// Only qualify ASCII-compatible charsets in this profile; other codecs need
		// a separate whole-stream contract, not an inferred byte mapping.
		for n := 0; n < 128; n++ {
			if entry.Scalars[n] != int32(n) {
				panic(fmt.Sprintf("not ASCII-compatible: %s/%02x", name, n))
			}
		}
		c.Codecs = append(c.Codecs, entry)
	}
	data, e := json.MarshalIndent(c, "", "  ")
	must(e)
	must(os.WriteFile(*out, append(data, '\n'), 0644))
	if *check {
		var old capture
		must(json.Unmarshal(read(reference), &old))
		if !reflect.DeepEqual(c.Codecs, old.Codecs) || c.Source != old.Source {
			panic("native legacy scalar evidence changed")
		}
	}
	fmt.Printf("Captured %d native charsets, %d byte observations\n", len(c.Codecs), len(c.Codecs)*256)
}
