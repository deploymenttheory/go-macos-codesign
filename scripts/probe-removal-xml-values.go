//go:build ignore

// Retain current CoreFoundation string interpretation independently of Go's XML
// implementation. codesign selection/mutation is captured by the companion probe.
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
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(name string, args ...string) []byte {
	b, e := exec.Command(name, args...).CombinedOutput()
	must(e)
	return b
}
func main() {
	out := flag.String("out", "testdata/bundle-removal/plist-xml-values.json", "capture output")
	flag.Parse()
	dir, e := os.MkdirTemp("", "xml-values-")
	must(e)
	defer os.RemoveAll(dir)
	type observation struct {
		Name   string
		Input  []byte
		Status int
		Value  json.RawMessage
	}
	var cases []observation
	sources := map[string]string{}
	for _, file := range []string{"plist-xml-characters.json", "plist-utf32-grammar.json"} {
		data := read("testdata/bundle-removal/" + file)
		sources[file] = hash(data)
		var corpus struct {
			Cases []struct {
				Shape, State, Info string
				Files              map[string][]byte
			}
		}
		must(json.Unmarshal(data, &corpus))
		for _, tc := range corpus.Cases {
			if tc.Shape != "app" || !strings.HasPrefix(tc.State, "ordinary-") {
				continue
			}
			item := observation{Name: file + "/" + tc.State, Input: tc.Files[tc.Info]}
			input := filepath.Join(dir, "Info.plist")
			must(os.WriteFile(input, item.Input, 0600))
			output, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", input).CombinedOutput()
			if err != nil {
				ex, ok := err.(*exec.ExitError)
				if !ok {
					panic(err)
				}
				item.Status = ex.ExitCode()
			} else {
				if !json.Valid(output) {
					panic("native output is not JSON")
				}
				item.Value = output
			}
			cases = append(cases, item)
		}
	}
	result := map[string]any{"schema": 1, "macos": string(run("/usr/bin/sw_vers")), "native_sha256": hash(read("/usr/bin/plutil")), "source_sha256": hash(read("scripts/probe-removal-xml-values.go")), "corpus_sha256": sources, "cases": cases}
	data, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile(*out, append(data, '\n'), 0644))
	fmt.Println("Captured", len(cases), "native XML values")
}
