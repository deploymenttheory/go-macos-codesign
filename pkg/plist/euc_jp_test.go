package plist_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/plist"
)

// Every one/two-byte string and every 0x8f-prefixed triple, for every qualified alias, is independently
// observed through native CFPropertyListCreateWithData in body and EOF contexts.
func TestEUCJPNativeStreams(t *testing.T) {
	read := func(p string) []byte {
		t.Helper()
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	var c struct {
		Schema            int
		MacOS, SDK, Clang string
		Native            string `json:"native_sha256"`
		Source            string `json:"source_sha256"`
		Oracle            string `json:"oracle_sha256"`
		Codecs            []struct {
			Name   string
			Table  int
			SHA256 string
		}
		Tables []struct {
			Singles, Pairs, Triples []*string
			TailValid               []bool
		}
	}
	if e := json.Unmarshal(read("../../testdata/bundle-removal/plist-euc-jp-values.json"), &c); e != nil {
		t.Fatal(e)
	}
	driver := read("../../scripts/probe-plist-euc-jp.go")
	if c.Schema != 1 || c.MacOS == "" || c.SDK == "" || c.Clang == "" || len(c.Native) != 64 || len(c.Oracle) != 64 || c.Source != hash(driver) || len(c.Codecs) != 8 || len(c.Tables) != 1 {
		t.Fatal("invalid native provenance/inventory")
	}
	names := []string{"euc-jp", "euc_jp", "eucjp", "cseucpkdfmtjapanese", "extended_unix_code_packed_format_for_japanese", "x-euc-jp", "cp51932", "windows-51932"}
	for i, codec := range c.Codecs {
		want := 0
		if codec.Name != names[i] || codec.Table != want {
			t.Fatal("unexpected native family", codec)
		}
		t.Run(codec.Name, func(t *testing.T) {
			table := c.Tables[codec.Table]
			if len(table.Singles) != 256 || len(table.Pairs) != 65536 || len(table.Triples) != 65536 || len(table.TailValid) != 131328 {
				t.Fatal("missing byte observations")
			}
			values := append(append(append([]*string{}, table.Singles...), table.Pairs...), table.Triples...)
			var rawBody, rawTail strings.Builder
			for n, want := range values {
				raw := []byte{byte(n)}
				if n >= 256+65536 {
					raw = []byte{0x8f, byte((n - 256 - 65536) >> 8), byte(n - 256 - 65536)}
				} else if n >= 256 {
					raw = []byte{byte((n - 256) >> 8), byte(n - 256)}
				}
				body := append([]byte(`<?xml version="1.0" encoding="`+codec.Name+`"?><dict><key>value</key><string><![CDATA[x`), raw...)
				body = append(body, []byte(`]]>y</string></dict>`)...)
				tail := append([]byte(`<?xml version="1.0" encoding="`+codec.Name+`"?><dict><key>value</key><string>second</string></dict>`), raw...)
				if want == nil {
					rawBody.WriteString("-\n")
				} else {
					rawBody.WriteString(hex.EncodeToString([]byte("x"+*want+"y")) + "\n")
				}
				if table.TailValid[n] {
					rawTail.WriteString("7365636f6e64\n")
				} else {
					rawTail.WriteString("-\n")
				}
				for pos, data := range [][]byte{body, tail} {
					before := bytes.Clone(data)
					got, e := plist.Decode(data)
					if !bytes.Equal(data, before) {
						t.Fatalf("mutated %x/%d", raw, pos)
					}
					valid := want != nil
					expected := ""
					if valid {
						expected = "x" + *want + "y"
					}
					if pos == 1 {
						valid = table.TailValid[n]
						expected = "second"
					}
					if !valid {
						var limit *plist.LimitError
						if !errors.Is(e, plist.ErrFormat) || errors.As(e, &limit) {
							t.Fatalf("native failure %x/%d: %#v %v", raw, pos, got, e)
						}
						continue
					}
					m, ok := got.(map[string]any)
					if e != nil || !ok || len(m) != 1 || m["value"] != expected {
						t.Fatalf("native value %x/%d: %#v, expected %q: %v", raw, pos, got, expected, e)
					}
				}
			}
			if hash([]byte(rawBody.String()+rawTail.String())) != codec.SHA256 {
				t.Fatal("native output hash mismatch")
			}
		})
	}
}

func TestEUCJPExpansionBudget(t *testing.T) {
	for _, name := range []string{"euc-jp", "windows-51932"} {
		t.Run(name, func(t *testing.T) {
			prefix := `<?xml encoding="` + name + `"?><string>`
			const suffix = `</string>`
			n := (plist.MaxSize - len(prefix) - len(suffix)) / 3
			padding := (plist.MaxSize - len(prefix) - len(suffix)) % 3
			data := append([]byte(prefix), bytes.Repeat([]byte{0xa4, 0xa2}, n)...)
			data = append(data, bytes.Repeat([]byte{'x'}, padding)...)
			data = append(data, suffix...)
			before := bytes.Clone(data)
			got, e := plist.Decode(data)
			if e != nil || len(got.(string)) != n*3+padding || !bytes.Equal(data, before) {
				t.Fatal("exact expansion limit", e)
			}
			data = append(data, 'x')
			before = bytes.Clone(data)
			_, e = plist.Decode(data)
			var limit *plist.LimitError
			if !errors.As(e, &limit) || !bytes.Equal(data, before) {
				t.Fatal("trailing expansion authorized interpretation", e)
			}
		})
	}
}

func TestEUCJPStreamBoundaries(t *testing.T) {
	for _, name := range []string{"euc-jp", "windows-51932"} {
		for _, n := range []int{1, 255, 256, 511, 512, 1007, 1008, 1023, 1024, 4095, 4096} {
			t.Run(fmt.Sprintf("%s/%d", name, n), func(t *testing.T) {
				prefix := `<?xml encoding="` + name + `"?><string>`
				data := append([]byte(prefix+strings.Repeat("a", n)), 0xa4, 0xa2)
				data = append(data, []byte(`</string>`)...)
				got, e := plist.Decode(data)
				if e != nil || got != strings.Repeat("a", n)+"あ" {
					t.Fatal(got, e)
				}
			})
		}
	}
}
