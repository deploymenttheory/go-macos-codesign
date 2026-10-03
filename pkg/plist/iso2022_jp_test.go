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

// Each state/name has an independent native observation for every singleton,
// pair, ESC+two bytes and ESC+$+two bytes, in framed body and bare EOF contexts.
func TestISO2022JPNativeStreams(t *testing.T) {
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
			States []struct {
				Name    string
				Prefix  []byte
				Mapping int
			}
			Mappings []struct {
				Values    []*string
				TailValid []bool
			}
		}
	}
	if e := json.Unmarshal(read("../../testdata/bundle-removal/plist-iso2022-jp-values.json"), &c); e != nil {
		t.Fatal(e)
	}
	if c.Schema != 1 || c.Source != hash(read("../../scripts/probe-plist-iso2022-jp.go")) || len(c.Native) != 64 || len(c.Oracle) != 64 || c.MacOS == "" || c.SDK == "" || c.Clang == "" || len(c.Codecs) != 6 || len(c.Tables) != 1 {
		t.Fatal("invalid native provenance/inventory")
	}
	names := []string{"iso-2022-jp", "iso_2022_jp", "iso2022jp", "csiso2022jp", "cp50221", "windows-50221"}
	states := []string{"ascii", "roman", "kana", "jis0208", "jis0212", "ascii-b", "ascii-h", "kana-right", "jis1978", "jis-d"}
	prefixes := []string{"", "\x1b(J", "\x1b(I", "\x1b$B", "\x1b$(D", "\x1b(B", "\x1b(H", "\x1b)I", "\x1b$@", "\x1b$D"}
	for index, codec := range c.Codecs {
		if codec.Name != names[index] || codec.Table != 0 {
			t.Fatal("unexpected codec", codec)
		}
		t.Run(codec.Name, func(t *testing.T) {
			h := sha256.New()
			if len(c.Tables[codec.Table].States) != 10 || len(c.Tables[codec.Table].Mappings) != 5 {
				t.Fatal("incomplete state inventory")
			}
			for state, entry := range c.Tables[codec.Table].States {
				wanted := []int{0, 1, 2, 3, 4, 0, 0, 2, 3, 3}
				if entry.Mapping != wanted[state] {
					t.Fatal("unexpected state mapping")
				}
				table := c.Tables[codec.Table].Mappings[entry.Mapping]
				if entry.Name != states[state] || string(entry.Prefix) != prefixes[state] || len(table.Values) != 196864 || len(table.TailValid) != 196864 {
					t.Fatal("incomplete state", entry.Name)
				}
				t.Run(entry.Name, func(t *testing.T) {
					var rawBody, rawTail strings.Builder
					for n, want := range table.Values {
						v := n - 256
						var raw []byte
						switch {
						case n < 256:
							raw = []byte{byte(n)}
						case v < 65536:
							raw = []byte{byte(v >> 8), byte(v)}
						case v < 2*65536:
							raw = []byte{0x1b, byte(v >> 8), byte(v), 0x5c, 0x22}
						default:
							raw = []byte{0x1b, '$', byte(v >> 8), byte(v), 0x5c, 0x22}
						}
						body := append([]byte(`<?xml version="1.0" encoding="`+codec.Name+`"?><dict><key>value</key><string><![CDATA[x`), entry.Prefix...)
						body = append(body, raw...)
						body = append(body, []byte("\x1b(B]]>y</string></dict>")...)
						tail := append([]byte(`<?xml version="1.0" encoding="`+codec.Name+`"?><dict><key>value</key><string>second</string></dict>`), entry.Prefix...)
						tail = append(tail, raw...)
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
								t.Fatalf("native value %x/%d: %#v expected %q: %v", raw, pos, got, expected, e)
							}
						}
					}
					_, _ = h.Write([]byte(rawBody.String()))
					_, _ = h.Write([]byte(rawTail.String()))
				})
			}
			if hex.EncodeToString(h.Sum(nil)) != codec.SHA256 {
				t.Fatal("native output hash mismatch")
			}
		})
	}
}

func TestISO2022JPExpansionBudget(t *testing.T) {
	for _, name := range []string{"iso-2022-jp", "windows-50221"} {
		t.Run(name, func(t *testing.T) {
			prefix := `<?xml encoding="` + name + `"?><string>`
			const suffix = `</string>`
			n := (plist.MaxSize - len(prefix) - len(suffix)) / 2
			padding := (plist.MaxSize - len(prefix) - len(suffix)) % 2
			data := append([]byte(prefix), bytes.Repeat([]byte{0xff}, n)...)
			data = append(data, bytes.Repeat([]byte{'x'}, padding)...)
			data = append(data, suffix...)
			before := bytes.Clone(data)
			got, e := plist.Decode(data)
			if e != nil || len(got.(string)) != 2*n+padding || !bytes.Equal(data, before) {
				t.Fatal("exact expansion limit", e)
			}
			data = append(data, 'x')
			before = bytes.Clone(data)
			_, e = plist.Decode(data)
			var limit *plist.LimitError
			if !errors.As(e, &limit) || !bytes.Equal(data, before) {
				t.Fatal("tail bypassed expansion budget", e)
			}
		})
	}
}

func TestISO2022JPStreamBoundaries(t *testing.T) {
	for _, n := range []int{1, 255, 256, 511, 512, 998, 999, 1000, 1001, 1023, 1024, 4095, 4096} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			input := `<?xml encoding="iso-2022-jp"?><string>` + strings.Repeat("a", n) + "\x1b$B\x24\x22\x1b(J\\\x1b(I\x21\x1b$(D\xa2\xaf\x1b(B" + `</string>`
			got, e := plist.Decode([]byte(input))
			if e != nil || got != strings.Repeat("a", n)+"あ¥｡˘" {
				t.Fatal(got, e)
			}
		})
	}
}

func TestISO2022JPBufferNative(t *testing.T) {
	var c struct {
		Schema int
		Source string `json:"source_sha256"`
		Native string `json:"native_sha256"`
		MacOS  string
		Cases  []struct {
			Name   string
			Input  []byte
			Status int
			Value  json.RawMessage
		}
	}
	data, e := os.ReadFile("../../testdata/bundle-removal/plist-iso2022-jp-boundaries.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &c); e != nil {
		t.Fatal(e)
	}
	driver, e := os.ReadFile("../../scripts/probe-plist-iso2022-jp-boundaries.go")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(driver)
	if c.Schema != 1 || c.Source != hex.EncodeToString(h[:]) || len(c.Native) != 64 || c.MacOS == "" || len(c.Cases) != 3240 {
		t.Fatal("incomplete boundary provenance")
	}
	seen := map[string]bool{}
	for _, tc := range c.Cases {
		if seen[tc.Name] {
			t.Fatal("duplicate boundary", tc.Name)
		}
		seen[tc.Name] = true
		t.Run(tc.Name, func(t *testing.T) {
			before := bytes.Clone(tc.Input)
			got, e := plist.Decode(tc.Input)
			if !bytes.Equal(before, tc.Input) {
				t.Fatal("input changed")
			}
			if tc.Status == 1 {
				var limit *plist.LimitError
				if !errors.Is(e, plist.ErrFormat) || errors.As(e, &limit) {
					t.Fatal("native failure changed", got, e)
				}
				return
			}
			if tc.Status != 0 {
				t.Fatal("unexpected native status")
			}
			b, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var compact bytes.Buffer
			if err = json.Compact(&compact, tc.Value); err != nil {
				t.Fatal(err)
			}
			if e != nil || !bytes.Equal(b, compact.Bytes()) {
				t.Fatal("native value changed", got, e)
			}
		})
	}
}
