package plist_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/plist"
)

// Each state/name has independent singleton and pair observations in body and
// EOF contexts. Initial ASCII also covers ESC+two and ESC+$+two byte vectors.
func TestISO2022ExtensionsNativeStreams(t *testing.T) {
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
	if e := json.Unmarshal(read("../../testdata/bundle-removal/plist-iso2022-extensions-values.json"), &c); e != nil {
		t.Fatal(e)
	}
	if c.Schema != 1 || c.Source != hash(read("../../scripts/probe-plist-iso2022-extensions.go")) || len(c.Native) != 64 || len(c.Oracle) != 64 || c.MacOS == "" || c.SDK == "" || c.Clang == "" || len(c.Codecs) != 7 || len(c.Tables) != 2 {
		t.Fatal("invalid native provenance/inventory")
	}
	names := []string{"iso-2022-jp-1", "iso_2022_jp_1", "iso2022jp1", "iso-2022-jp-2", "iso_2022_jp_2", "iso2022jp2", "csiso2022jp2"}
	states := []string{"ascii", "roman", "kana", "jis0208", "jis0212", "gb2312", "ksc5601", "latin", "greek", "roman-h", "jis1978", "jis1990", "ascii-b", "latin-designated", "greek-designated"}
	prefixes := []string{"", "\x1b(J", "\x1b(I", "\x1b$B", "\x1b$(D", "\x1b$A", "\x1b$(C", "\x1b.A\x1bN", "\x1b.F\x1bN", "\x1b(H", "\x1b$@", "\x1b&@", "\x1b(B", "\x1b.A", "\x1b.F"}
	for index, codec := range c.Codecs {
		family := 0
		if index >= 3 {
			family = 1
		}
		if codec.Name != names[index] || codec.Table != family {
			t.Fatal("unexpected codec", codec)
		}
		t.Run(codec.Name, func(t *testing.T) {
			h := sha256.New()
			if len(c.Tables[codec.Table].States) != 15 || len(c.Tables[codec.Table].Mappings) != []int{7, 11}[family] {
				t.Fatal("incomplete state inventory")
			}
			for state, entry := range c.Tables[codec.Table].States {
				wanted := [][]int{{0, 1, 2, 3, 4, 5, 5, 5, 5, 1, 3, 3, 6, 5, 5}, {0, 1, 2, 3, 4, 5, 6, 7, 8, 1, 3, 3, 9, 10, 10}}[family]
				if entry.Mapping != wanted[state] {
					t.Fatal("unexpected state mapping")
				}
				table := c.Tables[codec.Table].Mappings[entry.Mapping]
				count := 65792
				if state == 0 {
					count += 131072
				}
				if entry.Name != states[state] || string(entry.Prefix) != prefixes[state] || len(table.Values) != count || len(table.TailValid) != count {
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

func TestISO2022ExtensionsNativeContexts(t *testing.T) {
	var c struct {
		Schema int
		Source string `json:"source_sha256"`
		Native string `json:"native_sha256"`
		MacOS  string
		Cases  []struct {
			Name   string
			Input  []byte
			Status int
			Value  map[string]string
		}
	}
	data, e := os.ReadFile("../../testdata/bundle-removal/plist-iso2022-extension-streams.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &c); e != nil {
		t.Fatal(e)
	}
	driver, e := os.ReadFile("../../scripts/probe-plist-iso2022-extension-streams.go")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(driver)
	if c.Schema != 1 || c.Source != hex.EncodeToString(h[:]) || len(c.Native) != 64 || c.MacOS == "" || len(c.Cases) != 13650 {
		t.Fatal("incomplete native contexts")
	}
	seen := map[string]bool{}
	for _, tc := range c.Cases {
		if seen[tc.Name] {
			t.Fatal("duplicate native context")
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
				t.Fatal("invalid native exit status")
			}
			wanted := map[string]any{}
			for k, v := range tc.Value {
				wanted[k] = v
			}
			if e != nil || !reflect.DeepEqual(got, wanted) {
				t.Fatal("native full value changed", got, wanted, e)
			}
		})
	}
}

func TestISO2022ExtensionsExpansionBudget(t *testing.T) {
	for _, name := range []string{"iso-2022-jp-1", "iso-2022-jp-2"} {
		t.Run(name, func(t *testing.T) {
			prefix := []byte(`<?xml encoding="` + name + `"?><string>` + "\x1b$B")
			suffix := []byte("\x1b(B</string>")
			// Each two-byte JIS character expands to three UTF-8 bytes. The declaration
			// and syntax count too; state escapes contribute no decoded bytes.
			overhead := len(prefix) - 3 + len(suffix) - 3
			n := (plist.MaxSize - overhead) / 3
			input := append(bytes.Clone(prefix), bytes.Repeat([]byte{0x24, 0x22}, n)...)
			input = append(input, suffix...)
			padding := plist.MaxSize - (overhead + 3*n)
			input = append(input, bytes.Repeat([]byte{' '}, padding)...)
			before := bytes.Clone(input)
			if _, e := plist.Decode(input); e != nil {
				t.Fatal("exact converted limit", e)
			}
			if !bytes.Equal(input, before) {
				t.Fatal("input changed")
			}
			input = append(input, ' ')
			before = bytes.Clone(input)
			_, e := plist.Decode(input)
			var limit *plist.LimitError
			if !errors.As(e, &limit) {
				t.Fatal("overflow accepted", e)
			}
			if !bytes.Equal(input, before) {
				t.Fatal("overflow changed input")
			}
		})
	}
}
