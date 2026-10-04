package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRemovalXMLCharactersNativeReplay(t *testing.T) {
	states := []string{"utf16-le", "utf16-be", "literal-controls", "literal-noncharacters", "literal-newlines", "cdata", "mixed", "named", "decimal", "hex", "supplementary", "empty-entity", "surrogate-high", "surrogate-low", "scalar-overflow", "integer-overflow", "unknown-entity", "uppercase-x", "bad-digit", "missing-semicolon", "cdata-unclosed", "string-comment", "string-pi", "string-child", "key-entity", "key-cdata", "key-controls", "duplicate-escaped-key", "nested-strings", "empty-strings", "mismatched-close", "container-text"}
	wanted := map[string]bool{}
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, location := range []string{"ordinary", "platform"} {
			for _, state := range states {
				wanted[shape+"/"+location+"-"+state] = true
			}
		}
	}
	replayRemovalPlists(t, "plist-xml-characters.json", "probe-removal-plist-interpretation.go", wanted)
}

func TestRemovalXMLNativeValues(t *testing.T) {
	var corpus struct {
		Schema  int
		MacOS   string
		Native  string            `json:"native_sha256"`
		Driver  string            `json:"source_sha256"`
		Sources map[string]string `json:"corpus_sha256"`
		Cases   []struct {
			Name   string
			Input  []byte
			Status int
			Value  json.RawMessage
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../testdata/bundle-removal/plist-xml-values.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	if corpus.Schema != 1 || corpus.MacOS == "" || len(corpus.Native) != 64 || len(corpus.Cases) != 1294 || len(corpus.Sources) != 8 || corpus.Driver != hash(readTestFile(t, "../../scripts/probe-removal-xml-values.go")) {
		t.Fatal("incomplete native value evidence")
	}
	if _, err := hex.DecodeString(corpus.Native); err != nil {
		t.Fatal(err)
	}
	wanted := map[string][]byte{}
	for file, h := range corpus.Sources {
		b := readTestFile(t, "../../testdata/bundle-removal/"+file)
		if hash(b) != h {
			t.Fatal("stale source corpus", file)
		}
		var source struct {
			Cases []struct {
				Shape, State, Info string
				Files              map[string][]byte
			}
		}
		if err := json.Unmarshal(b, &source); err != nil {
			t.Fatal(err)
		}
		for _, tc := range source.Cases {
			if tc.Shape == "app" && strings.HasPrefix(tc.State, "ordinary-") {
				wanted[file+"/"+tc.State] = tc.Files[tc.Info]
			}
		}
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if !bytes.Equal(wanted[tc.Name], tc.Input) || wanted[tc.Name] == nil {
				t.Fatal("unexpected native input")
			}
			delete(wanted, tc.Name)
			before := bytes.Clone(tc.Input)
			got, err := decodeRemovalPlist(tc.Input)
			if err != nil || !bytes.Equal(tc.Input, before) {
				t.Fatal("interpretation failed or changed source", err)
			}
			if tc.Status != 0 {
				if tc.Status != 1 || len(got) != 0 || string(tc.Value) != "null" {
					t.Fatal("native syntax failure mismatch", got)
				}
				return
			}
			var want map[string]any
			if err := json.Unmarshal(tc.Value, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Go %#v; native %#v", got, want)
			}
		})
	}
	if len(wanted) != 0 {
		t.Fatal("missing native values", wanted)
	}
}

func TestRemovalXMLBoundaries(t *testing.T) {
	for _, s := range []string{`<dict><key>x</key></dict>`, `<dict><key>x</key><key>y</key></dict>`, `<dict><string>x</string></dict>`, `<dict></array>`, `</dict>`, `<dict><key>x</key><string>unterminated`, `<dict><key>x</key><string>&`, `<dict><key>x</key><string>&bogus;</string></dict>`, `<dict><key>x</key><string>&#-1;</string></dict>`, `<dict><key>x</key><string>&#xG;</string></dict>`, `<dict><key>x</key><string>&#999999999999999999999;</string></dict>`, `<unknown/>`, `<dict><key>x</key><integer/>`} {
		if got, err := decodeRemovalPlist([]byte(s)); err != nil || len(got) != 0 {
			t.Fatal("malformed native dictionary", s, got, err)
		}
	}
	for _, s := range []string{`<array/>`, `<plist/>`, `<string/>`, `<string></string>`, `<true/>`, `<plist>  </plist>`} {
		if _, err := decodeRemovalPlist([]byte(s)); err != nil {
			t.Fatal(s, err)
		}
	}
	const text = `<?xml version="1.0" encoding="UTF-8"?><!--head--><!DOCTYPE plist><plist><dict><key>CFBundleExecutable</key><string>second</string><key>integer</key><integer>-1</integer><key>real</key><real>1.25</real><key>bool</key><false/><key>data</key><data>YQ==</data><key>date</key><date>2026-10-02T00:00:00Z</date><key>empty</key><dict/></dict>ignored`
	got, err := decodeRemovalPlist([]byte(text))
	if err != nil || got["CFBundleExecutable"] != "second" || got["integer"] != int64(-1) || got["real"] != 1.25 || got["bool"] != false || !bytes.Equal(got["data"].([]byte), []byte("a")) {
		t.Fatal(got, err)
	}
	// Literal controls must not be normalized, escaped twice or confused with
	// legitimate private-use characters. Conversion is shared by all marked codecs.
	const value = "\x00\x01\ufffe\uffff\ue000a\r\nb\rc"
	textValue := `<dict><key>` + value + `</key><string>` + value + `</string></dict>`
	for _, data := range [][]byte{[]byte(textValue), removalUTF16(textValue), removalUTF32(textValue)} {
		values, err := decodeRemovalPlist(data)
		if err != nil || values[value] != value {
			t.Fatal("character fidelity", values, err)
		}
		if _, err := decodeBundlePlist(data); err == nil {
			t.Fatal("strict parser weakened")
		}
	}
	// Remaining unsupported contexts and resource budgets still fail before any
	// mutation; they cannot silently select the raw Info.plist for removal.
	for name, data := range map[string][]byte{
		"outside-string":  []byte("<dict>\x01</dict>"),
		"legacy-encoding": []byte(`<?xml version="1.0" encoding="ISO-2022-KR"?><dict/>`),
		"depth":           []byte(strings.Repeat(`<array>`, 33) + strings.Repeat(`</array>`, 33)),
		"string-values":   []byte(`<array>` + strings.Repeat(`<string/>`, maxBundlePlistValues) + `</array>`),
	} {
		t.Run(name, func(t *testing.T) {
			app := testBundle(t)
			main := readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))
			bundleFile(t, app, "Contents/Info.plist", data)
			bundleFile(t, app, bundleResourcesPath, []byte("unchanged envelope"))
			err := RemoveSignature(context.Background(), app)
			if !errors.Is(err, ErrUnsupported) && !errors.Is(err, ErrFormat) {
				t.Fatal("restriction authorized mutation", err)
			}
			if !bytes.Equal(data, readTestFile(t, filepath.Join(app, "Contents/Info.plist"))) || !bytes.Equal(main, readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))) || string(readTestFile(t, filepath.Join(app, bundleResourcesPath))) != "unchanged envelope" {
				t.Fatal("restriction mutated bundle")
			}
		})
	}
}
