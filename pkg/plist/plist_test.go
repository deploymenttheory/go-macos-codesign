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
	codec "howett.net/plist"
)

func TestDecodeRoots(t *testing.T) {
	for name, tc := range map[string]struct {
		input string
		value any
	}{
		"dictionary": {`<dict><key>x</key><string>y</string></dict>`, map[string]any{"x": "y"}},
		"array":      {`<array><true/><string>x</string></array>`, []any{true, "x"}},
		"string":     {`<string>x</string>`, "x"},
		"boolean":    {`<false/>`, false},
		"openstep":   {`{ x = y; }`, map[string]any{"x": "y"}},
	} {
		t.Run(name, func(t *testing.T) {
			data := []byte(tc.input)
			before := bytes.Clone(data)
			got, err := plist.Decode(data)
			if err != nil || !reflect.DeepEqual(got, tc.value) || !bytes.Equal(data, before) {
				t.Fatal(got, err)
			}
			// Independent binary serialization exercises the same public root contract.
			binary, err := codec.Marshal(tc.value, codec.BinaryFormat)
			if err != nil {
				t.Fatal(err)
			}
			got, err = plist.Decode(binary)
			if err != nil || !reflect.DeepEqual(got, tc.value) {
				t.Fatal(got, err)
			}
		})
	}
}

func TestDecodeErrorContract(t *testing.T) {
	for name, data := range map[string][]byte{"empty": nil, "no-root": []byte("\x01"), "xml": []byte("<dict>"), "openstep": []byte("{ x = ;"), "binary": []byte("bplist00")} {
		t.Run(name, func(t *testing.T) {
			_, err := plist.Decode(data)
			var diagnostic *plist.Error
			if !errors.Is(err, plist.ErrFormat) || !errors.As(err, &diagnostic) || diagnostic.Error() == "" {
				t.Fatal(err)
			}
			var limit *plist.LimitError
			if errors.As(err, &limit) {
				t.Fatal("syntax classified as limit", err)
			}
		})
	}
	_, err := plist.Decode([]byte(`<?xml version="1.0" encoding="EUC-JP"?><dict/>`))
	if !errors.Is(err, plist.ErrUnsupported) || errors.Is(err, plist.ErrFormat) {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"input":  bytes.Repeat([]byte(" "), plist.MaxSize+1),
		"depth":  []byte(strings.Repeat("<array>", plist.MaxDepth+1) + strings.Repeat("</array>", plist.MaxDepth+1)),
		"values": []byte("<array>" + strings.Repeat("<true/>", plist.MaxValues) + "</array>"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := plist.Decode(data)
			var limit *plist.LimitError
			if !errors.As(err, &limit) || !errors.Is(err, plist.ErrFormat) || limit.Error() == "" {
				t.Fatal(err)
			}
		})
	}
}

func TestDictionaryValidation(t *testing.T) {
	const duplicate = `<plist><dict><key>x</key><string>first</string><key>x</key><string>last</string></dict></plist>`
	got, err := plist.Decode([]byte(duplicate))
	if err != nil || got.(map[string]any)["x"] != "last" {
		t.Fatal(got, err)
	}
	for _, data := range []string{duplicate, `<dict/>`, `<plist><array/></plist>`} {
		if _, err := plist.DecodeDictionary([]byte(data)); !errors.Is(err, plist.ErrFormat) {
			t.Fatal(data, err)
		}
	}
	got, err = plist.DecodeDictionary([]byte(`<plist><dict><key>x</key><string>y</string></dict></plist>`))
	if err != nil || !reflect.DeepEqual(got, map[string]any{"x": "y"}) {
		t.Fatal(got, err)
	}
	// The compatibility entry point preserves the dependency's typed decode and
	// format result used by CMS and entitlement consumers.
	var value map[string]string
	format, err := plist.Unmarshal([]byte(`<plist><dict><key>x</key><string>y</string></dict></plist>`), &value)
	if err != nil || format != codec.XMLFormat || value["x"] != "y" {
		t.Fatal(format, value, err)
	}
}

// Compare the public package against retained complete native values, separately
// from codesign's operational fallback and mutation acceptance tests.
func TestDecodeNativeValues(t *testing.T) {
	read := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	var corpus struct {
		Schema  int
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
	if err := json.Unmarshal(read("../../testdata/bundle-removal/plist-xml-values.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != 1 || len(corpus.Cases) != 390 || len(corpus.Sources) != 5 || len(corpus.Native) != 64 || corpus.Driver != hash(read("../../scripts/probe-removal-xml-values.go")) {
		t.Fatal("incomplete native provenance")
	}
	for name, want := range corpus.Sources {
		if hash(read("../../testdata/bundle-removal/"+name)) != want {
			t.Fatal("stale corpus", name)
		}
	}
	names := map[string]bool{}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if names[tc.Name] {
				t.Fatal("duplicate case")
			}
			names[tc.Name] = true
			before := bytes.Clone(tc.Input)
			got, err := plist.Decode(tc.Input)
			if !bytes.Equal(before, tc.Input) {
				t.Fatal("changed input")
			}
			if tc.Status == 1 {
				var limit *plist.LimitError
				if !errors.Is(err, plist.ErrFormat) || errors.As(err, &limit) || string(tc.Value) != "null" {
					t.Fatal("native invalid input", got, err)
				}
				return
			}
			if tc.Status != 0 || err != nil {
				t.Fatal(tc.Status, err)
			}
			var want any
			if err := json.Unmarshal(tc.Value, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Go %#v; native %#v", got, want)
			}
		})
	}
}
