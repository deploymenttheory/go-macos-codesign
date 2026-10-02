package codesign

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestGenericRemovalAppleEvidence(t *testing.T) {
	root := filepath.Join("..", "..")
	checkHash := func(path, want string) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != want {
			t.Fatal("stale evidence", path)
		}
	}
	var ast struct {
		Schema  int
		Driver  string            `json:"driver_sha256"`
		Bodies  map[string]string `json:"body_sha256"`
		Targets map[string]map[string]struct {
			Kinds map[string]int `json:"ast_kinds"`
			Refs  map[string]int `json:"references"`
		}
	}
	if err := json.Unmarshal(readTestFile(t, filepath.Join(root, "spec/apple-generic-removal.json")), &ast); err != nil {
		t.Fatal(err)
	}
	checkHash("scripts/extract-generic-removal.go", ast.Driver)
	if ast.Schema != 1 || len(ast.Bodies) != 8 || len(ast.Targets) != 2 {
		t.Fatal("incomplete AST evidence")
	}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		methods := ast.Targets[target]
		if len(methods) != 8 {
			t.Fatal("missing target", target)
		}
		for name := range ast.Bodies {
			if methods[name].Kinds["CompoundStmt"] == 0 {
				t.Fatal("missing complete body", name)
			}
		}
		if methods["fd"].Refs["open"] == 0 || methods["remove"].Refs["removeAttr"] == 0 || methods["flush"].Refs["listAttr"] == 0 || methods["typeOf"].Refs["read"] == 0 {
			t.Fatal("missing operation references")
		}
	}
	var corpus struct {
		Schema  int
		Driver  string `json:"driver_sha256"`
		Fixture string `json:"fixture_sha256"`
		Native  string `json:"native_sha256"`
		Cases   []struct {
			Shape, Denial string
			Status        int
			Output        string
			Before        map[string]string `json:"before_attrs"`
			After         map[string]string `json:"after_attrs"`
			BeforeHash    string            `json:"before_sha256"`
			AfterHash     string            `json:"after_sha256"`
		}
	}
	if err := json.Unmarshal(readTestFile(t, filepath.Join(root, "testdata/generic-removal/native.json")), &corpus); err != nil {
		t.Fatal(err)
	}
	checkHash("scripts/probe-generic-removal.go", corpus.Driver)
	checkHash("testdata/macho/adhoc-arm64", corpus.Fixture)
	if corpus.Schema != 1 || len(corpus.Cases) != 40 || len(corpus.Native) != 64 {
		t.Fatal("incomplete native corpus")
	}
	seen := 0
	for _, tc := range corpus.Cases {
		if tc.Denial != "" {
			continue
		}
		seen++
		t.Run(tc.Shape, func(t *testing.T) {
			data := fixture(t, "adhoc-arm64")
			switch tc.Shape {
			case "empty":
				data = nil
			case "text":
				data = []byte("hello")
			case "script":
				data = []byte("#!/bin/sh\nexit 0\n")
			case "short-magic":
				data = data[:4]
			case "short-header":
				data = data[:27]
			case "truncated-macho":
				data = data[:32]
			case "object":
				binary.LittleEndian.PutUint32(data[12:], 1)
			}
			h := sha256.Sum256(data)
			if hex.EncodeToString(h[:]) != tc.BeforeHash {
				t.Fatal("input provenance mismatch")
			}
			metadata := appledouble.File{}
			for name, value := range tc.Before {
				b, err := hex.DecodeString(value)
				if err != nil {
					t.Fatal(err)
				}
				metadata.Attrs = append(metadata.Attrs, appledouble.Attr{Name: name, Value: b})
			}
			carrier := &signingCarrier{Reader: sidebandCarrier(t, metadata)}
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, data, 0755); err != nil {
				t.Fatal(err)
			}
			err := Remove(context.Background(), path, RemoveOptions{AppleDouble: carrier})
			if (err == nil) != (tc.Status == 0) {
				t.Fatal("native status", tc.Status, "Go", err)
			}
			after, err := appledouble.Decode(readCarrier(t, carrier))
			if err != nil {
				t.Fatal(err)
			}
			attrs := map[string]string{}
			for _, a := range after.Attrs {
				attrs[a.Name] = hex.EncodeToString(a.Value)
			}
			if !reflect.DeepEqual(attrs, tc.After) {
				t.Fatalf("attributes %#v; native %#v", attrs, tc.After)
			}
			h = sha256.Sum256(readTestFile(t, path))
			if hex.EncodeToString(h[:]) != tc.AfterHash {
				t.Fatal("data fork differs from native")
			}
		})
	}
	if seen != 8 {
		t.Fatal("missing dispatch controls")
	}
}

func readCarrier(t *testing.T, carrier *signingCarrier) []byte {
	t.Helper()
	b := make([]byte, carrier.Size())
	if _, err := carrier.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	return b
}
