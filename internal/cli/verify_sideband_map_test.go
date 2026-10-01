package cli

import (
	"context"
	"errors"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppleDoubleMapArguments(t *testing.T) {
	for _, args := range [][]string{{"--appledouble-map"}, {"--appledouble-map="}, {"--verify", "--appledouble-map", "map", "bundle"}, {"--verify", "--strict=sideband", "--appledouble-map", "map"}, {"--verify", "--strict=sideband", "--appledouble-map", "map", "a", "b"}, {"--verify", "--strict=sideband", "--no-strict", "--appledouble-map", "map", "a"}, {"--verify", "--strict=sideband", "--appledouble-map", "map", "--appledouble", "ad", "a"}} {
		if _, err := parse(args); err == nil {
			t.Fatal(args)
		}
	}
	if o, err := parse([]string{"--verify", "--strict=all", "--appledouble-map=map", "a"}); err != nil || o.appleDoubleMap != "map" {
		t.Fatal(o, err)
	}
}

func TestAppleDoubleManifest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "map.json")
	carrier := filepath.Join(dir, "metadata")
	if err := os.WriteFile(carrier, []byte("metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", `[]`, `null`, `{"":"metadata"}`, `{".":""}`, `{".":null}`, `{".":1}`, `{".":"absent"}`, `{".":"."}`, `{".":"metadata",".":"metadata"}`, `{".":"metadata"`, `{".":"metadata"} true`, `{".":"metadata", }`} {
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSidebandManifest(ctx, path); err == nil {
			t.Fatal("accepted manifest", input)
		}
	}
	if _, err := readSidebandManifest(ctx, dir); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := readSidebandManifest(ctx, path+"absent"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((8 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := readSidebandManifest(ctx, path); err == nil {
		t.Fatal("oversized map")
	}
	if err := os.WriteFile(path, []byte(`{".":"metadata"}`), 0600); err != nil {
		t.Fatal(err)
	}
	values, err := readSidebandManifest(ctx, path)
	if err != nil || values["."].Size() != 8 {
		t.Fatal(values, err)
	}
	b := make([]byte, 8)
	if n, err := values["."].ReadAt(b, 0); n != 8 || err != nil || string(b) != "metadata" {
		t.Fatal(n, b, err)
	}
	if _, err := values["."].ReadAt(b, 8); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := readSidebandManifest(canceled, path); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := os.WriteFile(carrier, []byte("changed data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := values["."].ReadAt(b, 0); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatal(err)
	}
	if err := os.Remove(carrier); err != nil {
		t.Fatal(err)
	}
	if _, err := values["."].ReadAt(b, 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := verifyWithMetadataMap(ctx, "absent", "", path, codesign.VerifyOptions{}); err == nil {
		t.Fatal("bad manifest ignored")
	}
}
