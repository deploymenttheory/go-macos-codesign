package acceptance

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"testing"
)

type resourceOrderEntry struct {
	Path          string `json:"path"`
	Info          int    `json:"info"`
	Error         int    `json:"errno"`
	FinderSize    int64  `json:"finder_size"`
	FinderError   int    `json:"finder_errno"`
	ResourceSize  int64  `json:"resource_size"`
	ResourceError int    `json:"resource_errno"`
}

func resourceOrderProbe(t *testing.T) string {
	t.Helper()
	apple(t)
	source := filepath.Join(root, "testdata/filesystem-metadata/resource-order.c")
	probe := filepath.Join(t.TempDir(), "resource-order")
	mustRun(t, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", probe)
	asts := map[string][]byte{}
	for _, arch := range []string{"arm64", "x86_64"} {
		out, stderr, status := run(t, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", arch+"-apple-macos15.0", "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if status != 0 || !json.Valid([]byte(out)) {
			t.Fatalf("resource order AST: %d %s", status, stderr)
		}
		for _, symbol := range []string{"fts_open", "fts_read", "getxattr"} {
			if !bytes.Contains([]byte(out), []byte(`"name": "`+symbol+`"`)) {
				t.Fatal("missing native declaration", symbol)
			}
		}
		var buffer bytes.Buffer
		compressor := gzip.NewWriter(&buffer)
		if _, err := compressor.Write([]byte(out)); err != nil {
			t.Fatal(err)
		}
		if err := compressor.Close(); err != nil {
			t.Fatal(err)
		}
		asts[arch] = buffer.Bytes()
	}
	host, stderr, status := run(t, "sw_vers")
	if status != 0 {
		t.Fatal(stderr)
	}
	compiler, stderr, status := run(t, "xcrun", "clang", "--version")
	if status != 0 {
		t.Fatal(stderr)
	}
	sources := map[string]string{}
	for _, name := range []string{"testdata/filesystem-metadata/resource-order.c", "testdata/filesystem-metadata/native-seeds.json", "acceptance/resource_order_probe_test.go", "acceptance/signing_profile_test.go", "acceptance/filesystem_metadata_bundle_test.go", "acceptance/filesystem_metadata_order_test.go", "acceptance/bundle_test.go", "go.mod", "go.sum"} {
		sources[name] = hash(nativeRead(t, filepath.Join(root, name)))
	}
	attest(t, map[string]any{"host": host, "compiler": compiler, "source_sha256": sources, "codesign_sha256": hash(nativeRead(t, apple(t))), "sdk_asts_gzip": asts, "scope": "SDK FTS traversal and attribute-size calls, not private Security implementation"})
	return probe
}

func observeResourceOrder(t *testing.T, probe, bundle string) ([]resourceOrderEntry, string) {
	t.Helper()
	out, stderr, status := run(t, probe, bundle)
	if status != 0 {
		t.Fatalf("native FTS probe: %d %s", status, stderr)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(out))
	var entries []resourceOrderEntry
	nested, resource := -1, -1
	for {
		var entry resourceOrderEntry
		err := decoder.Decode(&entry)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if entry.Error != 0 {
			t.Fatal("native traversal failed", entry)
		}
		switch entry.Path {
		case "Contents/._Info.plist":
			nested = len(entries)
		case "Contents/Resources/message.txt":
			resource = len(entries)
			if entry.ResourceSize <= 0 || entry.FinderSize <= 0 {
				t.Fatal("missing competing resource error", entry)
			}
		}
		entries = append(entries, entry)
	}
	if nested < 0 || resource < 0 {
		t.Fatal("missing competing traversal entries", entries)
	}
	diagnostic := "$BUNDLE: resource fork, Finder information, or similar detritus not allowed\n"
	if nested < resource {
		diagnostic = "$BUNDLE: code object is not signed at all\nIn subcomponent: $BUNDLE/Contents/._Info.plist\n"
	}
	return entries, diagnostic
}
