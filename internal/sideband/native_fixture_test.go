package sideband

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// All three CI hosts consume the same native observations. No native tool or
// metadata restoration is required to inspect the explicit carrier on Windows
// or Linux. A clean held file also exercises the host's real metadata API.
func TestNativeCapturedMetadata(t *testing.T) {
	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "testdata", "sideband", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Schema int
		Driver string            `json:"driver_sha256"`
		Input  map[string]string `json:"input_sha256"`
		Cases  []struct {
			Location string
			State    string            `json:"attribute_state"`
			Attrs    map[string]string `json:"attrs_hex"`
			Carrier  string            `json:"appledouble_hex"`
			Status   int               `json:"native_status"`
			Stdout   string            `json:"native_stdout"`
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.Schema != 1 || len(corpus.Cases) != 29 {
		t.Fatal("incomplete native corpus", len(corpus.Cases), err)
	}
	if len(corpus.Input) != 1 {
		t.Fatal("missing source provenance")
	}
	corpus.Input["scripts/probe-sideband.go"] = corpus.Driver
	for path, want := range corpus.Input {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != want {
			t.Fatalf("native evidence needs refreshing: %s", path)
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "clean-object-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before := snapshotAttributes(t, f)
	for _, tc := range corpus.Cases {
		t.Run(tc.Location+"/"+tc.State, func(t *testing.T) {
			encoded, err := hex.DecodeString(tc.Carrier)
			if err != nil {
				t.Fatal(err)
			}
			input := bytes.Clone(encoded)
			reader := bytes.NewReader(encoded)
			got, err := Inspect(context.Background(), f, reader)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, name := range []string{appledouble.ResourceForkName, appledouble.FinderInfoName} {
				if len(tc.Attrs[name]) > 0 {
					want = append(want, name)
				}
			}
			if !reflect.DeepEqual(got.Names(), want) {
				t.Fatal(got.Names(), want)
			}
			// The native policy excludes signature-directory attributes, and
			// reports only the first attribute on code/root objects. Inspection
			// exposes both; traversal and diagnostic selection are separate.
			details := want
			if tc.Location == "signature-directory" {
				details = nil
			} else if tc.Location != "resource" && len(details) > 1 {
				details = details[:1]
			}
			if tc.Status != boolInt(len(details) > 0) || strings.Count(tc.Stdout, "file with invalid attached data:") != len(details) {
				t.Fatal("native policy disagrees", tc.Status, tc.Stdout, details)
			}
			last := -1
			for _, name := range details {
				index := strings.Index(tc.Stdout, "Disallowed xattr "+name+" found on ")
				if index <= last {
					t.Fatal("native attribute diagnostic order", tc.Stdout)
				}
				last = index
			}
			if !bytes.Equal(input, encoded) || reader.Len() != len(input) {
				t.Fatal("carrier mutated or sequential offset moved")
			}
			// Inspection must not materialize the foreign metadata on any host.
			if after := snapshotAttributes(t, f); !reflect.DeepEqual(before, after) {
				t.Fatal("native metadata changed", before, after)
			}
		})
	}
}

func snapshotAttributes(t *testing.T, f *os.File) map[string]string {
	t.Helper()
	names, err := hostdata.ListXattrNames(f, hostdata.MaxXattrListSize)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string, len(names))
	for _, name := range names {
		data, present, err := hostdata.ReadXattr(f, name, 8<<20)
		if err != nil || !present {
			t.Fatal(name, present, err)
		}
		result[name] = hex.EncodeToString(data)
	}
	return result
}
