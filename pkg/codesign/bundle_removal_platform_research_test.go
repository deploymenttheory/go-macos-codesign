package codesign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// This checks retained research, not implementation parity. The loader's
// platform-plist selection additionally has a three-layout replay corpus.
func TestRemovalPlatformResearchProvenance(t *testing.T) {
	var corpus struct {
		Schema int
		MacOS  string
		Source string `json:"source_sha256"`
		Native string `json:"codesign_sha256"`
		Cases  []struct {
			Name, Selected, Output string
			Status                 int
			Envelope               bool              `json:"envelope_present"`
			Before                 map[string]string `json:"before_sha256"`
			After                  map[string]struct {
				Hash      string `json:"sha256"`
				Same      bool   `json:"same_identity"`
				Signature bool   `json:"signature_present"`
			}
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../testdata/bundle-removal/platform-info-research.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(readTestFile(t, "../../scripts/probe-removal-platform-info.go"))
	if corpus.Schema != 1 || corpus.MacOS == "" || len(corpus.Native) != 64 || corpus.Source != hex.EncodeToString(hash[:]) {
		t.Fatal("stale native research")
	}
	if _, err := hex.DecodeString(corpus.Native); err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"macos": "Contents/MacOS/platform", "macos-only": "Contents/MacOS/platform",
		"macosx": "Contents/MacOS/normal", "empty-macos": "Contents/Info-macos.plist",
		"missing-target": "Contents/Info-macos.plist", "key-macos": "Contents/MacOS/platform",
		"key-windows": "Contents/MacOS/normal", "directory": "Contents/MacOS/normal",
		"read": "Contents/MacOS/normal", "readattr": "", "readsecurity": "Contents/MacOS/platform",
		"readextattr": "Contents/MacOS/platform", "write": "Contents/MacOS/platform", "writeextattr": "Contents/MacOS/platform",
	}
	if len(corpus.Cases) != len(expected) {
		t.Fatal("incomplete native research")
	}
	for _, tc := range corpus.Cases {
		want, ok := expected[tc.Name]
		if !ok || tc.Selected != want {
			t.Fatal("unexpected or duplicate case", tc.Name)
		}
		delete(expected, tc.Name)
		status := 0
		if tc.Name == "readattr" {
			status = 1
			if !strings.Contains(tc.Output, "bundle format is ambiguous") {
				t.Fatal(tc.Output)
			}
		}
		if tc.Status != status || tc.Envelope != (status != 0) {
			t.Fatal("wrong native effects", tc.Name)
		}
		if len(tc.Before) < 3 || len(tc.Before) != len(tc.After) {
			t.Fatal("incomplete observations", tc.Name)
		}
		for name, before := range tc.Before {
			after, ok := tc.After[name]
			if !ok || len(before) != 64 || before != after.Hash || !after.Same || after.Signature != (name != tc.Selected) {
				t.Fatal("wrong object effects", tc.Name, name)
			}
		}
	}
}
