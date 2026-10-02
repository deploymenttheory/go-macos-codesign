package acceptance

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func platformInfoCases(t *testing.T) []emptyInfoCase {
	t.Helper()
	var corpus struct {
		Cases []struct {
			Shape, State, Info, Selected, Output string
			Status                               int
			Envelope                             bool
			Files                                map[string][]byte
			Directories                          []string
			Links                                map[string]string
			After                                map[string]emptyInfoFile
		}
	}
	if err := json.Unmarshal(nativeRead(t, filepath.Join(root, "testdata/bundle-removal/platform-selection.json")), &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 33 {
		t.Fatal("incomplete platform selection corpus")
	}
	var cases []emptyInfoCase
	for _, c := range corpus.Cases {
		cases = append(cases, emptyInfoCase{Shape: c.Shape, State: c.State, Info: c.Info, Main: c.Selected, Output: c.Output, Status: c.Status, Envelope: c.Envelope, Files: c.After, InputFiles: c.Files, Directories: c.Directories, Links: c.Links})
	}
	return cases
}

func platformInfoName(c emptyInfoCase) string {
	return "platform-info-" + c.Shape + "-" + c.State + ".json"
}

func TestRemovalPlatformInfo(t *testing.T) {
	for _, tc := range platformInfoCases(t) {
		t.Run(tc.Shape+"/"+tc.State, func(t *testing.T) {
			got := observeEmptyInfo(t, binaryPath, tc, true)
			if runtime.GOOS == "darwin" {
				native := observeEmptyInfo(t, apple(t), tc, false)
				local := observeEmptyInfo(t, binaryPath, tc, false)
				if !reflect.DeepEqual(got, native) || !reflect.DeepEqual(local, native) {
					t.Fatalf("native %#v; portable %#v; native metadata %#v", native, got, local)
				}
			}
			attest(t, got)
			if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
				b, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				bundleWrite(t, export, platformInfoName(tc), b)
			}
		})
	}
}

func verifyImportedPlatformInfo(t *testing.T, dir, reference string) {
	t.Helper()
	expected := map[string]emptyInfoResult{}
	for _, tc := range platformInfoCases(t) {
		expected[platformInfoName(tc)] = observeEmptyInfo(t, reference, tc, false)
	}
	seen := map[string]int{}
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "platform-info-") {
			return nil
		}
		want, ok := expected[d.Name()]
		if !ok {
			t.Fatal("unexpected platform selection artifact", path)
		}
		var got emptyInfoResult
		if err := json.Unmarshal(nativeRead(t, path), &got); err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: foreign %#v; native %#v", path, got, want)
		}
		seen[d.Name()]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name := range expected {
		if seen[name] != 2 {
			t.Fatal("expected both platform selection producers", name, seen[name])
		}
	}
	attest(t, map[string]any{"native_cases": len(expected), "per_case_producers": seen})
}
