package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type filesystemDiscoveryCase struct {
	Name string
	Case emptyInfoCase
}

// FAT has no symlinks. Keep versioned-framework cases in the native-filesystem
// suite and full library replay; exercise every captured flat layout here.
func filesystemDiscoveryCases(t *testing.T) []filesystemDiscoveryCase {
	t.Helper()
	var cases []filesystemDiscoveryCase
	for _, tc := range emptyInfoCases(t) {
		if tc.Shape != "framework" {
			cases = append(cases, filesystemDiscoveryCase{emptyInfoName(tc), tc})
		}
	}
	for _, tc := range platformInfoCases(t) {
		if tc.Shape != "framework" {
			cases = append(cases, filesystemDiscoveryCase{removalPlistName("platform-info-", tc), tc})
		}
	}
	if len(cases) != 40 {
		t.Fatal("incomplete native FAT discovery matrix", len(cases))
	}
	return cases
}

type filesystemDiscoveryCorpus struct {
	Schema       int
	Host         string
	CodesignHash string
	Sources      map[string]string
	Cases        map[string]emptyInfoResult
}

var filesystemDiscoverySources = []string{
	"acceptance/filesystem_metadata_discovery_test.go", "acceptance/removal_empty_info_test.go",
	"acceptance/removal_platform_info_test.go", "acceptance/removal_generic_test.go",
	"acceptance/filesystem_metadata_test.go", "acceptance/filesystem_metadata_evidence_test.go",
	"acceptance/harness_test.go", "acceptance/bundle_test.go", "go.mod", "go.sum",
	"testdata/filesystem-metadata/native-seeds.json", "testdata/bundle-removal/empty-info.json",
	"testdata/bundle-removal/platform-selection.json",
}

func filesystemDiscoveryReference(t *testing.T) map[string]emptyInfoResult {
	t.Helper()
	var corpus filesystemDiscoveryCorpus
	if err := json.Unmarshal(nativeRead(t, filepath.Join(root, "testdata/filesystem-metadata/native-discovery.json")), &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != 1 || !strings.Contains(corpus.Host, "ProductVersion:") || len(corpus.CodesignHash) != 64 || len(corpus.Cases) != 80 {
		t.Fatal("incomplete native filesystem discovery corpus")
	}
	for _, name := range filesystemDiscoverySources {
		if corpus.Sources[name] != hash(nativeRead(t, filepath.Join(root, name))) {
			t.Fatal("stale native filesystem discovery source", name)
		}
	}
	for _, filesystem := range []string{"fat32", "exfat"} {
		for _, tc := range filesystemDiscoveryCases(t) {
			got, present := corpus.Cases[filesystemDiscoveryName(filesystem, tc)]
			if !present || got.Platform != "appledouble" || len(got.Tree) != 64 || !reflect.DeepEqual(got.Files, tc.Case.Files) || got.Status != tc.Case.Status || got.Output != tc.Case.Output || got.Envelope != tc.Case.Envelope {
				t.Fatal("inconsistent native filesystem discovery case", filesystem, tc.Name)
			}
		}
	}
	return corpus.Cases
}

func filesystemDiscoveryName(filesystem string, tc filesystemDiscoveryCase) string {
	return "filesystem-discovery-" + filesystem + "-" + tc.Name
}

func observeFilesystemDiscovery(t *testing.T, exe, volume string, tc filesystemDiscoveryCase) emptyInfoResult {
	t.Helper()
	return observeEmptyInfoAt(t, exe, tc.Case, "appledouble", filesystemCaseDirectory(t, volume))
}

func TestFilesystemMetadataDiscovery(t *testing.T) {
	oracles := map[string]emptyInfoResult{}
	var reference map[string]emptyInfoResult
	output := os.Getenv("MACOSCODESIGN_RECORD_FILESYSTEM_DISCOVERY")
	if output == "" {
		reference = filesystemDiscoveryReference(t)
	} else {
		if runtime.GOOS != "darwin" {
			t.Fatal("only native macOS may capture the oracle")
		}
		if !filepath.IsAbs(output) {
			output = filepath.Join(root, output)
		}
		host, diagnostic, status := run(t, "sw_vers")
		if status != 0 {
			t.Fatal("native host identity", status, diagnostic)
		}
		corpus := filesystemDiscoveryCorpus{Schema: 1, Host: host, CodesignHash: hash(nativeRead(t, apple(t))), Sources: map[string]string{}, Cases: oracles}
		for _, name := range filesystemDiscoverySources {
			corpus.Sources[name] = hash(nativeRead(t, filepath.Join(root, name)))
		}
		t.Cleanup(func() {
			if len(oracles) != 80 {
				t.Error("incomplete native filesystem discovery corpus", len(oracles))
				return
			}
			wire, err := json.MarshalIndent(corpus, "", "  ")
			if err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(output, append(wire, '\n'), 0600); err != nil {
				t.Error(err)
			}
		})
	}
	for _, filesystem := range []string{"fat32", "exfat"} {
		t.Run(filesystem, func(t *testing.T) {
			volume := metadataVolume(t, filesystem)
			for _, tc := range filesystemDiscoveryCases(t) {
				t.Run(strings.TrimSuffix(tc.Name, ".json"), func(t *testing.T) {
					name := filesystemDiscoveryName(filesystem, tc)
					want := reference[name]
					if runtime.GOOS == "darwin" {
						want = observeFilesystemDiscovery(t, apple(t), volume, tc)
						oracles[name] = want
					}
					got := observeFilesystemDiscovery(t, binaryPath, volume, tc)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("native %#v; Go %#v", want, got)
					}
					attest(t, got)
					if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
						wire, err := json.Marshal(got)
						if err != nil {
							t.Fatal(err)
						}
						bundleWrite(t, export, name, wire)
					}
				})
			}
		})
	}
}

func verifyImportedFilesystemDiscovery(t *testing.T, directory, reference string) {
	t.Helper()
	expected := map[string]emptyInfoResult{}
	for _, filesystem := range []string{"fat32", "exfat"} {
		volume := metadataVolume(t, filesystem)
		for _, tc := range filesystemDiscoveryCases(t) {
			expected[filesystemDiscoveryName(filesystem, tc)] = observeFilesystemDiscovery(t, reference, volume, tc)
		}
	}
	seen := map[string]int{}
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "filesystem-discovery-") {
			return nil
		}
		want, present := expected[entry.Name()]
		if !present {
			t.Fatal("unexpected foreign filesystem discovery artifact", path)
		}
		var got emptyInfoResult
		if err := json.Unmarshal(nativeRead(t, path), &got); err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: foreign %#v; native %#v", path, got, want)
		}
		seen[entry.Name()]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name := range expected {
		if seen[name] != 2 {
			t.Fatal("expected both filesystem discovery producers", name, seen[name])
		}
	}
	attest(t, map[string]any{"native_cases": len(expected), "per_case_producers": seen})
}
