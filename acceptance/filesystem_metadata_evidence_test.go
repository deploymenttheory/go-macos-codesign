package acceptance

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type filesystemSeeds struct {
	Schema              int
	Complete            bool
	Host, Compiler, SDK string
	BinarySHA256        string            `json:"binary_sha256"`
	Sources             map[string]string `json:"source_sha256"`
	Seeds               map[string][]byte
}

func readFilesystemSeeds(read func(string) ([]byte, error)) (map[string][]byte, error) {
	const directory = "testdata/filesystem-metadata/"
	data, err := read(directory + "native-seeds.json")
	if err != nil {
		return nil, err
	}
	var report filesystemSeeds
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	binaryHash, err := hex.DecodeString(report.BinarySHA256)
	if err != nil || len(binaryHash) != 32 || report.Schema != 1 || !report.Complete || !strings.Contains(report.Host, "ProductVersion:") || !strings.Contains(report.Compiler, "clang") || report.SDK == "" {
		return nil, fmt.Errorf("incomplete native filesystem seed provenance")
	}
	for _, path := range []string{directory + "seed.c", "scripts/probe-filesystem-metadata-seeds.go", "go.mod", "go.sum", "seed-arm64.ast.json.gz", "seed-x86_64.ast.json.gz"} {
		actualPath := path
		if strings.HasSuffix(path, ".gz") {
			actualPath = directory + path
		}
		data, err := read(actualPath)
		if err != nil {
			return nil, err
		}
		if hash(data) != report.Sources[path] {
			return nil, fmt.Errorf("stale native filesystem seed source: %s", path)
		}
		if strings.HasSuffix(path, ".gz") {
			reader, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			ast, err := io.ReadAll(io.LimitReader(reader, 16<<20))
			closed := reader.Close()
			if err != nil || closed != nil || !json.Valid(ast) || !bytes.Contains(ast, []byte("copyfile")) || !bytes.Contains(ast, []byte("setxattr")) {
				return nil, fmt.Errorf("incomplete native filesystem seed AST: %s", path)
			}
		}
	}
	if len(report.Seeds) != 11 {
		return nil, fmt.Errorf("incomplete native filesystem seeds")
	}
	for _, kind := range []string{"strip", "remove", "clean", "fork", "finder", "both", "ordinary", "generic-clean", "generic-populated", "generic-empty", "discovery"} {
		metadata, err := appledouble.Decode(report.Seeds[kind])
		if err != nil {
			return nil, err
		}
		attrs := map[string]string{}
		for _, attr := range metadata.Attrs {
			attrs[attr.Name] = string(attr.Value)
		}
		if (kind == "strip" || kind == "remove") && attrs["com.example.retained"] != "retained" || kind == "strip" && (string(metadata.FinderInfo[:4]) != "TEST" || string(metadata.ResourceFork) != "fork") || kind == "remove" && attrs["com.apple.cs.CodeDirectory"] != "signature" {
			return nil, fmt.Errorf("native seed %s lacks required metadata", kind)
		}
		if kind == "fork" || kind == "both" {
			if string(metadata.ResourceFork) != "resource fork" {
				return nil, fmt.Errorf("native seed %s has wrong fork", kind)
			}
		}
		if kind == "finder" || kind == "both" {
			if string(metadata.FinderInfo[:8]) != "TEXTttxt" {
				return nil, fmt.Errorf("native seed %s has wrong FinderInfo", kind)
			}
		}
		if kind == "ordinary" && attrs["user.codesign-control"] != "keep" {
			return nil, fmt.Errorf("native seed lacks ordinary metadata")
		}
		if strings.HasPrefix(kind, "generic-") {
			for name, value := range genericValues(genericMetadata(strings.TrimPrefix(kind, "generic-"))) {
				if genericValues(*metadata)[name] != value {
					return nil, fmt.Errorf("native seed %s has wrong metadata: %s", kind, name)
				}
			}
			if kind == "generic-empty" || kind == "generic-populated" {
				for _, slot := range genericSlots {
					if _, present := attrs["com.apple.cs."+slot]; !present {
						return nil, fmt.Errorf("native seed %s lacks signature slot: %s", kind, slot)
					}
				}
			}
		}
		if kind == "discovery" && (attrs["com.apple.cs.CodeDirectory"] != "attached signature" || attrs["user.codesign-control"] != "unchanged") {
			return nil, fmt.Errorf("native discovery seed lacks required metadata")
		}
	}
	return report.Seeds, nil
}

func filesystemSeedInputs(t *testing.T) map[string][]byte {
	t.Helper()
	seeds, err := readFilesystemSeeds(func(path string) ([]byte, error) { return os.ReadFile(filepath.Join(root, path)) })
	if err != nil {
		t.Fatal(err)
	}
	return seeds
}

func TestFilesystemMetadataEvidence(t *testing.T) {
	_ = filesystemSeedInputs(t)
	for _, mutation := range []string{"incomplete", "version", "missing-seed", "empty-seed", "stale-module", "stale-ast", "missing-source"} {
		t.Run(mutation, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				if mutation == "missing-source" && path == "testdata/filesystem-metadata/seed.c" {
					return nil, os.ErrNotExist
				}
				data, err := os.ReadFile(filepath.Join(root, path))
				if err != nil || path != "testdata/filesystem-metadata/native-seeds.json" {
					return data, err
				}
				var report filesystemSeeds
				if err := json.Unmarshal(data, &report); err != nil {
					return nil, err
				}
				switch mutation {
				case "incomplete":
					report.Complete = false
				case "version":
					report.Schema++
				case "missing-seed":
					delete(report.Seeds, "strip")
				case "empty-seed":
					report.Seeds["strip"] = nil
				case "stale-module":
					report.Sources["go.mod"] = strings.Repeat("0", 64)
				case "stale-ast":
					report.Sources["seed-arm64.ast.json.gz"] = strings.Repeat("0", 64)
				}
				return json.Marshal(report)
			}
			if _, err := readFilesystemSeeds(read); err == nil {
				t.Fatal("accepted incomplete or stale native seed evidence")
			}
		})
	}
}

func TestNativeFilesystemIgnoresAdjacentAppleDouble(t *testing.T) {
	dir := extractionDirectory(t)
	t.Chdir(dir)
	copyFixture(t, "adhoc-arm64", "fixture")
	seed := filesystemSeedInputs(t)["strip"]
	if err := os.WriteFile("._fixture", seed, 0600); err != nil {
		t.Fatal(err)
	}
	before := layoutArchive(t, dir)
	mustRun(t, binaryPath, "--verify", "--strict=sideband", "fixture")
	nativeEqual(t, "ordinary dot-underscore file", layoutArchive(t, dir), before)
	attest(t, map[string]any{"adjacent_file_ignored": true, "input_preserved": true})
}
