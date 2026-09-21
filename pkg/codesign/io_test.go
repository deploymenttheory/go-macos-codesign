package codesign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type cancelBeforeRename struct {
	context.Context
	checks int
}

func (c *cancelBeforeRename) Err() error {
	c.checks++
	if c.checks >= 2 {
		return context.Canceled
	}
	return nil
}

func TestReplacementCancellationPreservesHardlinks(t *testing.T) {
	dir := t.TempDir()
	path, other := filepath.Join(dir, "target"), filepath.Join(dir, "other")
	data := fixture(t, "unsigned-arm64")
	if err := os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, other); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelBeforeRename{Context: context.Background()}
	if err := replaceFile(ctx, path, []byte("staged, never committed")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, name := range []string{path, other} {
		st, err := os.Stat(name)
		if err != nil || !os.SameFile(before, st) {
			t.Fatalf("inode changed: %s %v", name, err)
		}
		got, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("bytes changed: %s %v", name, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("staging leaked: %v %v", entries, err)
	}
}

func TestWriterAST(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-writer.json")
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Targets map[string]struct {
			Methods   map[string]struct{ References map[string]int }
			Constants map[string]string `json:"metadata_constants"`
		}
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Targets) != 2 {
		t.Fatal("both writer AST targets required")
	}
	for target, facts := range record.Targets {
		if len(facts.Methods) != 12 {
			t.Fatalf("missing complete writer methods for %s", target)
		}
		if facts.Methods["commit"].References["rename"] != 1 || facts.Methods["commit"].References["copy"] != 2 || facts.Methods["~MachOEditor"].References["remove"] != 1 {
			t.Fatalf("missing writer control flow for %s", target)
		}
		for _, call := range []string{"mainExecutableImage", "allocate", "commit", "remove", "flush"} {
			if facts.Methods["signer_remove"].References[call] != 1 {
				t.Fatalf("missing signer removal control flow %s for %s", call, target)
			}
		}
		for method, call := range map[string]string{
			"bundle_component_2":          "writeAll",
			"bundle_createMeta_0":         "copyfile",
			"bundle_metaPath_1":           "CFBundleCopySupportFilesDirectoryURL",
			"bundle_remove_0":             "execWriter",
			"bundle_remove_1":             "unlink",
			"bundle_flush_0":              "purgeMetaDirectory",
			"bundle_purgeMetaDirectory_0": "unlink",
		} {
			if facts.Methods[method].References[call] != 1 {
				t.Fatalf("missing %s/%s for %s", method, call, target)
			}
		}
		for call, count := range map[string]int{
			"fchown": 1, "fchmod": 1, "fsetattrlist": 2,
			"fd_volume_has_feature": 2, "copyfile_set_bsdflags": 1,
		} {
			if facts.Methods["copyfile_stat"].References[call] != count {
				t.Fatalf("missing directory stat control flow %s for %s", call, target)
			}
		}
		for _, call := range []string{"open", "fstat", "mmap", "close"} {
			if facts.Methods["mapFile"].References[call] != 1 {
				t.Fatalf("missing allocation mapping control flow %s for %s", call, target)
			}
		}
		for name, value := range map[string]string{
			"DirectoryCopyStat": "2", "DirectoryCopySecurity": "3",
			"DirectorySupportedFlags": "32777", "DirectoryOmitFlags": "1573056",
			"DirectoryPreserveFlags": "1572992",
			"MappingRead":            "1", "MappingPrivate": "2", "MappingResilientCodesign": "8192",
		} {
			if facts.Constants[name] != value {
				t.Fatalf("directory SDK constant %s = %q for %s; want %s", name, facts.Constants[name], target, value)
			}
		}
	}
}
