package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type filesystemCLIResult struct {
	Filesystem, Operation string
	Status                int
	Stdout, Stderr        string
	Data, Carrier         []byte
}

func filesystemCLIOutcome(t *testing.T, filesystem, operation, target, stdout, stderr string, status int) filesystemCLIResult {
	t.Helper()
	carrier := filepath.Join(filepath.Dir(target), "._"+filepath.Base(target))
	return filesystemCLIResult{filesystem, operation, status,
		strings.ReplaceAll(stdout, target, "$OPERAND"), strings.ReplaceAll(stderr, target, "$OPERAND"),
		nativeRead(t, target), nativeRead(t, carrier)}
}

func verifyImportedFilesystemCLI(t *testing.T, directory, reference string) {
	t.Helper()
	expected := map[string]filesystemCLIResult{}
	for _, filesystem := range []string{"fat32", "exfat"} {
		volume := metadataVolume(t, filesystem)
		for _, operation := range []string{"verify", "strip", "remove"} {
			dir := filesystemCaseDirectory(t, volume)
			target := filepath.Join(dir, "fixture")
			data := nativeRead(t, filepath.Join(root, "testdata/macho/adhoc-arm64"))
			seed := "strip"
			args := []string{"--verify", "--strict=sideband", "--verbose=1"}
			want := 1
			switch operation {
			case "strip":
				args, want = []string{"-f", "-s", "-", "--strip-disallowed-xattrs"}, 0
			case "remove":
				data, seed = []byte("#!/bin/sh\nexit 0\n"), "remove"
				args, want = []string{"--remove-signature"}, 0
			}
			if err := os.WriteFile(target, data, 0700); err != nil {
				t.Fatal(err)
			}
			installFilesystemCarrier(t, target, filesystemSeedInputs(t)[seed])
			stdout, stderr, status := run(t, reference, append(args, target)...)
			if status != want {
				t.Fatal("native filesystem outcome changed", operation, status, stdout, stderr)
			}
			result := filesystemCLIOutcome(t, filesystem, operation, target, stdout, stderr, status)
			if operation == "strip" {
				mustRun(t, reference, "--verify", "--strict=sideband", target)
			}
			expected["filesystem-cli-"+filesystem+"-"+operation+".json"] = result
		}
	}
	seen := map[string]int{}
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "filesystem-cli-") {
			return nil
		}
		want, present := expected[entry.Name()]
		if !present {
			t.Fatal("unexpected foreign filesystem CLI artifact", path)
		}
		var got filesystemCLIResult
		if err := json.Unmarshal(nativeRead(t, path), &got); err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: foreign filesystem outcome differs: data %s/%s carrier %s/%s diagnostics %q/%q", path, hash(got.Data), hash(want.Data), hash(got.Carrier), hash(want.Carrier), got.Stderr, want.Stderr)
		}
		seen[entry.Name()]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name := range expected {
		if seen[name] != 2 {
			t.Fatal("expected both filesystem CLI producers", name, seen[name])
		}
	}
	attest(t, map[string]any{"native_cases": len(expected), "per_case_producers": seen})
}
