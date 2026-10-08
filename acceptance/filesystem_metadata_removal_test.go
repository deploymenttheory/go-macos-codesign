package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var filesystemRemovalShapes = []string{"empty", "text", "script", "object", "short-header", "app", "flat-framework", "fallback-app", "fallback-flat-framework"}

// These layouts contain only objects FAT can represent. Symlink frameworks,
// aliases and access-control failures remain in the ordinary-filesystem suite.
func filesystemRemovalFixture(t *testing.T, dir, shape string) (string, string) {
	t.Helper()
	if !strings.Contains(shape, "app") && !strings.Contains(shape, "framework") {
		operand, target, _ := genericFixture(t, dir, shape)
		return operand, target
	}
	operand, base := filepath.Join(dir, "Fixture.app"), "Contents/"
	if strings.Contains(shape, "framework") {
		operand, base = filepath.Join(dir, "Fixture.framework"), ""
	}
	info := "<plist><dict><key>CFBundleExecutable</key><string>tool</string></dict></plist>"
	infoName, executable := base+"Info.plist", base+"MacOS/tool"
	if base == "" {
		infoName, executable = "Resources/Info.plist", "tool"
	}
	target := executable
	if strings.HasPrefix(shape, "fallback-") {
		info = "<plist><dict/></plist>"
		target = infoName
	}
	bundleWrite(t, operand, infoName, []byte(info))
	bundleWrite(t, operand, executable, []byte("generic executable\n"))
	bundleWrite(t, operand, base+"_CodeSignature/CodeResources", []byte("envelope"))
	return operand, filepath.Join(operand, target)
}

type filesystemRemovalResult struct {
	Schema                    int
	Filesystem, Shape, State  string
	Input, Before, After      []byte
	Carrier                   []byte
	Status                    int
	Stdout, Stderr            string
	SameFile, EnvelopeRemoved bool
	Attributes                map[string]string
}

type filesystemRemovalCorpus struct {
	Schema       int
	Host         string
	CodesignHash string
	Sources      map[string]string
	Cases        map[string]filesystemRemovalResult
}

var filesystemRemovalSources = []string{
	"acceptance/filesystem_metadata_removal_test.go", "acceptance/filesystem_metadata_test.go",
	"acceptance/filesystem_metadata_evidence_test.go", "acceptance/removal_generic_test.go",
	"acceptance/harness_test.go", "acceptance/bundle_test.go", "go.mod", "go.sum",
	"testdata/filesystem-metadata/native-seeds.json", "testdata/macho/adhoc-arm64",
}

func filesystemRemovalReference(t *testing.T) map[string]filesystemRemovalResult {
	t.Helper()
	var corpus filesystemRemovalCorpus
	if err := json.Unmarshal(nativeRead(t, filepath.Join(root, "testdata/filesystem-metadata/native-removal.json")), &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != 1 || !strings.Contains(corpus.Host, "ProductVersion:") || len(corpus.CodesignHash) != 64 || len(corpus.Cases) != 54 {
		t.Fatal("incomplete native filesystem removal corpus")
	}
	for _, name := range filesystemRemovalSources {
		if corpus.Sources[name] != hash(nativeRead(t, filepath.Join(root, name))) {
			t.Fatal("stale native filesystem removal source", name)
		}
	}
	seeds := filesystemSeedInputs(t)
	for _, filesystem := range []string{"fat32", "exfat"} {
		for _, shape := range filesystemRemovalShapes {
			for _, state := range []string{"clean", "populated", "empty"} {
				name := filesystemRemovalName(filesystem, shape, state)
				c, present := corpus.Cases[name]
				if !present || c.Schema != 1 || c.Filesystem != filesystem || c.Shape != shape || c.State != state || !bytes.Equal(c.Input, seeds["generic-"+state]) || !c.SameFile || !bytes.Equal(c.Before, c.After) {
					t.Fatal("incomplete or inconsistent native filesystem removal case", name)
				}
			}
		}
	}
	return corpus.Cases
}

func observeFilesystemRemoval(t *testing.T, executable, volume, filesystem, shape, state string) filesystemRemovalResult {
	t.Helper()
	dir := filesystemCaseDirectory(t, volume)
	operand, target := filesystemRemovalFixture(t, dir, shape)
	seed := filesystemSeedInputs(t)["generic-"+state]
	installFilesystemCarrier(t, target, seed)
	before := nativeRead(t, target)
	// FAT may change its synthesized file ID for an empty data fork while
	// updating associated storage. Compare the still-held object after mutation,
	// rather than treating a pre-operation numeric ID as a stable inode number.
	held, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	out, diagnostic, status := run(t, executable, "--remove-signature", operand)
	identity, err := held.Stat()
	if err != nil {
		t.Fatal(err)
	}
	carrier := filepath.Join(filepath.Dir(target), "._"+filepath.Base(target))
	result := filesystemRemovalResult{Schema: 1, Filesystem: filesystem, Shape: shape, State: state,
		Input: seed, Before: before, After: nativeRead(t, target), Carrier: nativeRead(t, carrier),
		Status: status, Stdout: out, Stderr: strings.ReplaceAll(diagnostic, operand, "$OPERAND"),
		SameFile: os.SameFile(identity, accessFileInfo(t, target)), Attributes: genericAttrs(t, target, genericMetadata(state), carrier)}
	if strings.Contains(shape, "app") || strings.Contains(shape, "framework") {
		base := "Contents/"
		if strings.Contains(shape, "framework") {
			base = ""
		}
		_, err := os.Stat(filepath.Join(operand, base+"_CodeSignature/CodeResources"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal("signature envelope lookup", err)
		}
		result.EnvelopeRemoved = os.IsNotExist(err)
	}
	return result
}

func filesystemRemovalName(filesystem, shape, state string) string {
	return fmt.Sprintf("filesystem-removal-%s-%s-%s.json", filesystem, shape, state)
}

func TestFilesystemMetadataRemoval(t *testing.T) {
	oracles := map[string]filesystemRemovalResult{}
	var reference map[string]filesystemRemovalResult
	if os.Getenv("MACOSCODESIGN_RECORD_FILESYSTEM_REMOVAL") == "" {
		reference = filesystemRemovalReference(t)
	}
	if output := os.Getenv("MACOSCODESIGN_RECORD_FILESYSTEM_REMOVAL"); output != "" {
		if !filepath.IsAbs(output) {
			output = filepath.Join(root, output)
		}
		if runtime.GOOS != "darwin" {
			t.Fatal("only native macOS may capture the oracle")
		}
		host, diagnostic, status := run(t, "sw_vers")
		if status != 0 {
			t.Fatal("native host identity", status, diagnostic)
		}
		corpus := filesystemRemovalCorpus{Schema: 1, Host: host, CodesignHash: hash(nativeRead(t, apple(t))), Sources: map[string]string{}, Cases: oracles}
		for _, name := range filesystemRemovalSources {
			corpus.Sources[name] = hash(nativeRead(t, filepath.Join(root, name)))
		}
		t.Cleanup(func() {
			if len(oracles) != 54 {
				t.Error("incomplete native filesystem removal corpus", len(oracles))
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
			for _, shape := range filesystemRemovalShapes {
				for _, state := range []string{"clean", "populated", "empty"} {
					t.Run(shape+"/"+state, func(t *testing.T) {
						want := reference[filesystemRemovalName(filesystem, shape, state)]
						if runtime.GOOS == "darwin" {
							want = observeFilesystemRemoval(t, apple(t), volume, filesystem, shape, state)
							oracles[filesystemRemovalName(filesystem, shape, state)] = want
						}
						got := observeFilesystemRemoval(t, binaryPath, volume, filesystem, shape, state)
						if !reflect.DeepEqual(got, want) {
							attest(t, map[string]any{"go": got, "native": want})
							t.Fatalf("native mismatch: Go status=%d stdout=%q stderr=%q same-file=%t envelope-removed=%t carrier=%s; native status=%d stdout=%q stderr=%q same-file=%t envelope-removed=%t carrier=%s", got.Status, got.Stdout, got.Stderr, got.SameFile, got.EnvelopeRemoved, hash(got.Carrier), want.Status, want.Stdout, want.Stderr, want.SameFile, want.EnvelopeRemoved, hash(want.Carrier))
						}
						attest(t, got)
						if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
							wire, err := json.Marshal(got)
							if err != nil {
								t.Fatal(err)
							}
							bundleWrite(t, export, filesystemRemovalName(filesystem, shape, state), wire)
						}
					})
				}
			}
		})
	}
}

func verifyImportedFilesystemRemoval(t *testing.T, directory, reference string) {
	t.Helper()
	expected := map[string]filesystemRemovalResult{}
	for _, filesystem := range []string{"fat32", "exfat"} {
		volume := metadataVolume(t, filesystem)
		for _, shape := range filesystemRemovalShapes {
			for _, state := range []string{"clean", "populated", "empty"} {
				expected[filesystemRemovalName(filesystem, shape, state)] = observeFilesystemRemoval(t, reference, volume, filesystem, shape, state)
			}
		}
	}
	seen := map[string]int{}
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "filesystem-removal-") {
			return nil
		}
		want, present := expected[entry.Name()]
		if !present {
			t.Fatal("unexpected filesystem removal artifact", path)
		}
		var got filesystemRemovalResult
		if err := json.Unmarshal(nativeRead(t, path), &got); err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("foreign filesystem removal differs from native operation: %s", path)
		}
		seen[entry.Name()]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range expected {
		if seen[name] != 2 {
			t.Fatal("expected both filesystem removal producers", name, seen[name])
		}
	}
	attest(t, map[string]any{"native_cases": len(expected), "per_case_producers": seen})
}
