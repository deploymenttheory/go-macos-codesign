package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type emptyInfoFile struct {
	SHA256    string
	SameInode bool `json:"same_inode"`
	Signature bool
}

type emptyInfoCase struct {
	Shape, State, Location, Info, Main, Output string
	Status                                     int
	Envelope                                   bool
	Files                                      map[string]emptyInfoFile
	InputFiles                                 map[string][]byte
	Directories                                []string
	Links                                      map[string]string
	BeforeRun                                  func(*testing.T, string) func()
}

type emptyInfoResult struct {
	Status       int
	Output, Tree string
	Platform     string
	Envelope     bool
	Files        map[string]emptyInfoFile
}

func emptyInfoCases(t *testing.T) []emptyInfoCase {
	t.Helper()
	var corpus struct{ Cases []emptyInfoCase }
	if err := json.Unmarshal(nativeRead(t, filepath.Join(root, "testdata/bundle-removal/empty-info.json")), &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 27 {
		t.Fatal("incomplete metadata-discovery corpus")
	}
	return corpus.Cases
}

func emptyInfoFixture(t *testing.T, dir string, tc emptyInfoCase) (string, string) {
	t.Helper()
	operand, base := filepath.Join(dir, "A.app"), "Contents/"
	if tc.Shape != "app" {
		operand, base = filepath.Join(dir, "A.framework"), ""
	}
	if tc.Shape == "framework" {
		base = "Versions/A/"
	}
	if tc.InputFiles != nil {
		for _, name := range tc.Directories {
			if err := os.MkdirAll(filepath.Join(operand, name), 0755); err != nil {
				t.Fatal(err)
			}
		}
		for name, target := range tc.Links {
			if err := os.Symlink(target, filepath.Join(operand, name)); err != nil {
				t.Fatal(err)
			}
		}
		for name, data := range tc.InputFiles {
			bundleWrite(t, operand, name, data)
		}
		bundleWrite(t, operand, base+"_CodeSignature/CodeResources", []byte("envelope"))
		return operand, base
	}
	for _, name := range []string{filepath.Dir(tc.Info), filepath.Dir(tc.Main), base + "_CodeSignature"} {
		if err := os.MkdirAll(filepath.Join(operand, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if tc.Shape == "framework" {
		for name, target := range map[string]string{"Versions/Current": "A", "A": "Versions/Current/A", "Resources": "Versions/Current/Resources"} {
			if err := os.Symlink(target, filepath.Join(operand, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(operand, name), b, 0755); err != nil {
			t.Fatal(err)
		}
	}
	write(base+"_CodeSignature/CodeResources", []byte("envelope"))
	if tc.State != "missing" {
		var b []byte
		if tc.State == "empty-dictionary" {
			b = []byte("<plist><dict/></plist>")
		}
		write(tc.Info, b)
	}
	if tc.Location != "absent" {
		write(tc.Main, []byte("generic executable\n"))
	}
	return operand, base
}

func observeEmptyInfo(t *testing.T, exe string, tc emptyInfoCase, platform string) emptyInfoResult {
	t.Helper()
	return observeEmptyInfoAt(t, exe, tc, platform, extractionDirectory(t))
}

// The platform identifies the fixture's actual attribute namespace. "appledouble"
// requires a directory on a mounted FAT volume and a genuine COPYFILE_PACK seed;
// it is never passed to the CLI or used to change its storage selection.
func observeEmptyInfoAt(t *testing.T, exe string, tc emptyInfoCase, platform, dir string) emptyInfoResult {
	t.Helper()
	operand, base := emptyInfoFixture(t, dir, tc)
	if platform == "appledouble" {
		// Match the captured input metadata on every host. Remove only fixture-
		// creation bookkeeping, before installing native seeds or running codesign.
		if err := filepath.WalkDir(operand, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), "._") {
				return os.Remove(path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	metadata := appledouble.File{Attrs: []appledouble.Attr{{Name: "com.apple.cs.CodeDirectory", Value: []byte("attached signature")}, {Name: "user.codesign-control", Value: []byte("unchanged")}}}
	carriers := map[string]string{}
	before := map[string]*os.File{}
	for name, want := range tc.Files {
		path := filepath.Join(operand, name)
		if hash(nativeRead(t, path)) != want.SHA256 {
			t.Fatal("input differs from captured native case", name)
		}
		if platform == "appledouble" {
			installFilesystemCarrier(t, path, filesystemSeedInputs(t)["discovery"])
			carriers[name] = filepath.Join(filepath.Dir(path), "._"+filepath.Base(path))
		} else {
			setSidebandObjectForPlatform(t, path, metadata, platform)
		}
		held, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		before[name] = held
	}
	var afterRun func()
	if tc.BeforeRun != nil {
		afterRun = tc.BeforeRun(t, operand)
	}
	out, stderr, status := run(t, exe, "--remove-signature", operand)
	if afterRun != nil {
		afterRun()
	}
	got := emptyInfoResult{Status: status, Output: strings.ReplaceAll(stderr, operand, "$BUNDLE"), Tree: hash(layoutArchive(t, operand)), Platform: platform, Files: map[string]emptyInfoFile{}}
	if out != "" || got.Status != tc.Status || got.Output != tc.Output {
		t.Fatalf("native discovery outcome differs: %d %q %q; want %d %q", status, out, stderr, tc.Status, tc.Output)
	}
	for name, want := range tc.Files {
		path := filepath.Join(operand, name)
		attrs := genericAttrsForPlatform(t, path, metadata, carriers[name], platform)
		_, signature := attrs["com.apple.cs.CodeDirectory"]
		if attrs["user.codesign-control"] != "756e6368616e676564" {
			t.Fatal("unrelated metadata changed", name, attrs)
		}
		identity, err := before[name].Stat()
		if err != nil {
			t.Fatal(err)
		}
		got.Files[name] = emptyInfoFile{hash(nativeRead(t, path)), os.SameFile(identity, accessFileInfo(t, path)), signature}
		if platform == "linux" {
			// user.com.apple.cs.* is unrelated metadata. Canonical signature
			// selection is exercised on FAT and by the full library corpus replay.
			want.Signature = true
		}
		if got.Files[name] != want {
			t.Fatal("native file outcome differs", name, got.Files[name], want)
		}
	}
	_, err := os.Stat(filepath.Join(operand, base+"_CodeSignature/CodeResources"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	got.Envelope = err == nil
	if got.Envelope != tc.Envelope {
		t.Fatal("wrong signature envelope state")
	}
	if tc.State == "missing" {
		if _, err := os.Stat(filepath.Join(operand, tc.Info)); !os.IsNotExist(err) {
			t.Fatal("missing plist created", err)
		}
	}
	return got
}

func emptyInfoName(tc emptyInfoCase) string {
	return "empty-info-" + tc.Shape + "-" + tc.State + "-" + tc.Location + ".json"
}

func TestRemovalEmptyInfo(t *testing.T) {
	for _, tc := range emptyInfoCases(t) {
		t.Run(tc.Shape+"/"+tc.State+"/"+tc.Location, func(t *testing.T) {
			got := observeEmptyInfo(t, binaryPath, tc, runtime.GOOS)
			if runtime.GOOS == "darwin" {
				native := observeEmptyInfo(t, apple(t), tc, runtime.GOOS)
				if !reflect.DeepEqual(got, native) {
					t.Fatalf("native %#v; Go %#v", native, got)
				}
			}
			attest(t, got)
			if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
				b, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				bundleWrite(t, export, emptyInfoName(tc), b)
			}
		})
	}
}

func verifyImportedEmptyInfo(t *testing.T, dir, reference string) {
	t.Helper()
	verifyImportedDiscoveryCases(t, dir, reference, emptyInfoCases(t), "empty-info-", emptyInfoName)
}
