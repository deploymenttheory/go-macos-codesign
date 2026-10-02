package codesign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestRemovalEmptyInfoNativeReplay(t *testing.T) {
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	var corpus struct {
		Schema int
		Driver string `json:"driver_sha256"`
		Native string `json:"native_sha256"`
		Cases  []struct {
			Shape, State, Location, Info, Main, Output string
			Status                                     int
			Envelope                                   bool
			Files                                      map[string]struct {
				SHA256    string
				SameInode bool `json:"same_inode"`
				Signature bool
			}
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../testdata/bundle-removal/empty-info.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != 1 || len(corpus.Cases) != 27 || len(corpus.Native) != 64 || corpus.Driver != hash(readTestFile(t, "../../scripts/probe-removal-empty-info.go")) {
		t.Fatal("stale or incomplete native evidence")
	}
	seen := map[string]bool{}
	for _, tc := range corpus.Cases {
		name := tc.Shape + "/" + tc.State + "/" + tc.Location
		if seen[name] {
			t.Fatal("duplicate native case", name)
		}
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "A.app")
			base := "Contents/"
			if tc.Shape != "app" {
				app = filepath.Join(t.TempDir(), "A.framework")
				base = ""
			}
			if tc.Shape == "framework" {
				base = "Versions/A/"
			}
			for _, p := range []string{filepath.Dir(tc.Info), filepath.Dir(tc.Main), base + "_CodeSignature"} {
				if err := os.MkdirAll(filepath.Join(app, p), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.Shape == "framework" {
				for n, v := range map[string]string{"Versions/Current": "A", "A": "Versions/Current/A", "Resources": "Versions/Current/Resources"} {
					if err := os.Symlink(v, filepath.Join(app, n)); err != nil {
						t.Fatal(err)
					}
				}
			}
			bundleFile(t, app, base+"_CodeSignature/CodeResources", []byte("envelope"))
			if tc.State != "missing" {
				var b []byte
				if tc.State == "empty-dictionary" {
					b = []byte("<plist><dict/></plist>")
				}
				bundleFile(t, app, tc.Info, b)
			}
			if tc.Location != "absent" {
				bundleFile(t, app, tc.Main, []byte("generic executable\n"))
			}
			carriers := map[string]*signingCarrier{}
			inputs := map[string]appledouble.Value{}
			before := map[string]os.FileInfo{}
			for path, want := range tc.Files {
				if hash(readTestFile(t, filepath.Join(app, path))) != want.SHA256 {
					t.Fatal("fixture differs from native", path)
				}
				st, err := os.Stat(filepath.Join(app, path))
				if err != nil {
					t.Fatal(err)
				}
				before[path] = st
				c := &signingCarrier{Reader: sidebandCarrier(t, appledouble.File{Attrs: []appledouble.Attr{{Name: "com.apple.cs.CodeDirectory", Value: []byte("attached signature")}}})}
				carriers[path], inputs[path] = c, c
			}
			err := Remove(context.Background(), app, RemoveOptions{AppleDoubleFiles: inputs})
			if (err == nil) != (tc.Status == 0) {
				t.Fatal("native outcome differs", err, tc.Status)
			}
			if err != nil {
				var detail *VerificationError
				if !errors.Is(err, ErrFormat) || !errors.As(err, &detail) || "$BUNDLE: "+detail.Diagnostic+"\n" != tc.Output {
					t.Fatal("native failure context differs", err)
				}
			}
			for path, want := range tc.Files {
				after, err := os.Stat(filepath.Join(app, path))
				if err != nil {
					t.Fatal(err)
				}
				if os.SameFile(before[path], after) != want.SameInode || hash(readTestFile(t, filepath.Join(app, path))) != want.SHA256 {
					t.Fatal("data or identity differs", path)
				}
				metadata, err := appledouble.Decode(readCarrier(t, carriers[path]))
				if err != nil {
					t.Fatal(err)
				}
				if (len(metadata.Attrs) != 0) != want.Signature {
					t.Fatal("wrong file selected", path)
				}
			}
			_, err = os.Stat(filepath.Join(app, base+"_CodeSignature/CodeResources"))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if (err == nil) != tc.Envelope {
				t.Fatal("envelope differs", err)
			}
			if tc.State == "missing" {
				if _, err := os.Stat(filepath.Join(app, tc.Info)); !os.IsNotExist(err) {
					t.Fatal("missing plist created", err)
				}
			}
		})
	}
}

func TestRemovalMissingInfoMachO(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "A.app")
			original := fixture(t, "adhoc-"+arch)
			bundleFile(t, app, "Contents/MacOS/A", original)
			bundleFile(t, app, "Contents/_CodeSignature/CodeResources", []byte("envelope"))
			want, err := RemoveSignatureBytes(context.Background(), original)
			if err != nil {
				t.Fatal(err)
			}
			if err := RemoveSignature(context.Background(), app); err != nil {
				t.Fatal(err)
			}
			if string(readTestFile(t, filepath.Join(app, "Contents/MacOS/A"))) != string(want) {
				t.Fatal("wrong Mach-O removal")
			}
			if _, err := os.Stat(filepath.Join(app, "Contents/Info.plist")); !os.IsNotExist(err) {
				t.Fatal("missing plist created", err)
			}
		})
	}
}
