package codesign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestRemovalPlatformNativeReplay(t *testing.T) {
	wanted := map[string]bool{}
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, state := range []string{"both", "only", "empty", "empty-dictionary", "missing-target", "directory", "macosx", "key-macos", "key-windows", "empty-key", "number-key"} {
			wanted[shape+"/"+state] = true
		}
	}
	replayRemovalPlists(t, "platform-selection.json", "probe-removal-platform-selection.go", wanted)
}

func replayRemovalPlists(t *testing.T, corpusName, driverName string, wanted map[string]bool) {
	t.Helper()
	var corpus struct {
		Schema int
		MacOS  string
		Driver string `json:"source_sha256"`
		Native string `json:"codesign_sha256"`
		Cases  []struct {
			Shape, State, Base, Info, Platform, Selected, Output string
			Status                                               int
			Envelope                                             bool
			Files                                                map[string][]byte
			Directories                                          []string
			Links                                                map[string]string
			After                                                map[string]struct {
				SHA256    string
				SameInode bool `json:"same_inode"`
				Signature bool
			}
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../testdata/bundle-removal/"+corpusName), &corpus); err != nil {
		t.Fatal(err)
	}
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	if corpus.Schema != 1 || corpus.MacOS == "" || len(corpus.Native) != 64 || corpus.Driver != hash(readTestFile(t, "../../scripts/"+driverName)) {
		t.Fatal("stale or incomplete platform evidence")
	}
	if _, err := hex.DecodeString(corpus.Native); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != len(wanted) {
		t.Fatal("incomplete platform cases")
	}
	for _, tc := range corpus.Cases {
		name := tc.Shape + "/" + tc.State
		if !wanted[name] || tc.Status != 0 || tc.Output != "" || tc.Envelope || len(tc.Files) != len(tc.After) {
			t.Fatal("unexpected native observation", name)
		}
		delete(wanted, name)
		t.Run(name, func(t *testing.T) {
			operand := filepath.Join(t.TempDir(), "A.app")
			if tc.Shape != "app" {
				operand = filepath.Join(t.TempDir(), "A.framework")
			}
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
			carriers := map[string]*signingCarrier{}
			inputs := map[string]appledouble.Value{}
			before := map[string]os.FileInfo{}
			for name, data := range tc.Files {
				bundleFile(t, operand, name, data)
				info, err := os.Stat(filepath.Join(operand, name))
				if err != nil {
					t.Fatal(err)
				}
				before[name] = info
				metadata := appledouble.File{Attrs: []appledouble.Attr{{Name: "com.apple.cs.CodeDirectory", Value: []byte("attached signature")}, {Name: "user.codesign-control", Value: []byte("unchanged")}}}
				carrier := &signingCarrier{Reader: sidebandCarrier(t, metadata)}
				carriers[name], inputs[name] = carrier, carrier
			}
			bundleFile(t, operand, tc.Base+"_CodeSignature/CodeResources", []byte("envelope"))
			if err := Remove(context.Background(), operand, RemoveOptions{AppleDoubleFiles: inputs}); err != nil {
				t.Fatal(err)
			}
			for name, want := range tc.After {
				if want.SHA256 != hash(tc.Files[name]) || want.Signature != (name != tc.Selected) || !want.SameInode {
					t.Fatal("invalid retained file observation", name)
				}
				path := filepath.Join(operand, name)
				after, err := os.Stat(path)
				if err != nil || !os.SameFile(before[name], after) || hash(readTestFile(t, path)) != want.SHA256 {
					t.Fatal("data or identity changed", name, err)
				}
				metadata, err := appledouble.Decode(readCarrier(t, carriers[name]))
				if err != nil {
					t.Fatal(err)
				}
				signature, control := false, false
				for _, attr := range metadata.Attrs {
					if attr.Name == "com.apple.cs.CodeDirectory" {
						signature = true
					}
					if attr.Name == "user.codesign-control" && string(attr.Value) == "unchanged" {
						control = true
					}
				}
				if signature != want.Signature || !control {
					t.Fatal("wrong metadata mutation", name)
				}
			}
			if _, err := os.Stat(filepath.Join(operand, tc.Base+"_CodeSignature/CodeResources")); !os.IsNotExist(err) {
				t.Fatal("envelope retained", err)
			}
		})
	}
}

func TestRemovalPlatformBoundaries(t *testing.T) {
	for _, scenario := range []string{"symlink", "unsupported-encoding", "oversized", "escape"} {
		t.Run(scenario, func(t *testing.T) {
			app := testBundle(t)
			platform := filepath.Join(app, "Contents/Info-macos.plist")
			switch scenario {
			case "symlink":
				if err := os.Symlink("Info.plist", platform); err != nil {
					t.Fatal(err)
				}
			case "unsupported-encoding":
				bundleFile(t, app, "Contents/Info-macos.plist", []byte(`<?xml version="1.0" encoding="ISO-2022-JP"?><plist><dict/></plist>`))
			case "oversized":
				bundleFile(t, app, "Contents/Info-macos.plist", make([]byte, maxBundlePlist+1))
			case "escape":
				if err := os.RemoveAll(filepath.Join(app, "Contents")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(app, "Contents")); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(app)
			if err != nil {
				t.Fatal(err)
			}
			if bundle, err := loadRemovalBundle(root, app, ""); err == nil {
				bundle.close()
				t.Fatal("accepted unqualified or uncontained metadata")
			}
			if _, err := root.Stat("."); !errors.Is(err, os.ErrClosed) {
				t.Fatal("failed loader leaked root", err)
			}
		})
	}
}

func TestRemovalPlatformDiscoveryDenial(t *testing.T) {
	app := testBundle(t)
	const plist = "Contents/Info-macos.plist"
	bundleFile(t, app, plist, []byte("<plist><dict><key>CFBundleExecutable</key><string>platform</string></dict></plist>"))
	bundleFile(t, app, "Contents/MacOS/platform", []byte("platform"))
	path, parent := filepath.Join(app, plist), filepath.Join(app, "Contents")
	before := readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))
	command := func(name string, args ...string) {
		t.Helper()
		if b, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
	}
	var restore func()
	switch runtime.GOOS {
	case "darwin":
		command("/bin/chmod", "+a", "everyone deny readattr", path)
		restore = func() { command("/bin/chmod", "-N", path) }
	case "windows":
		restore = func() {
			command("icacls", parent, "/remove:d", "*S-1-1-0")
			command("icacls", path, "/remove:d", "*S-1-1-0")
		}
		t.Cleanup(restore)
		command("icacls", path, "/deny", "*S-1-1-0:(RA)")
		command("icacls", parent, "/deny", "*S-1-1-0:(RD)")
	case "linux":
		if err := os.Chmod(parent, 0000); err != nil {
			t.Fatal(err)
		}
		restore = func() {
			if err := os.Chmod(parent, 0755); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(restore)
	root, err := os.OpenRoot(app)
	if err != nil {
		t.Fatal(err)
	}
	_, queryErr := hostdata.ReadEntryType(root, plist)
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(queryErr, os.ErrPermission) {
		t.Fatal("discovery denial ineffective", queryErr)
	}
	err = RemoveSignature(context.Background(), app)
	var detail *VerificationError
	if !errors.Is(err, os.ErrPermission) || !errors.As(err, &detail) || detail.Diagnostic != "bundle format is ambiguous (could be app or framework)" {
		t.Fatal("discovery denial was treated as content fallback", err)
	}
	restore()
	if string(readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))) != string(before) || string(readTestFile(t, filepath.Join(app, "Contents/MacOS/platform"))) != "platform" {
		t.Fatal("discovery failure mutated executable")
	}
}
