package codesign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func bundleLink(t *testing.T, b, name, target string) {
	t.Helper()
	p := filepath.Join(b, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

func testFramework(t *testing.T, versioned bool) string {
	t.Helper()
	b := filepath.Join(t.TempDir(), "F.framework")
	base := ""
	if versioned {
		base = "Versions/A/"
	}
	info := strings.ReplaceAll(strings.ReplaceAll(testBundleInfo, "hello", "F"), "APPL", "FMWK")
	bundleFile(t, b, base+"Resources/Info.plist", []byte(info))
	bundleFile(t, b, base+"F", fixture(t, "unsigned-arm64"))
	bundleFile(t, b, base+"Resources/data", []byte("data"))
	if versioned {
		bundleLink(t, b, "Versions/Current", "A")
		bundleLink(t, b, "F", "Versions/Current/F")
		bundleLink(t, b, "Resources", "Versions/Current/Resources")
	}
	return b
}

func TestFrameworkLayoutsAndLinks(t *testing.T) {
	ctx := context.Background()
	for _, versioned := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "versioned"}[versioned], func(t *testing.T) {
			b := testFramework(t, versioned)
			base := ""
			if versioned {
				base = "Versions/A/"
			}
			bundleFile(t, b, base+"Headers/F.h", []byte("header"))
			bundleFile(t, b, base+"PrivateHeaders/F.h", []byte("private"))
			bundleFile(t, b, base+"Modules/module.modulemap", []byte("module"))
			bundleFile(t, b, base+"helper", fixture(t, "unsigned-arm64"))
			bundleLink(t, b, base+"Resources/link", "./data")
			bundleLink(t, b, base+"Headers/alias", "F.h")
			bundleLink(t, b, base+"helper-alias", "helper")
			if err := Sign(ctx, b, SignOptions{Deep: true}); err != nil {
				t.Fatal(err)
			}
			r, err := Verify(ctx, b, VerifyOptions{Deep: true})
			if err != nil || r.Format != "bundle with Mach-O thin" {
				t.Fatal(r, err)
			}
			if _, err := Inspect(ctx, b); err != nil {
				t.Fatal(err)
			}
			if err := RemoveSignature(ctx, b); err != nil {
				t.Fatal(err)
			}
			if err := RemoveSignature(ctx, b); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, b, VerifyOptions{}); !errors.Is(err, ErrUnsigned) {
				t.Fatal(err)
			}
		})
	}
}

func TestFrameworkInvalidRoots(t *testing.T) {
	for _, change := range []string{"current-file", "current-missing", "current-absolute", "current-parent", "current-self", "current-dot", "current-bad", "version-file", "selected-link", "root-file", "root-alias", "missing-main-alias", "missing-resources-alias", "ambiguous", "wrong-type", "wrong-executable", "versions-file"} {
		t.Run(change, func(t *testing.T) {
			b := testFramework(t, true)
			remove := func(name string) {
				t.Helper()
				if err := os.Remove(filepath.Join(b, filepath.FromSlash(name))); err != nil {
					t.Fatal(err)
				}
			}
			switch change {
			case "current-file":
				remove("Versions/Current")
				bundleFile(t, b, "Versions/Current", []byte("A"))
			case "current-missing":
				remove("Versions/Current")
			case "current-absolute", "current-parent", "current-self", "current-dot", "current-bad":
				remove("Versions/Current")
				target := map[string]string{"current-absolute": "/A", "current-parent": "../A", "current-self": "Current", "current-dot": ".", "current-bad": "CON"}[change]
				bundleLink(t, b, "Versions/Current", target)
			case "version-file":
				bundleFile(t, b, "Versions/B", []byte("unsigned"))
			case "selected-link":
				if err := os.Rename(filepath.Join(b, "Versions/A"), filepath.Join(b, "Versions/B")); err != nil {
					t.Fatal(err)
				}
				bundleLink(t, b, "Versions/A", "B")
			case "root-file":
				bundleFile(t, b, "unsealed", []byte("unsealed"))
			case "root-alias":
				remove("F")
				bundleLink(t, b, "F", "Versions/Current/Resources/data")
			case "missing-main-alias":
				remove("F")
			case "missing-resources-alias":
				remove("Resources")
			case "ambiguous":
				bundleLink(t, b, "Contents", "Versions/Current/Contents")
			case "wrong-type":
				bundleFile(t, b, "Versions/A/Resources/Info.plist", []byte(testBundleInfo))
			case "wrong-executable":
				bundleFile(t, b, "Versions/A/Resources/Info.plist", []byte(strings.ReplaceAll(testBundleInfo, "APPL", "FMWK")))
			case "versions-file":
				if err := os.RemoveAll(filepath.Join(b, "Versions")); err != nil {
					t.Fatal(err)
				}
				bundleFile(t, b, "Versions", []byte("bad"))
			}
			if err := Sign(context.Background(), b, SignOptions{Deep: true}); err == nil {
				t.Fatal("unsafe root signed")
			}
		})
	}
}

func TestFrameworkRootVariantsAndBudgets(t *testing.T) {
	b := testFramework(t, true)
	for name, target := range map[string]string{"Versions/Current": "./A", "F": "./Versions/A/F", "Resources": "Versions/A/Resources"} {
		if err := os.Remove(filepath.Join(b, name)); err != nil {
			t.Fatal(err)
		}
		bundleLink(t, b, name, target)
	}
	for _, name := range []string{".DS_Store", "Versions/.DS_Store", "module.map"} {
		bundleFile(t, b, name, []byte("allowed unsealed metadata"))
		if err := os.Chmod(filepath.Join(b, name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := Sign(context.Background(), b, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	opened, err := openAppBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.close()
	scope := newBundleScan()
	scope.entries = maxBundleEntries
	if _, _, err := opened.scanTree(context.Background(), scope, 0, ""); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(b, "module.map"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := opened.validateFrameworkRoot(); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(b, "module.map"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(b, "Versions/Current")); err != nil {
		t.Fatal(err)
	}
	bundleLink(t, b, "Versions/Current", "B")
	if err := opened.validateFrameworkRoot(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestBundleLinkBoundsAndFailures(t *testing.T) {
	for _, target := range []string{"/outside", "../../../outside", "missing", "loop", "CON", "../bad:name", "bad//name"} {
		t.Run(target[:min(len(target), 20)], func(t *testing.T) {
			b := testBundle(t)
			bundleLink(t, b, "Contents/Resources/loop", target)
			before, err := os.ReadFile(filepath.Join(b, "Contents/MacOS/hello"))
			if err != nil {
				t.Fatal(err)
			}
			if err := Sign(context.Background(), b, SignOptions{}); err == nil {
				t.Fatal("bad link signed")
			}
			after, err := os.ReadFile(filepath.Join(b, "Contents/MacOS/hello"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("mutated main", err)
			}
		})
	}
	b := testBundle(t)
	bundleFile(t, b, "Contents/Resources/data", []byte("data"))
	bundleLink(t, b, "Contents/Resources/link", "data")
	opened, err := openAppBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.close()
	scope := newBundleScan()
	scope.bytes = maxFileSize
	if _, err := opened.resourceLink("Contents/Resources/link", "Resources/link", scope); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := opened.resourceLink("missing", "Resources/link", newBundleScan()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := Sign(context.Background(), b, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(b, "Contents/Resources/link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), b, VerifyOptions{}); err == nil {
		t.Fatal("missing sealed link")
	}
}

func TestSymlinkSealValidation(t *testing.T) {
	name := "Resources/link"
	seal := symlinkSeal("target", false)
	for _, test := range []struct {
		seal   any
		actual map[string]any
		valid  bool
	}{
		{seal, map[string]any{name: seal}, true},
		{seal, map[string]any{}, false},
		{seal, map[string]any{name: symlinkSeal("other", false)}, false},
		{map[string]any{"symlink": ""}, map[string]any{}, false},
		{map[string]any{"symlink": "target", "hash2": make([]byte, 32)}, map[string]any{}, false},
		{map[string]any{"symlink": true}, map[string]any{}, false},
	} {
		data := encodeBundleResources(map[string]any{}, map[string]any{name: test.seal})
		_, err := verifyBundleResources(data, test.actual)
		if (err == nil) != test.valid {
			t.Fatal(test, err)
		}
	}
	name = "Resources/fr.lproj/link"
	data := encodeBundleResources(map[string]any{}, map[string]any{name: symlinkSeal("../target", true)})
	if _, err := verifyBundleResources(data, map[string]any{}); err != nil {
		t.Fatal(err)
	}
}

func TestFrameworkNestedHardlinkAndShallow(t *testing.T) {
	app := testBundle(t)
	framework := testFramework(t, true)
	parent := filepath.Join(app, "Contents/Frameworks")
	if err := os.MkdirAll(parent, 0755); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "F.framework")
	if err := os.Rename(framework, destination); err != nil {
		t.Fatal(err)
	}
	if err := Sign(context.Background(), app, SignOptions{Deep: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), app, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(app, "Contents/MacOS/hello"), filepath.Join(destination, "Versions/A/Resources/alias")); err != nil {
		t.Fatal(err)
	}
	if err := Sign(context.Background(), app, SignOptions{Deep: true, Force: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestBundleLayoutAST(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-bundle-layouts.json")
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Targets map[string]map[string]struct {
			Kinds   map[string]int `json:"ast_kinds"`
			Members map[string]int `json:"members"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		methods := record.Targets[target]
		if len(methods) != 8 || methods["bestGuess"].Kinds["CXXNewExpr"] != 7 || methods["validateFrameworkRoot"].Kinds["BlockExpr"] != 1 || methods["validateSymlinkResource"].Members["reportProblem"] != 2 || methods["checkMoved"].Kinds["IfStmt"] != 2 || methods["purgeMetaDirectory"].Members["unlink"] != 1 || methods["setup"].Members["version"] != 4 || methods["validateOtherVersions"].Members["staticValidate"] != 1 {
			t.Fatal(target, methods)
		}
	}
}
