package codesign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const testBundleInfo = `<plist version="1.0"><dict><key>CFBundleExecutable</key><string>hello</string><key>CFBundleIdentifier</key><string>org.example.bundle</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>`

func bundleFile(t *testing.T, app, name string, data []byte) {
	t.Helper()
	p := filepath.Join(app, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0755); err != nil {
		t.Fatal(err)
	}
}
func testBundle(t *testing.T) string {
	t.Helper()
	app := filepath.Join(t.TempDir(), "Example.app")
	bundleFile(t, app, "Contents/Info.plist", []byte(testBundleInfo))
	bundleFile(t, app, "Contents/MacOS/hello", fixture(t, "unsigned-arm64"))
	return app
}

func TestBundleLifecycle(t *testing.T) {
	ctx := context.Background()
	app := testBundle(t)
	bundleFile(t, app, ".DS_Store", []byte("ignored"))
	bundleFile(t, app, "Contents/Resources/empty", nil)
	r, err := Inspect(ctx, app)
	if err != nil || r.Bundle == nil || r.Valid {
		t.Fatal(r, err)
	}
	if _, err := Verify(ctx, app, VerifyOptions{}); !errors.Is(err, ErrUnsigned) {
		t.Fatal(err)
	}
	if err := Sign(ctx, app, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err = Verify(ctx, app, VerifyOptions{Architecture: "arm64"})
	if err != nil || !r.Valid {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, app, VerifyOptions{Architecture: "missing"}); err == nil {
		t.Fatal("unknown architecture")
	}
	if err := Sign(ctx, app, SignOptions{}); !errors.Is(err, ErrSigned) {
		t.Fatal(err)
	}
	if err := Sign(ctx, app, SignOptions{Force: true, Identifier: "override"}); err != nil {
		t.Fatal(err)
	}
	r, err = Verify(ctx, app, VerifyOptions{})
	if err != nil || r.Architectures[0].Signature.Directories[0].Identifier != "override" {
		t.Fatal(err)
	}
	if err := RemoveSignature(ctx, app); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSignature(ctx, app); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []SignOptions{{InfoPlist: []byte("x")}, {Resources: []byte("x")}} {
		if err := Sign(ctx, app, opts); err == nil {
			t.Fatal("override accepted")
		}
	}
	if _, err := Verify(ctx, app, VerifyOptions{Resources: []byte("x")}); err == nil {
		t.Fatal("verify override")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	for _, fn := range []func() error{func() error { return Sign(cancelCtx, app, SignOptions{}) }, func() error { _, err := Inspect(cancelCtx, app); return err }, func() error { _, err := Verify(cancelCtx, app, VerifyOptions{}); return err }, func() error { return RemoveSignature(cancelCtx, app) }} {
		if err := fn(); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

func TestBundleRejectsUnsupportedLayout(t *testing.T) {
	for _, name := range []string{"extra", "Contents/Frameworks/F.unsupported/file", "Contents/CodeResources", "Contents/_CodeSignature/coderesources", "Contents/_MASReceipt/receipt"} {
		t.Run(name, func(t *testing.T) {
			app := testBundle(t)
			bundleFile(t, app, name, []byte("unsupported"))
			before, _ := os.ReadFile(filepath.Join(app, "Contents/MacOS/hello"))
			if err := Sign(context.Background(), app, SignOptions{}); !errors.Is(err, ErrUnsupported) {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(filepath.Join(app, "Contents/MacOS/hello"))
			if !bytes.Equal(before, after) {
				t.Fatal("mutated")
			}
			if _, err := Inspect(context.Background(), app); err == nil {
				t.Fatal("inspect")
			}
			if _, err := Verify(context.Background(), app, VerifyOptions{}); err == nil {
				t.Fatal("verify")
			}
			if err := RemoveSignature(context.Background(), app); err == nil {
				t.Fatal("remove")
			}
		})
	}
	for _, name := range []string{"Contents/Resources", "Contents/_CodeSignature"} {
		app := testBundle(t)
		bundleFile(t, app, name, []byte("file instead of directory"))
		if err := Sign(context.Background(), app, SignOptions{}); err == nil {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"Contents/PkgInfo", "Contents/version.plist", "Contents/MacOS/hello"} {
		app := testBundle(t)
		_ = os.Remove(filepath.Join(app, name))
		if err := os.MkdirAll(filepath.Join(app, name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := Sign(context.Background(), app, SignOptions{}); err == nil {
			t.Fatal(name)
		}
	}
	for _, bad := range []string{"../escape", "/absolute", "a\\b", "a:b", "a?b", "a\x00b", "é", "a.", "a ", "NUL", "COM1.txt", strings.Repeat("a", 256), strings.Repeat("a/", 34) + "b", strings.Repeat("a/", 600) + "b"} {
		if err := bundleRelativePath(bad); err == nil {
			t.Fatal("path accepted", bad)
		}
	}
	if runtime.GOOS != "windows" {
		app := testBundle(t)
		bundleFile(t, app, "Contents/Resources/a", nil)
		bundleFile(t, app, "Contents/Resources/A", nil)
		// Case-insensitive filesystems cannot create this pair; test only if both exist.
		entries, _ := os.ReadDir(filepath.Join(app, "Contents/Resources"))
		if len(entries) == 2 {
			if err := Sign(context.Background(), app, SignOptions{}); err == nil {
				t.Fatal("case collision")
			}
		}
	}
}

func TestBundleMetadataErrors(t *testing.T) {
	for _, info := range []string{"", "not XML", `<plist><array/></plist>`, strings.Replace(testBundleInfo, "hello", "../escape", 1), strings.Replace(testBundleInfo, "hello", "", 1), strings.Replace(testBundleInfo, "hello", ".", 1), strings.Replace(testBundleInfo, "org.example.bundle", "", 1), strings.Replace(testBundleInfo, "APPL", "FMWK", 1), strings.Replace(testBundleInfo, "</dict>", "<key>MainHTML</key><string>x</string></dict>", 1), strings.Replace(testBundleInfo, "</dict>", "<key>CFBundleIdentifier</key><string>duplicate</string></dict>", 1), `<plist><dict><key>bad`, strings.Repeat("<array>", 34) + strings.Repeat("</array>", 34), `<plist><dict>` + strings.Repeat("<true/>", 100001) + `</dict></plist>`, strings.Repeat("x", maxBundlePlist+1)} {
		t.Run(strconv.Itoa(len(info)), func(t *testing.T) {
			app := testBundle(t)
			bundleFile(t, app, "Contents/Info.plist", []byte(info))
			if err := Sign(context.Background(), app, SignOptions{}); err == nil {
				t.Fatal("accepted metadata")
			}
			if _, err := Inspect(context.Background(), app); err == nil {
				t.Fatal("inspect metadata")
			}
			if _, err := Verify(context.Background(), app, VerifyOptions{}); err == nil {
				t.Fatal("verify metadata")
			}
			if err := RemoveSignature(context.Background(), app); err == nil {
				t.Fatal("remove metadata")
			}
		})
	}
	app := testBundle(t)
	if err := os.Remove(filepath.Join(app, "Contents/Info.plist")); err != nil {
		t.Fatal(err)
	}
	if _, err := openAppBundle(app); err == nil {
		t.Fatal("missing plist")
	}
	if _, err := openAppBundle(filepath.Join(app, "missing")); err == nil {
		t.Fatal("missing root")
	}
	if _, err := openAppBundle(filepath.Join(app, "Contents/MacOS/hello")); err == nil {
		t.Fatal("file root")
	}
	for _, name := range []string{"Contents/Info.plist", "Contents/MacOS/hello"} {
		app := testBundle(t)
		_ = os.Remove(filepath.Join(app, name))
		if err := os.Mkdir(filepath.Join(app, name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := Sign(context.Background(), app, SignOptions{}); err == nil {
			t.Fatal(name)
		}
	}
}

func TestBundleIOErrors(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.root.Close()
	ctx := context.Background()
	if _, err := b.read("Contents", 100); err == nil {
		t.Fatal("read directory")
	}
	if _, err := b.read("Contents/Info.plist", 1); err == nil {
		t.Fatal("read limit")
	}
	if err := b.write(ctx, "Contents", nil, false); err == nil {
		t.Fatal("write directory")
	}
	if err := b.write(ctx, "missing", nil, false); err == nil {
		t.Fatal("write missing")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := b.write(cancelCtx, b.executable, nil, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	b.annotate(nil, nil)
	bundleFile(t, app, "Contents/MacOS/hello", []byte("not Mach-O"))
	if _, err := inspectBundle(ctx, app, PathOptions{}); err == nil {
		t.Fatal("inspect malformed")
	}
	if err := removeBundle(ctx, app, PathOptions{}); err == nil {
		t.Fatal("remove malformed")
	}
	if err := os.Remove(filepath.Join(app, b.executable)); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectBundle(ctx, app, PathOptions{}); err == nil {
		t.Fatal("inspect missing")
	}
	if _, err := verifyBundle(ctx, app, VerifyOptions{}); err == nil {
		t.Fatal("verify missing")
	}
	if err := signBundle(ctx, app, SignOptions{}); err == nil {
		t.Fatal("sign missing")
	}
	if err := removeBundle(ctx, app, PathOptions{}); err == nil {
		t.Fatal("remove missing")
	}
	if err := b.root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.scan(ctx); err == nil {
		t.Fatal("scan closed root")
	}
	if _, err := b.read(b.executable, 100); err == nil {
		t.Fatal("read closed root")
	}
	if err := b.write(ctx, b.executable, nil, false); err == nil {
		t.Fatal("write closed root")
	}
}

func TestBundleResourcePolicy(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		include, optional, legacy bool
	}{{"Resources/a", true, false, false}, {"Resources/fr.lproj/a", true, true, false}, {"Resources/Base.lproj/a", true, false, false}, {"Resources/fr.lproj/locversion.plist", false, false, false}, {"Resources/.DS_Store", false, false, false}, {"PkgInfo", false, false, false}, {"version.plist", true, false, true}, {"Resources/.DS_Store", true, false, true}, {"other", false, false, true}} {
		a, b := resourcePolicy(tc.name, tc.legacy)
		if a != tc.include || b != tc.optional {
			t.Fatal(tc, a, b)
		}
	}
	actual := map[string]any{"Resources/a": resourceSeal(make([]byte, 32), false, false)}
	data := encodeBundleResources(map[string]any{}, actual)
	if _, err := verifyBundleResources(data, actual); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(map[string]any){func(m map[string]any) { delete(m, "files2") }, func(m map[string]any) { m["rules2"] = map[string]any{} }, func(m map[string]any) { m["extra"] = true }, func(m map[string]any) { m["files2"] = map[string]any{"../escape": true} }, func(m map[string]any) { m["files2"] = map[string]any{"Info.plist": true} }, func(m map[string]any) { m["files2"] = map[string]any{"Resources/a": true} }, func(m map[string]any) {
		m["files2"] = map[string]any{"Resources/a": map[string]any{"hash2": []byte("short")}}
	}, func(m map[string]any) {
		m["files2"] = map[string]any{"Resources/a": map[string]any{"hash2": make([]byte, 32), "optional": true}}
	}} {
		m, err := decodeBundlePlist(data)
		if err != nil {
			t.Fatal(err)
		}
		mutation(m)
		var out strings.Builder
		out.WriteString(`<plist version="1.0">`)
		entitlementXML(&out, m, 0)
		out.WriteString(`</plist>`)
		if _, err := verifyBundleResources([]byte(out.String()), actual); err == nil {
			t.Fatal("accepted invalid envelope")
		}
	}
	if _, err := verifyBundleResources(nil, nil); err == nil {
		t.Fatal("empty envelope")
	}
	if _, err := verifyBundleResources(data, nil); err == nil {
		t.Fatal("missing resource")
	}
	if _, err := verifyBundleResources(data, map[string]any{"Resources/a": true}); err == nil {
		t.Fatal("changed resource")
	}
	if _, err := verifyBundleResources(data, map[string]any{"Resources/a": actual["Resources/a"], "Resources/new": true}); err == nil {
		t.Fatal("added resource")
	}
	optional := encodeBundleResources(map[string]any{}, map[string]any{"Resources/fr.lproj/a": resourceSeal(make([]byte, 32), true, false)})
	if _, err := verifyBundleResources(optional, nil); err != nil {
		t.Fatal(err)
	}
}

func TestBundleClangFacts(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-bundles.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		Targets map[string]struct {
			Flags   map[string]string
			Methods map[string]struct{ Literals []string }
		}
	}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	if len(facts.Targets) != 2 {
		t.Fatal("two Clang targets required")
	}
	for target, facts := range facts.Targets {
		if !reflect.DeepEqual(facts.Flags, map[string]string{"optional": "1", "omitted": "2", "nested": "4", "exclusion": "16", "softTarget": "32", "user_controlled": "64"}) {
			t.Fatal(target, "flags")
		}
		var literals strings.Builder
		for _, literal := range facts.Methods["defaultResourceRules"].Literals {
			decoded, err := strconv.Unquote(literal)
			if err != nil {
				t.Fatal(err)
			}
			literals.WriteString(decoded)
		}
		for pattern := range bundleRules(false) {
			pattern = strings.TrimPrefix(pattern, "^Resources/")
			if pattern != "" && !strings.Contains(literals.String(), pattern) {
				t.Fatal(target, "rule absent from Apple AST", pattern)
			}
		}
	}
}

func FuzzBundleResources(f *testing.F) {
	f.Add(encodeBundleResources(map[string]any{}, map[string]any{}))
	f.Add([]byte(testBundleInfo))
	f.Add(scalarBundlePlist([]byte{9}))
	f.Add(rawBundlePlist([][]byte{{0xd1, 1, 2}, {0x51, 'k'}, {0xa2, 3, 3}, {0x61, 0, 'v'}}, 1, 1))
	f.Add(rawBundlePlist([][]byte{{0xd1, 1, 2}, {0x51, 'k'}, {0xa1, 2}}, 8, 1))
	binaryInfo, err := os.ReadFile("../../testdata/bundle-plists/Info.plist")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(binaryInfo)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxBundlePlist {
			return
		}
		_, _ = verifyBundleResources(data, map[string]any{})
	})
}

func TestBundleSymlinksAndLimits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires Windows privileges")
	}
	ctx := context.Background()
	for _, name := range []string{"Contents", "Contents/Info.plist", "Contents/MacOS/hello", "Contents/Resources/escape", "Contents/_CodeSignature"} {
		t.Run(name, func(t *testing.T) {
			app := testBundle(t)
			destination := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(destination, []byte("outside"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(app, filepath.FromSlash(name))
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(destination, path); err != nil {
				t.Fatal(err)
			}
			if err := Sign(ctx, app, SignOptions{}); err == nil {
				t.Fatal("followed symlink")
			}
			got, _ := os.ReadFile(destination)
			if string(got) != "outside" {
				t.Fatal("modified outside target")
			}
		})
	}
	app := testBundle(t)
	link := filepath.Join(t.TempDir(), "Link.app")
	if err := os.Symlink(app, link); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, link, SignOptions{}); err == nil {
		t.Fatal("root symlink")
	}
	// Sparse resource exercises the streaming bound without a GiB allocation.
	app = testBundle(t)
	path := filepath.Join(app, "Contents/Resources/huge")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, app, SignOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestBundleMissingBindings(t *testing.T) {
	app := testBundle(t)
	ctx := context.Background()
	opts := SignOptions{Identifier: "org.example.bundle", InfoPlist: []byte(testBundleInfo)}
	data, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), opts)
	if err != nil {
		t.Fatal(err)
	}
	bundleFile(t, app, "Contents/MacOS/hello", data)
	bundleFile(t, app, bundleResourcesPath, encodeBundleResources(map[string]any{}, map[string]any{}))
	r, err := Verify(ctx, app, VerifyOptions{})
	if err == nil || r == nil || r.Valid {
		t.Fatal("accepted missing resource binding", err)
	}
}

func TestBundleHardLinkedWriteTargets(t *testing.T) {
	for _, target := range []string{"Contents/MacOS/hello", bundleResourcesPath} {
		t.Run(target, func(t *testing.T) {
			app := testBundle(t)
			if target == bundleResourcesPath {
				bundleFile(t, app, target, []byte("old envelope"))
			}
			alias := "Contents/Resources/alias"
			bundleFile(t, app, alias, nil)
			path := filepath.Join(app, filepath.FromSlash(alias))
			source := filepath.Join(app, filepath.FromSlash(target))
			before, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			// macOS disallows linking from CodeResources; the reverse direction
			// creates the same alias and is supported on all three test OSes.
			if err := os.WriteFile(path, before, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(path, source); err != nil {
				t.Fatal(err)
			}
			if err := Sign(context.Background(), app, SignOptions{}); !errors.Is(err, ErrUnsupported) {
				t.Fatal("accepted hard link to a write target", err)
			}
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("changed hard-linked file", err)
			}
		})
	}
}

func TestBundleXMLStructure(t *testing.T) {
	for _, malformed := range []string{
		`<plist><dict><key><array/></key><true/></dict></plist>`,
		`<plist><key>x</key></plist>`,
		`<plist><dict><array><key>x</key></array></dict></plist>`,
		testBundleInfo + testBundleInfo,
		testBundleInfo + "trailing text",
		`<dict/>`,
	} {
		if _, err := decodeBundlePlist([]byte(malformed)); err == nil {
			t.Fatal("accepted malformed XML", malformed)
		}
	}
}

func TestBundleTimestampFailurePreservesFiles(t *testing.T) {
	ctx := context.Background()
	for _, signed := range []bool{false, true} {
		t.Run(strconv.FormatBool(signed), func(t *testing.T) {
			app := testBundle(t)
			if signed {
				if err := Sign(ctx, app, SignOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			mainPath := filepath.Join(app, "Contents/MacOS/hello")
			resourcePath := filepath.Join(app, filepath.FromSlash(bundleResourcesPath))
			before, err := os.ReadFile(mainPath)
			if err != nil {
				t.Fatal(err)
			}
			resources, resourceErr := os.ReadFile(resourcePath)
			failure := errors.New("test TSA failed")
			opts := SignOptions{Force: signed, Identity: testIdentity(t, "rsa"), Timestamp: &TimestampOptions{
				TrustedRoots: AppleTimestampRoots(),
				Provider:     func(context.Context, []byte) ([]byte, error) { return nil, failure },
			}}
			if err := Sign(ctx, app, opts); !errors.Is(err, failure) {
				t.Fatal(err)
			}
			after, err := os.ReadFile(mainPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("TSA failure modified executable", err)
			}
			afterResources, err := os.ReadFile(resourcePath)
			if !bytes.Equal(resources, afterResources) || (err == nil) != (resourceErr == nil) {
				t.Fatal("TSA failure modified resource envelope", err)
			}
			if !signed {
				if _, err := os.Stat(filepath.Dir(resourcePath)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("TSA failure created signature directory", err)
				}
			}
		})
	}
}
