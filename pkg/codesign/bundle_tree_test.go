package codesign

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func nestedApp(t *testing.T, outer, name string) string {
	t.Helper()
	app := filepath.Join(outer, filepath.FromSlash(name))
	bundleFile(t, app, "Contents/Info.plist", []byte(testBundleInfo))
	bundleFile(t, app, "Contents/MacOS/hello", fixture(t, "unsigned-arm64"))
	bundleFile(t, app, "Contents/Resources/data", []byte("resource"))
	return app
}

func TestRecursiveAppTrust(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"rsa", "p256"} {
		app := testBundle(t)
		child := nestedApp(t, app, "Contents/Helpers/Child.app")
		grand := nestedApp(t, child, "Contents/Helpers/Grand.app")
		id := testIdentity(t, kind)
		if err := Sign(ctx, grand, SignOptions{Identity: id}); err != nil {
			t.Fatal(err)
		}
		if err := Sign(ctx, app, SignOptions{Deep: true}); err != nil {
			t.Fatal(err)
		}
		// Shallow verification stops at the immediate ad-hoc child.
		if _, err := Verify(ctx, app, VerifyOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(ctx, app, VerifyOptions{Deep: true}); err == nil {
			t.Fatal("deep verification bypassed grandchild trust")
		}
		if _, err := Verify(ctx, app, VerifyOptions{Deep: true, TrustedCertificates: id.Certificates}); err != nil {
			t.Fatal(err)
		}
		if err := Sign(ctx, child, SignOptions{Identity: id, Force: true}); err != nil {
			t.Fatal(err)
		}
		if err := Sign(ctx, app, SignOptions{Force: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(ctx, app, VerifyOptions{}); err == nil {
			t.Fatal("shallow verification bypassed immediate child trust")
		}
		if _, err := Verify(ctx, app, VerifyOptions{TrustedCertificates: id.Certificates}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecursiveAppBounds(t *testing.T) {
	ctx := context.Background()
	for _, depth := range []int{maxBundleDepth, maxBundleDepth + 1} {
		app := testBundle(t)
		current := app
		for i := 0; i < depth; i++ {
			current = nestedApp(t, current, "Contents/MacOS/A.app")
		}
		err := Sign(ctx, app, SignOptions{Deep: true})
		if depth == maxBundleDepth {
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, app, VerifyOptions{Deep: true}); err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, ErrUnsupported) {
			t.Fatal("depth limit", err)
		}
	}
	app := testBundle(t)
	for i := 0; i < 2; i++ {
		child := nestedApp(t, app, fmt.Sprintf("Contents/Helpers/Child%d.app", i))
		for j := 0; j < maxNestedFiles/2; j++ {
			bundleFile(t, child, fmt.Sprintf("Contents/Helpers/tool%d", j), fixture(t, "unsigned-arm64"))
		}
	}
	if err := Sign(ctx, app, SignOptions{Deep: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("global child count", err)
	}
	app = testBundle(t)
	nestedApp(t, app, "Contents/Helpers/Child.app")
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	scope := newBundleScan()
	scope.entries = maxBundleEntries - 6 // exhausted while descending into the child
	if _, _, err := b.scanTree(ctx, scope, 0, ""); !errors.Is(err, ErrUnsupported) {
		t.Fatal("entry budget", err)
	}
	scope = newBundleScan()
	scope.bytes = maxFileSize
	if _, err := b.scanChild(ctx, "Contents/Helpers/Child.app", scope, 1, ""); !errors.Is(err, ErrUnsupported) {
		t.Fatal("metadata budget", err)
	}
	scope = newBundleScan()
	scope.nested = maxNestedFiles
	if _, err := b.scanChild(ctx, "Contents/Helpers/Child.app", scope, 1, ""); !errors.Is(err, ErrUnsupported) {
		t.Fatal("app count budget", err)
	}
}

func TestRecursiveHardlinks(t *testing.T) {
	for _, tc := range []struct{ from, to string }{
		{"Contents/MacOS/hello", "Contents/Helpers/A.app/Contents/Resources/alias"},
		{"Contents/Helpers/A.app/Contents/MacOS/hello", "Contents/Resources/alias"},
		{"Contents/Helpers/A.app/Contents/MacOS/hello", "Contents/Helpers/B.app/Contents/Resources/alias"},
		{"Contents/Helpers/A.app/Contents/Resources/data", "Contents/Helpers/B.app/Contents/MacOS/hello"},
	} {
		app := testBundle(t)
		nestedApp(t, app, "Contents/Helpers/A.app")
		nestedApp(t, app, "Contents/Helpers/B.app")
		to := filepath.Join(app, filepath.FromSlash(tc.to))
		if err := os.MkdirAll(filepath.Dir(to), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(to); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(app, filepath.FromSlash(tc.from)), to); err != nil {
			t.Fatal(err)
		}
		if err := Sign(context.Background(), app, SignOptions{Deep: true}); !errors.Is(err, ErrUnsupported) {
			t.Fatal(tc, err)
		}
	}
}

type delayedBundleSigner struct {
	crypto.Signer
	calls, failAt int
}

func (s *delayedBundleSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	if s.calls == s.failAt {
		return nil, errors.New("deliberate signing failure")
	}
	return s.Signer.Sign(random, digest, opts)
}

func TestRecursiveConstructionPreservesTree(t *testing.T) {
	for _, failAt := range []int{2, 3} {
		app := testBundle(t)
		a := nestedApp(t, app, "Contents/Helpers/A.app")
		b := nestedApp(t, app, "Contents/Helpers/B.app")
		id := testIdentity(t, "rsa")
		id.Signer = &delayedBundleSigner{Signer: id.Signer, failAt: failAt}
		if err := Sign(context.Background(), app, SignOptions{Deep: true, Identity: id}); err == nil {
			t.Fatal("expected signing failure")
		}
		for _, p := range []string{app, a, b} {
			data, err := os.ReadFile(filepath.Join(p, "Contents/MacOS/hello"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, fixture(t, "unsigned-arm64")) {
				t.Fatal("construction failure modified executable")
			}
			if _, err := os.Stat(filepath.Join(p, "Contents/_CodeSignature")); !os.IsNotExist(err) {
				t.Fatal("construction failure created directory", err)
			}
		}
	}
}

func TestRecursiveMalformedAndClosedRoots(t *testing.T) {
	ctx := context.Background()
	for _, bad := range []string{"info", "executable", "missing-executable", "envelope", "layout", "wrong-package"} {
		app := testBundle(t)
		child := nestedApp(t, app, "Contents/Helpers/Child.app")
		switch bad {
		case "info":
			bundleFile(t, child, "Contents/Info.plist", []byte("bad"))
		case "executable":
			bundleFile(t, child, "Contents/MacOS/hello", []byte("bad"))
		case "missing-executable":
			if err := os.Remove(filepath.Join(child, "Contents/MacOS/hello")); err != nil {
				t.Fatal(err)
			}
		case "envelope":
			if err := os.MkdirAll(filepath.Join(child, bundleResourcesPath), 0755); err != nil {
				t.Fatal(err)
			}
		case "layout":
			bundleFile(t, child, "Contents/unsupported", nil)
		case "wrong-package":
			bundleFile(t, child, "Contents/Info.plist", bytes.ReplaceAll([]byte(testBundleInfo), []byte("APPL"), []byte("FMWK")))
		}
		if err := Sign(ctx, app, SignOptions{Deep: true}); err == nil {
			t.Fatal("accepted malformed child", bad)
		}
	}
	app := testBundle(t)
	nestedApp(t, app, "Contents/Helpers/Child.app")
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.scanChild(ctx, "missing.app", newBundleScan(), 1, ""); err == nil {
		t.Fatal("missing app")
	}
	if _, _, err := b.scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(b.children) != 1 {
		t.Fatal("missing child root")
	}
	b.close()
	if _, err := b.children[0].root.Stat("."); err == nil {
		t.Fatal("child root leaked")
	}
	if _, err := b.root.Stat("."); err == nil {
		t.Fatal("root leaked")
	}
}

func TestNestedAppSourceAST(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-nested-apps.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		Targets map[string]map[string]struct {
			Members map[string]int
			Kinds   map[string]int `json:"ast_kinds"`
		}
	}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	if len(facts.Targets) != 2 {
		t.Fatal("missing Clang target")
	}
	for target, methods := range facts.Targets {
		if methods["scan"].Kinds["SwitchStmt"] != 1 || methods["scan"].Members["findRule"] == 0 {
			t.Fatal(target, "missing directory boundary control flow")
		}
		v := methods["validateNonResourceComponents"]
		if v.Kinds["CaseStmt"] != 1 || v.Members["component"] != 1 || v.Members["validateDirectory"] != 1 {
			t.Fatal(target, "missing shallow metadata policy")
		}
		if methods["findStringEndingNoCase"].Kinds["IfStmt"] != 1 {
			t.Fatal(target, "missing localization helper")
		}
	}
}

func TestRecursiveEnvelopeLimit(t *testing.T) {
	ctx := context.Background()
	app := testBundle(t)
	child := nestedApp(t, app, "Contents/Helpers/Child.app")
	if err := Sign(ctx, app, SignOptions{Deep: true}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(child, bundleResourcesPath), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxBundlePlist + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, app, VerifyOptions{}); err != nil {
		t.Fatal("shallow verification read child resources", err)
	}
	if _, err := Verify(ctx, app, VerifyOptions{Deep: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("deep envelope bound", err)
	}
}
