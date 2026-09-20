package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFrameworkVersions(t *testing.T) string {
	t.Helper()
	b := testFramework(t, true)
	if err := os.CopyFS(filepath.Join(b, "Versions/B"), os.DirFS(filepath.Join(b, "Versions/A"))); err != nil {
		t.Fatal(err)
	}
	bundleFile(t, b, "Versions/B/Resources/data", []byte("different B resource"))
	return b
}

func TestFrameworkVersionSelection(t *testing.T) {
	ctx := context.Background()
	b := testFrameworkVersions(t)
	for _, version := range []string{"B", "A"} {
		if err := Sign(ctx, b, SignOptions{BundleVersion: version}); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(ctx, b, VerifyOptions{BundleVersion: version, Deep: true}); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []string{"", "Current", "A", "B"} {
		r, err := InspectWithOptions(ctx, b, PathOptions{BundleVersion: version})
		if err != nil {
			t.Fatal(err)
		}
		selected := version
		if selected == "" {
			selected = "Current"
		}
		if r.Bundle.Executable != filepath.Join(b, "Versions", selected, "F") {
			t.Fatal(r.Bundle)
		}
	}
	a := readTestFile(t, filepath.Join(b, "Versions/A/F"))
	if err := RemoveSignatureWithOptions(ctx, b, PathOptions{BundleVersion: "B"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, readTestFile(t, filepath.Join(b, "Versions/A/F"))) {
		t.Fatal("removing B changed A")
	}
	if _, err := Verify(ctx, b, VerifyOptions{BundleVersion: "B"}); !errors.Is(err, ErrUnsigned) {
		t.Fatal(err)
	}
	// The unselected version need not even be a recognized bundle.
	bundleFile(t, b, "Versions/B/Resources/Info.plist", []byte("unknown metadata"))
	if _, err := Verify(ctx, b, VerifyOptions{Deep: true}); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"missing", ".", "..", "../A", "/A", "CON", `A\B`} {
		if err := Sign(ctx, b, SignOptions{BundleVersion: version, Force: true}); err == nil {
			t.Fatal("unsafe selection", version)
		}
		if _, err := InspectWithOptions(ctx, b, PathOptions{BundleVersion: version}); err == nil {
			t.Fatal("unsafe inspection", version)
		}
		if err := RemoveSignatureWithOptions(ctx, b, PathOptions{BundleVersion: version}); err == nil {
			t.Fatal("unsafe removal", version)
		}
	}
}

func readTestFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNestedFrameworkVersions(t *testing.T) {
	ctx := context.Background()
	for _, mutation := range []string{"none", "unsigned", "requirement", "page", "resource", "info", "malformed"} {
		t.Run(mutation, func(t *testing.T) {
			parent, framework := testBundle(t), testFrameworkVersions(t)
			dest := filepath.Join(parent, "Contents/Frameworks/F.framework")
			if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(framework, dest); err != nil {
				t.Fatal(err)
			}
			req, err := RequirementsBytes([]byte(`designated => identifier "org.example.bundle"`))
			if err != nil {
				t.Fatal(err)
			}
			for _, version := range []string{"A", "B"} {
				if mutation == "unsigned" && version == "B" {
					continue
				}
				if err := Sign(ctx, dest, SignOptions{BundleVersion: version, Requirements: req}); err != nil {
					t.Fatal(err)
				}
			}
			if err := Sign(ctx, parent, SignOptions{}); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "requirement":
				if err := Sign(ctx, dest, SignOptions{BundleVersion: "B", Force: true, Identifier: "other"}); err != nil {
					t.Fatal(err)
				}
			case "page":
				p := filepath.Join(dest, "Versions/B/F")
				data := readTestFile(t, p)
				data[4096] ^= 1
				bundleFile(t, dest, "Versions/B/F", data)
			case "resource":
				bundleFile(t, dest, "Versions/B/Resources/data", []byte("tampered"))
			case "info":
				bundleFile(t, dest, "Versions/B/Resources/Info.plist", append(readTestFile(t, filepath.Join(dest, "Versions/B/Resources/Info.plist")), '\n'))
			case "malformed":
				bundleFile(t, dest, "Versions/B/F", []byte("not Mach-O"))
			}
			for _, deep := range []bool{false, true} {
				_, err := Verify(ctx, parent, VerifyOptions{Deep: deep})
				valid := mutation == "none" || !deep && (mutation == "page" || mutation == "resource")
				if (err == nil) != valid {
					t.Fatalf("deep=%v valid=%v error=%v", deep, valid, err)
				}
				if _, err := Verify(ctx, dest, VerifyOptions{Deep: deep}); err != nil {
					t.Fatal("standalone inspected an alternate signature", err)
				}
			}
		})
	}
}

func TestFrameworkVersionBudgetsAndHardlinks(t *testing.T) {
	ctx := context.Background()
	b := testFrameworkVersions(t)
	opened, err := openAppBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.close()
	for _, exhausted := range []string{"entries", "bytes", "children", "canceled"} {
		scope := newBundleScan()
		callCtx := ctx
		switch exhausted {
		case "entries":
			scope.entries = maxBundleEntries
		case "bytes":
			scope.bytes = maxFileSize
		case "children":
			scope.nested = maxNestedFiles
		case "canceled":
			var cancel context.CancelFunc
			callCtx, cancel = context.WithCancel(ctx)
			cancel()
		}
		if err := opened.inventoryOtherVersions(callCtx, scope, ""); err == nil {
			t.Fatal("ignored budget", exhausted)
		}
	}
	layout := "Versions/B/Resources/alias"
	if err := os.Link(filepath.Join(b, "Versions/A/F"), filepath.Join(b, layout)); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, b, SignOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(b, layout)); err != nil {
		t.Fatal(err)
	}
	// A raw link is inventoried without following an unselected version's alias.
	bundleLink(t, b, layout, "missing")
	if err := Sign(ctx, b, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxNestedFiles; i++ {
		if err := os.Mkdir(filepath.Join(b, "Versions", fmt.Sprintf("V%02d", i)), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Inspect(ctx, b); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestBundleVersionIgnoredForOtherInputs(t *testing.T) {
	ctx := context.Background()
	for _, b := range []string{testBundle(t)} {
		if err := Sign(ctx, b, SignOptions{BundleVersion: "missing"}); err != nil {
			t.Fatal(err)
		}
		r, err := InspectWithOptions(ctx, b, PathOptions{BundleVersion: "missing"})
		if err != nil || strings.Contains(r.Bundle.Executable, "missing") {
			t.Fatal(r, err)
		}
		if _, err := Verify(ctx, b, VerifyOptions{BundleVersion: "missing"}); err != nil {
			t.Fatal(err)
		}
		if err := RemoveSignatureWithOptions(ctx, b, PathOptions{BundleVersion: "missing"}); err != nil {
			t.Fatal(err)
		}
	}
}
