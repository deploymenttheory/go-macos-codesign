package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrameworkDirectoryPaths(t *testing.T) {
	ctx := context.Background()
	for _, selector := range []string{"A", "B", "Current"} {
		t.Run(selector, func(t *testing.T) {
			framework := testFrameworkVersions(t)
			p := filepath.Join(framework, "Versions", selector)
			other := "B"
			physical := selector
			if selector == "Current" {
				physical = "A"
			}
			if physical == "B" {
				other = "A"
			}
			before := readTestFile(t, filepath.Join(framework, "Versions", other, "F"))
			if err := Sign(ctx, p, SignOptions{Deep: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, p, VerifyOptions{Deep: true}); err != nil {
				t.Fatal(err)
			}
			r, err := Inspect(ctx, p)
			want, resolveErr := filepath.EvalSymlinks(filepath.Join(framework, "Versions", physical, "F"))
			if err != nil || resolveErr != nil || r.Bundle.Executable != want {
				t.Fatal(r, err)
			}
			if err := Sign(ctx, p, SignOptions{Force: true, DryRun: true}); err != nil {
				t.Fatal(err)
			}
			if err := RemoveSignature(ctx, p); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, p, VerifyOptions{}); !errors.Is(err, ErrUnsigned) {
				t.Fatal(err)
			}
			if !bytes.Equal(before, readTestFile(t, filepath.Join(framework, "Versions", other, "F"))) {
				t.Fatal("changed unselected version")
			}
		})
	}
}

func TestFrameworkDirectoryBoundary(t *testing.T) {
	ctx := context.Background()
	b := testFrameworkVersions(t)
	p := filepath.Join(b, "Versions/B")
	// Direct versions do not validate the enclosing framework or other versions.
	if err := os.Remove(filepath.Join(b, "F")); err != nil {
		t.Fatal(err)
	}
	bundleFile(t, b, "unsealed", []byte("outer file"))
	bundleFile(t, b, "Versions/A/Resources/Info.plist", []byte("invalid"))
	if err := Sign(ctx, p, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, p, VerifyOptions{Deep: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, b, VerifyOptions{}); err == nil {
		t.Fatal("accepted enclosing malformed root")
	}
	for _, selector := range []string{"A", "B", "Current", "missing"} {
		if err := Sign(ctx, p, SignOptions{BundleVersion: selector, Force: true}); err == nil {
			t.Fatal("arbitrated a direct version", selector)
		}
		if _, err := InspectWithOptions(ctx, p, PathOptions{BundleVersion: selector}); err == nil {
			t.Fatal("inspected a nested version", selector)
		}
	}
	if err := os.Link(filepath.Join(p, "F"), filepath.Join(p, "Resources/alias")); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, p, SignOptions{Force: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestFrameworkCurrentPathSafety(t *testing.T) {
	ctx := context.Background()
	for _, target := range []string{"./A", "A", "Current", ".", "../A", "CON", "A/B", "missing", "file", "absolute-file", "alias"} {
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			b := testFramework(t, true)
			p := filepath.Join(b, "Versions/Current")
			outside := filepath.Join(t.TempDir(), "outside")
			original := fixture(t, "unsigned-arm64")
			if err := os.WriteFile(outside, original, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			link := target
			if target == "absolute-file" {
				link = outside
			}
			if target == "alias" {
				bundleLink(t, b, "Versions/alias", "A")
			}
			if target == "file" {
				bundleFile(t, b, "Versions/file", original)
			}
			bundleLink(t, b, "Versions/Current", link)
			err := Sign(ctx, p, SignOptions{})
			valid := target == "A" || target == "./A"
			if (err == nil) != valid {
				t.Fatal(target, err)
			}
			if !bytes.Equal(original, readTestFile(t, outside)) {
				t.Fatal("changed outside file")
			}
		})
	}
	b := testFramework(t, true)
	if err := os.Remove(filepath.Join(b, "Versions/Current")); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(ctx, filepath.Join(b, "Versions/Current")); err == nil {
		t.Fatal("missing Current")
	}
	if _, err := resolveBundleDirectory(filepath.Join(b, "Versions/CON")); err == nil {
		t.Fatal("reserved directory")
	}
	// A trailing separator or /. must not let Lstat follow a version-root alias.
	bundleLink(t, b, "Versions/B", "A")
	for _, suffix := range []string{"", string(filepath.Separator), string(filepath.Separator) + "."} {
		if err := Sign(ctx, filepath.Join(b, "Versions/B")+suffix, SignOptions{}); !errors.Is(err, ErrUnsupported) {
			t.Fatal("followed version alias", suffix, err)
		}
	}
	if err := os.RemoveAll(filepath.Join(b, "Versions")); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(ctx, filepath.Join(b, "Versions/Current")); err == nil {
		t.Fatal("missing Versions directory")
	}
}
