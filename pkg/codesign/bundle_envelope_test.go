package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnvelopeDirectoryRetainsWriteAliasGuard(t *testing.T) {
	for _, dry := range []bool{false, true} {
		app := testBundle(t)
		child := nestedApp(t, app, "Contents/PlugIns/Child.app")
		main := filepath.Join(child, "Contents/MacOS/hello")
		before := readTestFile(t, main)
		st, err := os.Stat(main)
		if err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(app, bundleResourcesPath, "alias")
		if err := os.MkdirAll(filepath.Dir(alias), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(main, alias); err != nil {
			t.Fatal(err)
		}
		err = Sign(context.Background(), app, SignOptions{Deep: true, DryRun: dry})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatal("accepted write alias under envelope directory", err)
		}
		current, err := os.Stat(main)
		if err != nil || !os.SameFile(st, current) || !bytes.Equal(readTestFile(t, main), before) {
			t.Fatal("alias rejection committed a child", err)
		}
		assertNoBundleStaging(t, app)
	}
}

func TestEnvelopeSymlinksStillRejectBeforeWrites(t *testing.T) {
	for _, kind := range []string{"internal", "external", "dangling"} {
		for _, dry := range []bool{false, true} {
			t.Run(kind+map[bool]string{true: "/dryrun", false: "/sign"}[dry], func(t *testing.T) {
				app := testBundle(t)
				child := nestedApp(t, app, "Contents/PlugIns/Child.app")
				target := filepath.Join(t.TempDir(), "target")
				if kind == "internal" {
					target = filepath.Join(app, "Contents/Resources/data")
				}
				if kind != "dangling" {
					if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(target, []byte("preserved target"), 0644); err != nil {
						t.Fatal(err)
					}
				}
				envelope := filepath.Join(app, bundleResourcesPath)
				if err := os.MkdirAll(filepath.Dir(envelope), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, envelope); err != nil {
					t.Fatal(err)
				}
				paths := []string{filepath.Join(app, "Contents/MacOS/hello"), filepath.Join(child, "Contents/MacOS/hello")}
				before := make([]os.FileInfo, len(paths))
				for i, p := range paths {
					var err error
					before[i], err = os.Stat(p)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := Sign(context.Background(), app, SignOptions{Deep: true, DryRun: dry}); !errors.Is(err, ErrFormat) {
					t.Fatal("accepted signing envelope symlink", err)
				}
				for i, p := range paths {
					current, err := os.Stat(p)
					if err != nil || !os.SameFile(before[i], current) || !bytes.Equal(readTestFile(t, p), fixture(t, "unsigned-arm64")) {
						t.Fatal("rejected envelope changed executable", err)
					}
				}
				if link, err := os.Readlink(envelope); err != nil || link != target {
					t.Fatal("changed envelope link", err)
				}
				if kind == "dangling" {
					if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("created symlink target", err)
					}
				} else if string(readTestFile(t, target)) != "preserved target" {
					t.Fatal("mutated symlink target")
				}
				assertNoBundleStaging(t, app)
			})
		}
	}
}

func TestDeepVerificationStillRejectsEnvelopeDirectory(t *testing.T) {
	ctx := context.Background()
	app := testBundle(t)
	child := nestedApp(t, app, "Contents/PlugIns/Child.app")
	if err := Sign(ctx, app, SignOptions{Deep: true}); err != nil {
		t.Fatal(err)
	}
	envelope := filepath.Join(child, bundleResourcesPath)
	if err := os.Remove(envelope); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(envelope, 0755); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, app, SignOptions{Deep: true, Force: true, DryRun: true}); err != nil {
		t.Fatal("dry run rejected envelope directory", err)
	}
	if _, err := Verify(ctx, app, VerifyOptions{Deep: true}); !errors.Is(err, ErrFormat) {
		t.Fatal("deep verification accepted envelope directory", err)
	}
	assertNoBundleStaging(t, app)
}
