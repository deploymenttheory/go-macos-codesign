package codesign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutableBundleLifecycle(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"app", "framework", "version", "current", "alias"} {
		t.Run(kind, func(t *testing.T) {
			b := testBundle(t)
			p, resource := filepath.Join(b, "Contents/MacOS/hello"), "Contents/Resources/data"
			if kind != "app" {
				b = testFramework(t, kind != "framework")
				p, resource = filepath.Join(b, "F"), "Resources/data"
				if kind != "framework" {
					resource = "Versions/A/Resources/data"
				}
				if kind == "version" {
					p = filepath.Join(b, "Versions/A/F")
				}
				if kind == "current" {
					p = filepath.Join(b, "Versions/Current/F")
				}
			}
			bundleFile(t, b, resource, []byte("original"))
			if err := Sign(ctx, p, SignOptions{DryRun: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, p, VerifyOptions{}); !errors.Is(err, ErrUnsigned) {
				t.Fatal(err)
			}
			if err := Sign(ctx, p, SignOptions{}); err != nil {
				t.Fatal(err)
			}
			r, err := Inspect(ctx, p)
			physical, e := filepath.EvalSymlinks(p)
			if e != nil {
				t.Fatal(e)
			}
			if err != nil || r.Bundle == nil || r.Bundle.Executable != physical {
				t.Fatal(r, err, physical)
			}
			if _, err = Verify(ctx, p, VerifyOptions{Deep: true}); err != nil {
				t.Fatal(err)
			}
			bundleFile(t, b, resource, []byte("tampered"))
			if _, err = Verify(ctx, p, VerifyOptions{}); err == nil {
				t.Fatal("executable path bypassed resource seal")
			}
			if err = RemoveSignature(ctx, p); err != nil {
				t.Fatal(err)
			}
			if _, err = Verify(ctx, p, VerifyOptions{}); !errors.Is(err, ErrUnsigned) {
				t.Fatal(err)
			}
		})
	}
}

func TestExecutableDiscoveryBoundaries(t *testing.T) {
	ctx := context.Background()
	b := testBundle(t)
	main := filepath.Join(b, "Contents/MacOS/hello")
	for _, kind := range []string{"copy", "hardlink", "renamed", "missing-info", "missing-key"} {
		t.Run(kind, func(t *testing.T) {
			b := testBundle(t)
			p := filepath.Join(b, "Contents/MacOS/helper")
			if kind == "hardlink" {
				if err := os.Link(filepath.Join(b, "Contents/MacOS/hello"), p); err != nil {
					t.Fatal(err)
				}
			} else {
				bundleFile(t, b, "Contents/MacOS/helper", fixture(t, "unsigned-arm64"))
			}
			if kind == "renamed" {
				bundleFile(t, b, "Contents/Info.plist", []byte(strings.ReplaceAll(testBundleInfo, "hello", "other")))
			}
			if kind == "missing-info" {
				if err := os.Remove(filepath.Join(b, "Contents/Info.plist")); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "missing-key" {
				bundleFile(t, b, "Contents/Info.plist", []byte(strings.ReplaceAll(testBundleInfo, "<key>CFBundleExecutable</key><string>hello</string>", "")))
			}
			r, err := Inspect(ctx, p)
			if err != nil || r.Bundle != nil {
				t.Fatal(r, err)
			}
		})
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(main, alias); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, alias, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, alias, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, alias, SignOptions{Force: true, Resources: []byte("override")}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, alias, VerifyOptions{InfoPlist: []byte("override")}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	for _, kind := range []string{"malformed", "oversize", "metadata-link", "package-type"} {
		t.Run(kind, func(t *testing.T) {
			b := testBundle(t)
			p := filepath.Join(b, "Contents/MacOS/hello")
			info := filepath.Join(b, "Contents/Info.plist")
			switch kind {
			case "malformed":
				bundleFile(t, b, "Contents/Info.plist", []byte("invalid"))
			case "oversize":
				bundleFile(t, b, "Contents/Info.plist", bytes.Repeat([]byte("x"), maxBundlePlist+1))
			case "metadata-link":
				if err := os.Remove(info); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(main, info); err != nil {
					t.Fatal(err)
				}
			case "package-type":
				bundleFile(t, b, "Contents/Info.plist", []byte(strings.ReplaceAll(testBundleInfo, "APPL", "????")))
			}
			before := readTestFile(t, p)
			for _, op := range []func() error{func() error { return Sign(ctx, p, SignOptions{}) }, func() error { _, e := Inspect(ctx, p); return e }, func() error { _, e := Verify(ctx, p, VerifyOptions{}); return e }, func() error { return RemoveSignature(ctx, p) }} {
				if err := op(); err == nil {
					t.Fatal("accepted unsupported metadata")
				}
			}
			if !bytes.Equal(before, readTestFile(t, p)) {
				t.Fatal("modified input after discovery failure")
			}
		})
	}
}

func TestExecutableDiscoveryAST(t *testing.T) {
	data := readTestFile(t, "../../spec/apple-bundle-discovery.json")
	var record struct {
		Targets map[string]map[string]struct {
			Kinds      map[string]int `json:"ast_kinds"`
			References map[string]int `json:"references"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		methods := record.Targets[target]
		if len(methods) != 5 || methods["_CFBundleCreateWithExecutableURLIfLooksLikeBundle"].References["strcmp"] != 1 || methods["_CFBundleCreateWithExecutableURLIfMightBeBundle"].References["CFDictionaryGetCount"] != 1 || methods["_CFBundleCopyBundleURLForExecutablePath"].References["_CFLengthAfterDeletingLastPathComponent"] != 4 {
			t.Fatal(target, methods)
		}
	}
}
