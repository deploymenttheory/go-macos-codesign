package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBundleStaleFilesStillFailVerification(t *testing.T) {
	app := testBundle(t)
	ctx := context.Background()
	if err := Sign(ctx, app, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	stale := "Contents/_CodeSignature/obsolete"
	bundleFile(t, app, stale, []byte("stale signature"))
	if _, err := Verify(ctx, app, VerifyOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("verification accepted an unexpected signature file", err)
	}
	if err := Sign(ctx, app, SignOptions{}); !errors.Is(err, ErrSigned) {
		t.Fatal("signing without force accepted an existing signature", err)
	}
	if got := readTestFile(t, filepath.Join(app, stale)); string(got) != "stale signature" {
		t.Fatal("failed signature construction purged metadata")
	}
	if err := Sign(ctx, app, SignOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, app, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestBundleStaleFilesRejectWriteAliases(t *testing.T) {
	for _, name := range []string{"Contents/MacOS/hello", bundleResourcesPath} {
		for _, stale := range []string{"obsolete", "directory/alias"} {
			t.Run(name+"/"+stale, func(t *testing.T) {
				app := testBundle(t)
				bundleFile(t, app, bundleResourcesPath, []byte("old envelope"))
				path := filepath.Join(app, name)
				before := readTestFile(t, path)
				neighbour := filepath.Join(t.TempDir(), "neighbour")
				if err := os.WriteFile(neighbour, before, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				for _, dst := range []string{path, filepath.Join(app, "Contents/_CodeSignature", stale)} {
					if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.Link(neighbour, dst); err != nil {
						t.Fatal(err)
					}
				}
				if err := Sign(context.Background(), app, SignOptions{}); !errors.Is(err, ErrUnsupported) {
					t.Fatal("internal write alias accepted", err)
				}
				if !bytes.Equal(readTestFile(t, path), before) || !bytes.Equal(readTestFile(t, neighbour), before) {
					t.Fatal("rejected signature changed a linked file")
				}
				assertNoBundleStaging(t, app)
			})
		}
	}
}

func TestBundleCleanupFailureAfterExecutableCommit(t *testing.T) {
	app, later := testBundle(t), testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	other, err := openAppBundle(later)
	if err != nil {
		t.Fatal(err)
	}
	defer other.close()
	laterBefore := readTestFile(t, filepath.Join(later, other.executable))
	// An unsupported entry at flush time must not be removed or traversed.
	// Earlier commits survive; later prepared executables are only cleaned up.
	bundleFile(t, app, "Contents/_CodeSignature/directory/keep", []byte("retained"))
	writes := []bundleWrite{
		{name: b.resourcesPath(), data: []byte("envelope committed first"), bundle: b, kind: bundleResourceWrite},
		{name: b.executable, data: []byte("executable committed second"), bundle: b, cleanup: bundleCleanupKeepResources},
		{name: other.executable, data: []byte("not committed"), bundle: other},
	}
	if err := commitBundleWrites(context.Background(), writes); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if string(readTestFile(t, filepath.Join(app, b.executable))) != "executable committed second" || string(readTestFile(t, filepath.Join(app, b.resourcesPath()))) != "envelope committed first" {
		t.Fatal("earlier commits changed on flush failure")
	}
	if !bytes.Equal(readTestFile(t, filepath.Join(later, other.executable)), laterBefore) {
		t.Fatal("later executable committed after flush failure")
	}
	if string(readTestFile(t, filepath.Join(app, "Contents/_CodeSignature/directory/keep"))) != "retained" {
		t.Fatal("traversed an unsupported directory")
	}
	assertNoBundleStaging(t, app)
	assertNoBundleStaging(t, later)
}

func TestBundleCleanupRootAndCancellation(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if err := b.purgeSignatureFiles(context.Background(), false); err != nil {
		t.Fatal("absent directory", err)
	}
	bundleFile(t, app, "Contents/_CodeSignature/obsolete", []byte("retained"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.purgeSignatureFiles(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// The first Err check passes; cancellation while scanning must still preserve
	// the unvisited entry and leave the opened metadata root closed on return.
	if err := b.purgeSignatureFiles(&cancelBeforeRename{Context: context.Background()}, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if string(readTestFile(t, filepath.Join(app, "Contents/_CodeSignature/obsolete"))) != "retained" {
		t.Fatal("cancelled purge deleted stale file")
	}
	if err := b.root.Rename("Contents/_CodeSignature", "Contents/saved"); err != nil {
		t.Fatal(err)
	}
	bundleFile(t, app, "Contents/_CodeSignature", []byte("not a directory"))
	if err := b.purgeSignatureFiles(context.Background(), false); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err := b.root.Remove("Contents/_CodeSignature"); err != nil {
		t.Fatal(err)
	}
	if err := b.root.Symlink("saved", "Contents/_CodeSignature"); err != nil {
		t.Fatal(err)
	}
	if err := b.purgeSignatureFiles(context.Background(), false); !errors.Is(err, ErrUnsupported) {
		t.Fatal("followed a replacement signature-directory symlink", err)
	}
	if string(readTestFile(t, filepath.Join(app, "Contents/saved/obsolete"))) != "retained" {
		t.Fatal("purge followed a symlink")
	}
	b.root.Close()
	if err := b.purgeSignatureFiles(context.Background(), false); err == nil {
		t.Fatal("closed root accepted")
	}
}

// Even a changed CodeResources discovered at flush time must never be followed
// or removed as a directory. Signing scans already reject these write targets;
// removal defers rejection until the post-commit purge.
func TestBundleCleanupRejectsChangedEnvelope(t *testing.T) {
	for _, kind := range []string{"directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			app := testBundle(t)
			bundleFile(t, app, "Contents/_CodeSignature/stale", []byte("retain"))
			path := filepath.Join(app, bundleResourcesPath)
			if kind == "directory" {
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink("stale", path); err != nil {
				t.Fatal(err)
			}
			b, err := openAppBundle(app)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			if err := b.purgeSignatureFiles(context.Background(), false); !errors.Is(err, ErrUnsupported) {
				t.Fatal("changed envelope accepted", err)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("changed envelope removed", err)
			}
			if string(readTestFile(t, filepath.Join(app, "Contents/_CodeSignature/stale"))) != "retain" {
				t.Fatal("purge followed changed envelope")
			}
		})
	}
}

func TestBundleCleanupEntryLimit(t *testing.T) {
	app := testBundle(t)
	meta := filepath.Join(app, "Contents/_CodeSignature")
	for i := 0; i <= maxBundleEntries; i++ {
		bundleFile(t, app, fmt.Sprintf("Contents/_CodeSignature/stale-%d", i), nil)
	}
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if err := b.purgeSignatureFiles(context.Background(), false); !errors.Is(err, ErrUnsupported) {
		t.Fatal("oversized purge accepted", err)
	}
	entries, err := os.ReadDir(meta)
	if err != nil || len(entries) != maxBundleEntries+1 {
		t.Fatalf("entry limit must precede unlinks: %d: %v", len(entries), err)
	}
}

type cancelAfterSignatureUnlink struct {
	context.Context
	path string
}

func (c cancelAfterSignatureUnlink) Err() error {
	if _, err := os.Lstat(c.path); errors.Is(err, os.ErrNotExist) {
		return context.Canceled
	}
	return nil
}

func TestBundleCleanupCancellationAfterUnlink(t *testing.T) {
	app := testBundle(t)
	for _, name := range []string{"n23", "CodeResources", "CodeDirectory"} {
		bundleFile(t, app, "Contents/_CodeSignature/"+name, []byte(name))
	}
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	ctx := cancelAfterSignatureUnlink{context.Background(), filepath.Join(app, "Contents/_CodeSignature/n23")}
	if err := b.purgeSignatureFiles(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, name := range []string{"CodeResources", "CodeDirectory"} {
		if string(readTestFile(t, filepath.Join(app, "Contents/_CodeSignature", name))) != name {
			t.Fatal("cancellation removed a later component", name)
		}
	}
}
