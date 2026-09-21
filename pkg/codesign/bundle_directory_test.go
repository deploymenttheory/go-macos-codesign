package codesign

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBundleDirectoryHeldRoot(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if err := os.Chmod(app, 0750); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(t.TempDir(), "Moved.app")
	if err := os.Rename(app, moved); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		moved = app // Windows may refuse to move a held directory.
	} else {
		if err := os.MkdirAll(filepath.Join(app, "Contents"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.createSignatureDirectory(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(moved, "Contents/_CodeSignature")
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0750 {
		t.Fatal("wrong root metadata", info.Mode())
	}
	if moved != app {
		if _, err := os.Stat(filepath.Join(app, "Contents/_CodeSignature")); !os.IsNotExist(err) {
			t.Fatal("created in decoy", err)
		}
	}
	if err := os.Chmod(dir, 0711); err != nil {
		t.Fatal(err)
	}
	if err := b.createSignatureDirectory(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0711 {
		t.Fatal("changed existing metadata", info.Mode())
	}
}

type cancelDirectoryMetadata struct {
	context.Context
	checks int
}

func (c *cancelDirectoryMetadata) Err() error {
	c.checks++
	if c.checks == 2 {
		return context.Canceled
	}
	return nil
}

func TestBundleDirectoryCancellationAndClosedRoot(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.createSignatureDirectory(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	name := b.base + "_CodeSignature"
	if _, err := b.root.Stat(name); !os.IsNotExist(err) {
		t.Fatal("created on cancelled context", err)
	}
	// Cancellation after mkdir retains an empty directory, without committing
	// any envelope or executable. That is not a whole-tree rollback contract.
	if err := b.createSignatureDirectory(&cancelDirectoryMetadata{Context: context.Background()}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(app, name))
	if err != nil || len(entries) != 0 {
		t.Fatal("unexpected directory contents", entries, err)
	}
	if err := b.root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.createSignatureDirectory(context.Background()); err == nil {
		t.Fatal("accepted closed root")
	}
}
