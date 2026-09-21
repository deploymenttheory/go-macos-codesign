package codesign

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestBundleReadPreservesAccessUntilAllocation(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	path := filepath.Join(app, b.executable)
	if err := os.Chtimes(path, time.Unix(978307200, 234567890), time.Unix(946684800, 123456789)); err != nil {
		t.Fatal(err)
	}
	stat := func() syscall.Stat_t {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return *info.Sys().(*syscall.Stat_t)
	}
	before := stat()
	if _, err := b.read(b.executable, 1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("oversized executable: %v", err)
	}
	if after := stat(); after != before {
		t.Fatal("rejected read recorded access")
	}
	if _, err := b.read(b.executable, maxFileSize); err != nil {
		t.Fatal(err)
	}
	if after := stat(); after != before {
		t.Fatal("planning read recorded allocation access")
	}
	started := time.Now()
	if _, err := prepareBundleExecutable(context.Background(), bundleWrite{name: b.executable, bundle: b}, true); err != nil {
		t.Fatal(err)
	}
	finished := time.Now()
	after := stat()
	access := time.Unix(after.Atimespec.Sec, after.Atimespec.Nsec)
	if access.Before(started) || access.After(finished) {
		t.Fatalf("read access %v outside [%v, %v]", access, started, finished)
	}
	before.Atimespec = after.Atimespec
	if before != after {
		t.Fatal("allocation access changed unrelated metadata")
	}
	assertNoBundleStaging(t, app)
}

type cancelAfterBundleReplacement struct {
	context.Context
	path     string
	original os.FileInfo
}

func (c cancelAfterBundleReplacement) Err() error {
	current, err := os.Stat(c.path)
	if err == nil && !os.SameFile(c.original, current) {
		return context.Canceled
	}
	return nil
}

func TestBundleCleanupCancellationPreservesCopiedAccess(t *testing.T) {
	app := testBundle(t)
	path := filepath.Join(app, "Contents/MacOS/hello")
	neighbour := filepath.Join(t.TempDir(), "neighbour")
	if err := os.Link(path, neighbour); err != nil {
		t.Fatal(err)
	}
	bundleFile(t, app, "Contents/_CodeSignature/stale", []byte("retain"))
	if err := os.Chtimes(path, time.Unix(978307200, 234567890), time.Unix(946684800, 123456789)); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := cancelAfterBundleReplacement{context.Background(), path, before}
	if err := Sign(ctx, app, SignOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(neighbour)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) || !os.SameFile(before, other) {
		t.Fatal("unexpected cancellation commit boundary")
	}
	if after.Sys().(*syscall.Stat_t).Atimespec != other.Sys().(*syscall.Stat_t).Atimespec {
		t.Fatal("cancelled cleanup refreshed replacement access")
	}
	if string(readTestFile(t, filepath.Join(app, "Contents/_CodeSignature/stale"))) != "retain" {
		t.Fatal("cancelled cleanup removed a signature file")
	}
	assertNoBundleStaging(t, app)
}
