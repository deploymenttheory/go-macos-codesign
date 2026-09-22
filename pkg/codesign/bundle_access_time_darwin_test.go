package codesign

import (
	"context"
	"errors"
	"os"
	"os/exec"
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

func TestBundlePreparationDefersSourceAccess(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	path := filepath.Join(app, b.executable)
	if err := os.Chtimes(path, time.Unix(978307200, 234567891), time.Unix(946684800, 123456789)); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := prepareBundleExecutable(context.Background(), bundleWrite{name: b.executable, data: []byte("staged"), bundle: b}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.replacement.Close()
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if *before.Sys().(*syscall.Stat_t) != *after.Sys().(*syscall.Stat_t) {
		t.Fatal("private preparation changed source metadata")
	}
	started := time.Now()
	if err := p.copySourceAccess(); err != nil {
		t.Fatal(err)
	}
	finished := time.Now()
	after, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := b.root.Stat(p.replacement.Path)
	if err != nil {
		t.Fatal(err)
	}
	sourceAt := after.Sys().(*syscall.Stat_t).Atimespec
	access := time.Unix(sourceAt.Sec, sourceAt.Nsec)
	if access.Before(started) || access.After(finished) || stage.Sys().(*syscall.Stat_t).Atimespec != sourceAt {
		t.Fatal("staged access did not copy the deferred source read exactly")
	}
	old, got := *before.Sys().(*syscall.Stat_t), *after.Sys().(*syscall.Stat_t)
	old.Atimespec = got.Atimespec
	if old != got {
		t.Fatal("deferred read changed unrelated source metadata")
	}
	oldStage, newStage := *p.staged.Sys().(*syscall.Stat_t), *stage.Sys().(*syscall.Stat_t)
	oldStage.Atimespec, oldStage.Ctimespec = newStage.Atimespec, newStage.Ctimespec
	if oldStage != newStage {
		t.Fatal("access copy changed unrelated staged metadata")
	}
}

func TestBundleAccessCopyFailurePreservesExecutable(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	before := readTestFile(t, filepath.Join(app, b.executable))
	p, err := prepareBundleExecutable(context.Background(), bundleWrite{name: b.executable, data: []byte("uncommitted"), bundle: b}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.replacement.Close()
	stage := filepath.Join(app, p.replacement.Path)
	if out, err := exec.Command("/bin/chmod", "+a", "everyone deny writeattr", stage).CombinedOutput(); err != nil {
		t.Fatalf("ACL: %v: %s", err, out)
	}
	defer func() { _ = exec.Command("/bin/chmod", "-N", stage).Run() }()
	if err := p.commit(context.Background()); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("access copy denial: %v", err)
	}
	after, err := b.root.Stat(b.executable)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(p.original, after) || string(readTestFile(t, filepath.Join(app, b.executable))) != string(before) {
		t.Fatal("failed access copy replaced executable")
	}
}
