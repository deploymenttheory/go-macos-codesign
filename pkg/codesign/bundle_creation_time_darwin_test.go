package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestBundleCreationTimeFailurePreservesSource(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	path := filepath.Join(app, b.executable)
	data := readTestFile(t, path)
	if out, err := exec.Command("/bin/chmod", "+a", "everyone deny writeattr", path).CombinedOutput(); err != nil {
		t.Fatalf("ACL: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	writes := []bundleWrite{
		{name: b.resourcesPath(), data: []byte("new resource envelope"), bundle: b, kind: bundleResourceWrite},
		{name: b.executable, data: []byte("new executable"), bundle: b},
	}
	if err := commitBundleWrites(context.Background(), writes); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("creation metadata denial: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Sys().(*syscall.Stat_t).Birthtimespec != after.Sys().(*syscall.Stat_t).Birthtimespec || !bytes.Equal(readTestFile(t, path), data) {
		t.Fatal("failed preparation changed the source")
	}
	if _, err := b.root.Stat(b.base + "_CodeSignature"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("envelope committed before metadata preparation: %v", err)
	}
	assertNoBundleStaging(t, app)
}

func TestBundleCreationTimeCancellation(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	path := filepath.Join(app, b.executable)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data := readTestFile(t, path)
	ctx := &cancelBeforeRename{Context: context.Background()}
	if err := b.write(ctx, b.executable, []byte("uncommitted"), false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Sys().(*syscall.Stat_t).Birthtimespec != after.Sys().(*syscall.Stat_t).Birthtimespec || !bytes.Equal(readTestFile(t, path), data) {
		t.Fatal("cancelled write changed the source")
	}
	assertNoBundleStaging(t, app)
}
