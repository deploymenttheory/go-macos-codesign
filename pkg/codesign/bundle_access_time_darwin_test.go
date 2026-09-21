package codesign

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestBundleExecutableReadAccessBounds(t *testing.T) {
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
	if _, err := b.readExecutable(b.executable, 1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("oversized executable: %v", err)
	}
	if after := stat(); after != before {
		t.Fatal("rejected read recorded access")
	}
	started := time.Now()
	if _, err := b.readExecutable(b.executable, maxFileSize); err != nil {
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
		t.Fatal("executable read changed unrelated metadata")
	}
}
