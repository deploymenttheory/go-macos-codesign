package codesign

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestStandaloneReadAccessBounds(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(map[bool]string{false: "executable", true: "oversized"}[oversized], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "executable")
			if err := os.WriteFile(path, fixture(t, "unsigned-arm64"), 0551); err != nil {
				t.Fatal(err)
			}
			if oversized {
				if err := os.Chmod(path, 0751); err != nil {
					t.Fatal(err)
				}
				if err := os.Truncate(path, maxFileSize+1); err != nil {
					t.Fatal(err)
				}
			}
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
			if !oversized {
				if _, err := readFile(path); err != nil {
					t.Fatal(err)
				}
				if stat() != before {
					t.Fatal("ordinary read changed metadata")
				}
			}
			started := time.Now()
			_, err := readFileWithAccess(path, true)
			finished := time.Now()
			after := stat()
			if oversized {
				if !errors.Is(err, ErrUnsupported) || after != before {
					t.Fatalf("oversized read changed metadata or returned wrong error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			access := time.Unix(after.Atimespec.Sec, after.Atimespec.Nsec)
			if access.Before(started) || access.After(finished) {
				t.Fatalf("read access %v outside [%v, %v]", access, started, finished)
			}
			before.Atimespec = after.Atimespec
			if before != after {
				t.Fatal("executable read changed unrelated metadata")
			}
		})
	}
}
