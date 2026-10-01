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

// A read-only reopen cannot SetFileTime or FlushFileBuffers on Windows. Keep
// the SDK's original writer until both finish, including when restored source
// attributes prohibit reopening the staged file for writing.
func TestBundleAccessTimeWindowsHeldWriter(t *testing.T) {
	for _, readonly := range []bool{false, true} {
		name := "writable"
		if readonly {
			name = "readonly"
		}
		t.Run(name, func(t *testing.T) {
			app := testBundle(t)
			b, err := openAppBundle(app)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			sourcePath := filepath.Join(app, b.executable)
			if err := os.Chtimes(sourcePath, time.Unix(1700000000, 123456700), time.Unix(1699990000, 765432100)); err != nil {
				t.Fatal(err)
			}
			if readonly {
				if err := os.Chmod(sourcePath, 0555); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(sourcePath, 0755)
			}
			p, err := prepareBundleExecutable(context.Background(), bundleWrite{name: b.executable, data: []byte("staged content"), bundle: b}, false)
			if err != nil {
				t.Fatal(err)
			}
			defer p.replacement.Close()
			before, err := p.replacement.File.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := p.copySourceAccess(); err != nil {
				t.Fatal(err)
			}
			if err := p.replacement.File.Close(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("writer must close before rename: %v", err)
			}
			source, err := b.root.Stat(b.executable)
			if err != nil {
				t.Fatal(err)
			}
			after, err := b.root.Stat(p.replacement.Path)
			if err != nil {
				t.Fatal(err)
			}
			old := before.Sys().(*syscall.Win32FileAttributeData)
			if gotReadonly := old.FileAttributes&syscall.FILE_ATTRIBUTE_READONLY != 0; gotReadonly != readonly {
				t.Fatalf("restored readonly attribute: got %v want %v", gotReadonly, readonly)
			}
			got := after.Sys().(*syscall.Win32FileAttributeData)
			want := source.Sys().(*syscall.Win32FileAttributeData)
			if got.LastAccessTime != want.LastAccessTime {
				t.Fatalf("access time: got %+v want %+v", got.LastAccessTime, want.LastAccessTime)
			}
			if got.CreationTime != old.CreationTime || got.LastWriteTime != old.LastWriteTime || got.FileAttributes != old.FileAttributes {
				t.Fatalf("unrelated staged metadata changed: before %+v after %+v", old, got)
			}
			if !os.SameFile(before, after) || !os.SameFile(p.original, source) {
				t.Fatal("metadata copy replaced an object")
			}
			if err := p.replacement.Close(); err != nil {
				t.Fatal(err)
			}
			assertNoBundleStaging(t, app)
		})
	}
}
