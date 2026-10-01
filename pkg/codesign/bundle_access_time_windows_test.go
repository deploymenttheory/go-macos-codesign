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

// A read-only reopen cannot SetFileTime or FlushFileBuffers on Windows. Keep
// the SDK's original writer until both finish, including when restored source
// attributes prohibit reopening the staged file for writing.
func TestBundleAccessTimeWindowsHeldWriter(t *testing.T) {
	for _, name := range []string{"writable", "readonly", "deny-writeattr"} {
		t.Run(name, func(t *testing.T) {
			readonly := name == "readonly"
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
			if name == "deny-writeattr" {
				if out, err := exec.Command("icacls", sourcePath, "/deny", "*S-1-1-0:(WA)").CombinedOutput(); err != nil {
					t.Fatalf("deny attributes: %v: %s", err, out)
				}
				defer func() {
					if out, err := exec.Command("icacls", sourcePath, "/remove:d", "*S-1-1-0").CombinedOutput(); err != nil {
						t.Errorf("remove attribute denial: %v: %s", err, out)
					}
				}()
				if err := os.Chtimes(sourcePath, time.Now(), time.Now()); !errors.Is(err, os.ErrPermission) {
					t.Fatalf("source attribute denial ineffective: %v", err)
				}
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
			if old.FileAttributes&syscall.FILE_ATTRIBUTE_READONLY != 0 {
				t.Fatal("private staging must remain writable before final restoration")
			}
			got := after.Sys().(*syscall.Win32FileAttributeData)
			want := source.Sys().(*syscall.Win32FileAttributeData)
			if got.LastAccessTime != want.LastAccessTime {
				t.Fatalf("access time: got %+v want %+v", got.LastAccessTime, want.LastAccessTime)
			}
			if gotReadonly := got.FileAttributes&syscall.FILE_ATTRIBUTE_READONLY != 0; gotReadonly != readonly {
				t.Fatalf("restored readonly attribute: got %v want %v", gotReadonly, readonly)
			}
			if got.CreationTime != want.CreationTime || got.LastWriteTime != old.LastWriteTime || got.FileAttributes != want.FileAttributes {
				t.Fatalf("unrelated staged metadata changed: before %+v after %+v", old, got)
			}
			if !os.SameFile(before, after) || !os.SameFile(p.original, source) {
				t.Fatal("metadata copy replaced an object")
			}
			if name == "deny-writeattr" {
				if err := os.Chtimes(filepath.Join(app, p.replacement.Path), time.Now(), time.Now()); !errors.Is(err, os.ErrPermission) {
					t.Fatalf("replacement lost attribute denial: %v", err)
				}
				// Final restoration has closed both handles. Exercise the same
				// rename used by commit, with source and replacement ACLs intact.
				if err := b.root.Rename(p.replacement.Path, b.executable); err != nil {
					t.Fatal(err)
				}
				if string(readTestFile(t, sourcePath)) != "staged content" {
					t.Fatal("attribute-denied replacement was not committed")
				}
				if err := os.Chtimes(sourcePath, time.Now(), time.Now()); !errors.Is(err, os.ErrPermission) {
					t.Fatalf("committed replacement lost attribute denial: %v", err)
				}
			}
			if err := p.replacement.Close(); err != nil {
				t.Fatal(err)
			}
			assertNoBundleStaging(t, app)
		})
	}
}
