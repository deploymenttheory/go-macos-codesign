package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// Content-only resources must remain sealable when unrelated metadata reads are
// denied. Strict metadata policy is still independent and may require those reads.
func TestResourceContentWindowsRights(t *testing.T) {
	for name, mask := range map[string]uint32{"acl": windows.READ_CONTROL, "ea": windows.FILE_READ_EA, "data": windows.FILE_READ_DATA} {
		t.Run(name, func(t *testing.T) {
			app := testBundle(t)
			const resource = "Contents/Resources/data"
			bundleFile(t, app, resource, []byte("resource contents"))
			path := filepath.Join(app, filepath.FromSlash(resource))
			original := readTestFile(t, path)
			before := readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))
			restore := denyResourceRight(t, path, mask)
			if f, err := os.Open(path); err == nil {
				f.Close()
				t.Fatal("generic-read denial ineffective")
			} else if !errors.Is(err, os.ErrPermission) {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(app)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			f, err := openResourceFile(root, resource)
			if name == "data" {
				if err == nil {
					f.Close()
					t.Fatal("data denial bypassed")
				}
				if !errors.Is(err, os.ErrPermission) {
					t.Fatal(err)
				}
			} else {
				if err != nil {
					t.Fatal("content acquisition requested unrelated rights", err)
				}
				data, err := io.ReadAll(f)
				if err != nil || !bytes.Equal(data, original) {
					t.Fatal("wrong contents", err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err = Sign(context.Background(), app, SignOptions{NoStrict: true})
			if name == "data" {
				if !errors.Is(err, os.ErrPermission) {
					t.Fatal("signing lost actual read denial", err)
				}
			} else if err != nil {
				t.Fatal("content-only signing failed", err)
			}
			restore()
			if !bytes.Equal(original, readTestFile(t, path)) {
				t.Fatal("resource mutated")
			}
			if name == "data" {
				if !bytes.Equal(before, readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))) {
					t.Fatal("read failure committed executable")
				}
			} else if _, err := Verify(context.Background(), app, VerifyOptions{}); err != nil {
				t.Fatal("resource seal invalid", err)
			}
		})
	}
}

func denyResourceRight(t *testing.T, path string, mask uint32) func() {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	saved, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	original, _, err := saved.DACL()
	if err != nil {
		t.Fatal(err)
	}
	principal := "WD"
	// OWNER RIGHTS suppresses the owner's implicit READ_CONTROL grant.
	if mask == windows.READ_CONTROL {
		principal = "OW"
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(D;;0x%x;;;%s)(A;;FA;;;WD)", mask, principal))
	if err != nil {
		t.Fatal(err)
	}
	denied, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, denied, nil); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, original, nil); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(restore)
	return restore
}
