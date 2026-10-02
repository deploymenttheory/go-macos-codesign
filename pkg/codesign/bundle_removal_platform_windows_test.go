package codesign

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRemovalPlatformWindowsRights(t *testing.T) {
	for name, right := range map[string]uint32{"acl": windows.READ_CONTROL, "ea": windows.FILE_READ_EA, "data": windows.FILE_READ_DATA} {
		t.Run(name, func(t *testing.T) {
			app := testBundle(t)
			const plist = "Contents/Info-macos.plist"
			bundleFile(t, app, plist, []byte("<plist><dict><key>CFBundleExecutable</key><string>platform</string></dict></plist>"))
			bundleFile(t, app, "Contents/MacOS/platform", []byte("platform"))
			path := filepath.Join(app, plist)
			before := readTestFile(t, path)
			restore := denyResourceRight(t, path, right)
			if file, err := os.Open(path); err == nil {
				file.Close()
				t.Fatal("generic-read denial ineffective")
			} else if !errors.Is(err, os.ErrPermission) {
				t.Fatal(err)
			}
			bundle, err := openBundleVersion(app, "", true)
			if err != nil {
				t.Fatal(err)
			}
			defer bundle.close()
			want := "Contents/MacOS/platform"
			if name == "data" {
				want = "Contents/MacOS/hello"
			}
			if bundle.executable != want {
				t.Fatal("wrong permission-boundary selection", bundle.executable, want)
			}
			restore()
			if string(readTestFile(t, path)) != string(before) {
				t.Fatal("metadata acquisition changed bytes")
			}
		})
	}
}
