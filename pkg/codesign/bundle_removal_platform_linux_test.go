package codesign

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRemovalPlatformLinuxDataDenial(t *testing.T) {
	app := testBundle(t)
	const plist = "Contents/Info-macos.plist"
	bundleFile(t, app, plist, []byte("<plist><dict><key>CFBundleExecutable</key><string>platform</string></dict></plist>"))
	bundleFile(t, app, "Contents/MacOS/platform", []byte("platform"))
	path := filepath.Join(app, plist)
	before := readTestFile(t, path)
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })
	if file, err := os.Open(path); err == nil {
		file.Close()
		t.Fatal("data denial ineffective; run as a non-root user")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	bundle, err := openBundleVersion(app, "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.close()
	if bundle.executable != "Contents/MacOS/hello" || bundle.infoPath != "Contents/Info.plist" {
		t.Fatal("read denial did not select ordinary metadata", bundle.executable, bundle.infoPath)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if string(readTestFile(t, path)) != string(before) {
		t.Fatal("metadata acquisition changed bytes")
	}
}
