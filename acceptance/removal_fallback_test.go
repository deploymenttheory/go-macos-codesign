package acceptance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Every fallback leaves a non-selected executable untouched (or absent) and
// uses the real Info.plist as the generic signature carrier. The generic matrix
// compares complete tree bytes, attributes and inode identity with Apple and
// exports every AppleDouble result for macOS verification of both foreign hosts.
func fallbackFixture(t *testing.T, dir, scenario string) (string, string, bool) {
	t.Helper()
	shape := "app"
	if scenario == "framework" || scenario == "flat-framework" {
		shape = scenario
	}
	operand, paths := sidebandBundleFixture(t, dir, shape)
	info := nativeRead(t, paths["info"])
	s := string(info)
	switch scenario {
	case "missing-key", "empty-key", "bad-key":
		// These generated fixtures use the name hello for Contents apps.
		old := "<key>CFBundleExecutable</key><string>hello</string>"
		if !strings.Contains(s, old) {
			t.Fatal("unexpected fixture executable metadata", s)
		}
		replacement := ""
		if scenario == "empty-key" {
			replacement = "<key>CFBundleExecutable</key><string></string>"
		}
		if scenario == "bad-key" {
			replacement = "<key>CFBundleExecutable</key><integer>1</integer>"
		}
		s = strings.ReplaceAll(s, old, replacement)
	case "historical-directory":
		destination := filepath.Join(operand, "Contents/Mac OS X/hello")
		if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(paths["main"], destination); err != nil {
			t.Fatal(err)
		}
	default:
		if err := os.Remove(paths["main"]); err != nil {
			t.Fatal(err)
		}
		if scenario == "installer" {
			s = strings.ReplaceAll(s, "</dict>", "<key>IFMajorVersion</key><integer>1</integer></dict>")
		}
	}
	if err := os.WriteFile(paths["info"], []byte(s), 0644); err != nil {
		t.Fatal(err)
	}
	return operand, paths["info"], true
}

func TestRemovalFallbackMetadataDenial(t *testing.T) {
	dir := extractionDirectory(t)
	operand, paths := sidebandBundleFixture(t, dir, "app")
	metadata := genericMetadata("populated")
	setSidebandObject(t, paths["info"], metadata)
	initialAttrs := genericAttrs(t, paths["info"], metadata, "")
	before := nativeRead(t, paths["main"])
	infoBefore := nativeRead(t, paths["info"])
	mainIdentity, infoIdentity := accessFileInfo(t, paths["main"]), accessFileInfo(t, paths["info"])
	var restore func()
	t.Cleanup(func() {
		if restore != nil {
			restore()
		}
	})
	switch runtime.GOOS {
	case "darwin":
		mustRun(t, "/bin/chmod", "+a", "everyone deny readattr", paths["main"])
		restore = func() { mustRun(t, "/bin/chmod", "-N", paths["main"]) }
	case "windows":
		// NTFS also grants child-attribute visibility through directory listing.
		// Deny both sources, without inheriting the directory ACE onto the file.
		parent := filepath.Dir(paths["main"])
		restore = func() {
			mustRun(t, "icacls", parent, "/remove:d", "*S-1-1-0")
			mustRun(t, "icacls", paths["main"], "/remove:d", "*S-1-1-0")
		}
		mustRun(t, "icacls", paths["main"], "/deny", "*S-1-1-0:(RA)")
		mustRun(t, "icacls", parent, "/deny", "*S-1-1-0:(RD)")
	case "linux":
		parent := filepath.Dir(paths["main"])
		mode := accessFileInfo(t, parent).Mode().Perm()
		if err := os.Chmod(parent, 0000); err != nil {
			t.Fatal(err)
		}
		restore = func() {
			if err := os.Chmod(parent, mode); err != nil {
				t.Fatal(err)
			}
		}
	default:
		t.Fatal("unqualified host")
	}
	r, err := os.OpenRoot(operand)
	if err != nil {
		t.Fatal(err)
	}
	_, err = hostdata.StatMetadata(r, "Contents/MacOS/hello")
	r.Close()
	if !os.IsPermission(err) {
		t.Fatal("metadata denial is ineffective", err)
	}
	mustRun(t, binaryPath, "--remove-signature", operand)
	restore()
	nativeEqual(t, "unselected executable", nativeRead(t, paths["main"]), before)
	nativeEqual(t, "plist data", nativeRead(t, paths["info"]), infoBefore)
	if !os.SameFile(mainIdentity, accessFileInfo(t, paths["main"])) || !os.SameFile(infoIdentity, accessFileInfo(t, paths["info"])) {
		t.Fatal("file identity changed")
	}
	assertNativeGenericRemoval(t, genericAttrs(t, paths["info"], metadata, ""), initialAttrs)
	if _, err := os.Stat(paths["signature"]); !os.IsNotExist(err) {
		t.Fatal("envelope retained", err)
	}
	attest(t, map[string]any{"effective_metadata_denial": true, "fallback_removed": true, "unselected_executable": hash(before), "info": hash(infoBefore)})
}
