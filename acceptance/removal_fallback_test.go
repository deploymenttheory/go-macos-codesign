package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
