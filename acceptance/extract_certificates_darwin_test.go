package acceptance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCertificateExtractionPermission(t *testing.T) {
	dir := extractionDirectory(t)
	t.Chdir(dir)
	path, _ := certificateExtractionInput(t, dir, "arm64", "rsa")
	if err := os.WriteFile("cert0", []byte("preserve"), 0444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod("cert0", 0644) })
	want := "Executable=" + path + "\n" + path + ": Permission denied\n"
	for _, exe := range []string{binaryPath, apple(t)} {
		out, stderr, status := run(t, exe, "-d", "--extract-certificates=cert", path)
		if out != "" || stderr != want || status != 1 || string(nativeRead(t, "cert0")) != "preserve" {
			t.Fatal(exe, status, out, stderr)
		}
	}
	attest(t, map[string]any{"native_compared": true, "output_preserved": true, "exact_diagnostics": true})
}

func TestCertificateExtractionBundleAliasDifference(t *testing.T) {
	dir := extractionDirectory(t)
	t.Chdir(dir)
	if err := os.Mkdir("physical", 0755); err != nil {
		t.Fatal(err)
	}
	path, certs := certificateExtractionInput(t, filepath.Join(dir, "physical"), "app", "rsa")
	layoutLink(t, dir, "alias", "physical")
	operand := filepath.Join(dir, "alias", filepath.Base(path))
	wantGo := "Executable=" + filepath.Join(operand, "Contents/MacOS/hello") + "\n"
	wantNative := "Executable=" + filepath.Join(path, "Contents/MacOS/hello") + "\n"
	for i, exe := range []string{binaryPath, apple(t)} {
		out, stderr, status := run(t, exe, "-d", "--extract-certificates=cert", operand)
		want := wantGo
		if i == 1 {
			want = wantNative
		}
		if out != "" || status != 0 || stderr != want {
			t.Fatal(exe, status, out, stderr)
		}
		nativeEqual(t, "alias certificate", nativeRead(t, "cert0"), certs[0])
	}
	attest(t, map[string]any{"go_stderr": wantGo, "native_stderr": wantNative, "native_compared": true, "certificate_byte_equal": true, "remaining_bundle_parent_alias_difference": true})
}
