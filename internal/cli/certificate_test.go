package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCertificateCommands(t *testing.T) {
	cert := filepath.Join("../../testdata/identities", "rsa-cert.pem")
	key := filepath.Join("../../testdata/identities", "rsa-key.pem")
	bad := write(t, "bad.pem", []byte("not PEM"))
	missing := filepath.Join(t.TempDir(), "missing.pem")
	path := file(t, "unsigned-universal")
	for _, args := range [][]string{
		{"-s", cert, "--key", key, "-i", "org.example.certificate", path},
		{"--verify", "--trust", cert, path},
		{"-dvvvv", path},
	} {
		_, stderr, code := invoke(t, args...)
		if code != 0 {
			t.Fatalf("%q: %d %s", args, code, stderr)
		}
	}
	for _, tc := range []struct {
		args   []string
		status int
	}{
		{[]string{"--verify", path}, 1},
		{[]string{"--verify", "--trust", "../../testdata/identities/p256-cert.pem", path}, 1},
		{[]string{"--verify", "--trust", missing, path}, 1},
		{[]string{"--verify", "--trust", bad, path}, 1},
		{[]string{"-s", cert, "--key", missing, path}, 1},
		{[]string{"-s", cert, "--key", bad, path}, 1},
		{[]string{"-s", "-", "--key", key, path}, 2},
		{[]string{"--verify", "--key", key, path}, 2},
		{[]string{"-s", cert, "--trust", cert, path}, 2},
	} {
		_, stderr, code := invoke(t, tc.args...)
		if code != tc.status {
			t.Fatalf("%q: %d %s", tc.args, code, stderr)
		}
	}
	_, stderr, code := invoke(t, "-dvvvv", path)
	if code != 0 || !strings.Contains(stderr, "Signature size=") || strings.Contains(stderr, "Signature=adhoc") {
		t.Fatal(code, stderr)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, code := invoke(t, "-fs", cert, "--key", bad, path); code != 1 {
		t.Fatal(code)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed identity import changed target")
	}
}
