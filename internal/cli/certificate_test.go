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

func TestPKCS12AndRootCommands(t *testing.T) {
	password := write(t, "password", []byte("public-codesign-test-only\r\n"))
	bad := write(t, "bad", []byte("bad"))
	missing := filepath.Join(t.TempDir(), "missing")
	pfx := "../../testdata/pkcs12/rsa-modern.p12"
	cert := "../../testdata/identities/rsa-cert.pem"
	path := file(t, "unsigned-arm64")
	for _, args := range [][]string{{"-s", pfx, "--password-file", password, "-i", "pfx", path}, {"--verify", "--trust-root", cert, path}, {"-dvv", path}, {"-d", "--json", path}} {
		out, stderr, status := invoke(t, args...)
		if status != 0 {
			t.Fatal(args, status, stderr)
		}
		if args[0] == "-dvv" && (!strings.Contains(stderr, "Authority=Public codesign test identity rsa") || !strings.Contains(stderr, "Signed Time=")) {
			t.Fatal(stderr)
		}
		if args[0] == "-d" && !strings.Contains(out, "CertificateMetadata") {
			t.Fatal(out)
		}
	}
	for _, tc := range []struct {
		args   []string
		status int
	}{
		{[]string{"-fs", pfx, "--password-file", bad, path}, 1},
		{[]string{"-fs", pfx, "--password-file", missing, path}, 1},
		{[]string{"-fs", cert, "--password-file", password, path}, 1},
		{[]string{"-fs", pfx, "--key", cert, path}, 1},
		{[]string{"-fs", pfx, "--key", cert, "--password-file", password, path}, 2},
		{[]string{"--verify", "--password-file", password, path}, 2},
		{[]string{"-s", "-", "--trust-root", cert, path}, 2},
		{[]string{"--verify", "--trust-root", missing, path}, 1},
		{[]string{"--verify", "--trust-root", bad, path}, 1},
	} {
		_, stderr, status := invoke(t, tc.args...)
		if status != tc.status {
			t.Fatal(tc.args, status, stderr)
		}
	}
	if _, stderr, status := invoke(t, "-fs", "../../testdata/pkcs12/rsa-empty.p12", "-i", "empty", path); status != 0 {
		t.Fatal(stderr)
	}
}
