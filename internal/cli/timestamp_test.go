package cli

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTimestampCommands(t *testing.T) {
	path := "../../testdata/timestamps/apple-rsa-arm64"
	cert := "../../testdata/identities/rsa-cert.pem"
	der, err := os.ReadFile("../../testdata/chains/developer-id-2")
	if err != nil {
		t.Fatal(err)
	}
	root := write(t, "root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	bad := write(t, "bad.pem", []byte("bad"))
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tc := range []struct {
		args   []string
		status int
	}{
		{[]string{"--verify", "--trust", cert, "--timestamp-root", root, path}, 0},
		{[]string{"--verify", "--trust", cert, path}, 1},
		{[]string{"--verify", "--trust", cert, "--timestamp-root", cert, path}, 1},
		{[]string{"--verify", "--timestamp-root", bad, path}, 1},
		{[]string{"--verify", "--timestamp-root", missing, path}, 1},
		{[]string{"-s", "-", "--timestamp-root", root, path}, 2},
	} {
		_, stderr, code := invoke(t, tc.args...)
		if code != tc.status {
			t.Fatalf("%v: %d %s", tc.args, code, stderr)
		}
	}
	_, stderr, code := invoke(t, "-dvv", path)
	if code != 0 || !strings.Contains(stderr, "Timestamp=") || strings.Contains(stderr, "Signed Time=") {
		t.Fatal(code, stderr)
	}
	stdout, stderr, code := invoke(t, "-d", "--json", path)
	if code != 0 || !strings.Contains(stdout, `"Timestamp":`) || !strings.Contains(stdout, `"Valid":false`) {
		t.Fatal(code, stdout, stderr)
	}
}
