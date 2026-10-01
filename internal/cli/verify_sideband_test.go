package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestAppleDoubleArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--appledouble"}, {"--appledouble="},
		{"--verify", "--appledouble", "metadata", "code"},
		{"--verify", "--strict=sideband", "--appledouble", "metadata"},
		{"--verify", "--strict=sideband", "--appledouble", "metadata", "a", "b"},
		{"--verify", "--strict=sideband", "--no-strict", "--appledouble", "metadata", "code"},
		{"--verify", "--strict=sideband", "--strict=none", "--appledouble", "metadata", "code"},
		{"-d", "--appledouble", "metadata", "code"},
	} {
		if _, err := parse(args); err == nil {
			t.Fatal("accepted ambiguous or unused carrier", args)
		}
	}
	for _, arg := range []string{"--strict", "--strict=sideband", "--strict=all", "--strict=512", "--strict=640"} {
		o, err := parse([]string{"--verify", arg, "--appledouble=metadata", "code"})
		if err != nil || o.appleDoublePath != "metadata" {
			t.Fatal(arg, o, err)
		}
	}
}

func TestAppleDoubleCLIDiagnostics(t *testing.T) {
	path := file(t, "adhoc-arm64")
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	metadata := appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}}
	data, err := metadata.Encode()
	if err != nil {
		t.Fatal(err)
	}
	carrier := write(t, "metadata", data)
	for _, verbose := range []bool{false, true} {
		for _, jsonMode := range []bool{false, true} {
			args := []string{"--verify", "--strict=sideband", "--appledouble", carrier, path}
			if verbose {
				args = append(args, "--verbose=1")
			}
			if jsonMode {
				args = append(args, "--json")
			}
			out, stderr, status := invoke(t, args...)
			wantErr := path + ": resource fork, Finder information, or similar detritus not allowed\n"
			wantOut := ""
			if verbose {
				message := "file with invalid attached data: Disallowed xattr com.apple.ResourceFork found on " + resolved + "\n"
				if jsonMode {
					wantErr += message
				} else {
					wantOut = message
				}
			}
			if status != 1 || stderr != wantErr {
				t.Fatal(status, out, stderr, wantErr)
			}
			if jsonMode {
				var report codesign.Report
				if err := json.Unmarshal([]byte(out), &report); err != nil || report.Valid {
					t.Fatal(out, err)
				}
			} else if out != wantOut {
				t.Fatal(out, wantOut)
			}
		}
	}
	for _, bad := range []string{filepath.Join(t.TempDir(), "absent"), t.TempDir(), write(t, "bad-metadata", []byte("malformed"))} {
		out, stderr, status := invoke(t, "--verify", "--strict=all", "--appledouble", bad, path)
		if status != 1 || out != "" || stderr == "" {
			t.Fatal(status, out, stderr)
		}
	}
	// A neighboring malformed carrier has no meaning unless explicitly supplied.
	neighbor := filepath.Join(filepath.Dir(path), "._"+filepath.Base(path))
	if err := os.WriteFile(neighbor, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, stderr, status := invoke(t, "--verify", "--strict=sideband", path); status != 0 || out != "" || stderr != "" {
		t.Fatal(status, out, stderr)
	}
	if out, _, status := invoke(t, "--help"); status != 0 || !strings.Contains(out, "--appledouble") {
		t.Fatal(out, status)
	}
}
