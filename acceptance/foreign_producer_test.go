package acceptance

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// CI validates the complete producer receipt and artifact hashes before native
// readback. Read its OS here instead of inferring path syntax from diagnostics.
func foreignProducerOS(t *testing.T, artifact string) string {
	t.Helper()
	var receipt struct {
		Schema     int `json:"schema"`
		Provenance struct {
			OS string `json:"os"`
		} `json:"provenance"`
	}
	directory := filepath.Dir(filepath.Dir(artifact))
	if err := json.Unmarshal(nativeRead(t, filepath.Join(directory, "producer.json")), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != 1 || (receipt.Provenance.OS != "Linux" && receipt.Provenance.OS != "Windows") {
		t.Fatal("invalid foreign producer receipt", directory)
	}
	return receipt.Provenance.OS
}

// Only the native subcomponent pathname changes syntax on Windows. Preserve
// every other byte, including diagnostic prose, line endings and quoted values.
func foreignBundleDiagnostic(native, host string) (string, error) {
	switch host {
	case "Linux":
		return native, nil
	case "Windows":
		lines := strings.Split(native, "\n")
		const prefix = "In subcomponent: $BUNDLE/"
		for i, line := range lines {
			if strings.HasPrefix(line, prefix) {
				lines[i] = "In subcomponent: $BUNDLE\\" + strings.ReplaceAll(strings.TrimPrefix(line, prefix), "/", "\\")
			}
		}
		return strings.Join(lines, "\n"), nil
	default:
		return "", fmt.Errorf("unsupported foreign producer OS %q", host)
	}
}

func TestForeignBundleDiagnostic(t *testing.T) {
	native := "$BUNDLE: code object is not signed at all\nIn subcomponent: $BUNDLE/Contents/MacOS/._hello\nopaque / value\n"
	windows := "$BUNDLE: code object is not signed at all\nIn subcomponent: $BUNDLE\\Contents\\MacOS\\._hello\nopaque / value\n"
	for _, host := range []string{"Linux", "Windows"} {
		t.Run(host, func(t *testing.T) {
			want := native
			if host == "Windows" {
				want = windows
			}
			got, err := foreignBundleDiagnostic(native, host)
			if err != nil || got != want {
				t.Fatalf("diagnostic = %q, %v; want %q", got, err, want)
			}
		})
	}
	if _, err := foreignBundleDiagnostic(native, "Darwin"); err == nil {
		t.Fatal("accepted a non-foreign producer")
	}
}
