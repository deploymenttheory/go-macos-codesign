// Acceptance tests execute the compiled CLI and independent Apple tools.
// No production package invokes a subprocess.
package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var binaryPath, root string

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	root = filepath.Dir(wd)
	tmp, err := os.MkdirTemp("", "macoscodesign-acceptance-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(tmp, "macoscodesign")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}
	args := []string{"build", "-o", binaryPath}
	if dir := os.Getenv("MACOSCODESIGN_COVERAGE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		args = append(args, "-cover", "-covermode=atomic", "-coverpkg=github.com/deploymenttheory/go-macos-codesign/...")
	}
	args = append(args, "./cmd/macoscodesign")
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.RemoveAll(tmp)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

func run(t *testing.T, exe string, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	env := []string{}
	for _, s := range os.Environ() {
		if !strings.HasPrefix(s, "MACOSCODESIGN_") && !strings.HasPrefix(s, "GOCOVERDIR=") {
			env = append(env, s)
		}
	}
	cmd.Env = append(env, "LC_ALL=C", "TZ=UTC")
	if exe == binaryPath && os.Getenv("MACOSCODESIGN_COVERAGE_DIR") != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+os.Getenv("MACOSCODESIGN_COVERAGE_DIR"))
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("command timeout", args)
	}
	if err != nil {
		var e *exec.ExitError
		if !errors.As(err, &e) {
			t.Fatal(err)
		}
		return stdout.String(), stderr.String(), e.ExitCode()
	}
	return stdout.String(), stderr.String(), 0
}

func copyFixture(t *testing.T, name, dst string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "testdata", "macho", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0755); err != nil {
		t.Fatal(err)
	}
}
func mustRun(t *testing.T, exe string, args ...string) {
	t.Helper()
	out, err, code := run(t, exe, args...)
	if code != 0 {
		t.Fatalf("%s %q exited %d\n%s\n%s", exe, args, code, out, err)
	}
}
func apple(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "darwin" {
		if os.Getenv("MACOSCODESIGN_REQUIRE_APPLE") == "1" {
			t.Fatal("Apple acceptance is required on a non-macOS runner")
		}
		t.Skip("Apple reference runs on macOS")
	}
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Fatal(err)
	}
	return "/usr/bin/codesign"
}

func attest(t *testing.T, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("ATTEST", string(data))
	if dir := os.Getenv("MACOSCODESIGN_EVIDENCE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		name := strings.NewReplacer("/", "_", "\\", "_").Replace(t.Name())
		if err := os.WriteFile(filepath.Join(dir, name+".json"), append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
