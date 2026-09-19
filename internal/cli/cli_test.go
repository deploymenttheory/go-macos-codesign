package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func invoke(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	t.Setenv("MACOSCODESIGN_CONFIG", "")
	var out, err bytes.Buffer
	code := Run(context.Background(), args, strings.NewReader(""), &out, &err)
	return out.String(), err.String(), code
}
func file(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "macho", name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hello")
	if err := os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
	return path
}
func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestArgumentParser(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		op      string
		verbose int
	}{
		{[]string{"-vv", "file"}, "verify", 1}, {[]string{"-dvvvv", "file"}, "display", 4}, {[]string{"-fs-", "file"}, "sign", 0},
		{[]string{"--verify", "--verbose=4", "--architecture=arm64", "file"}, "verify", 4},
		{[]string{"--sign=-", "--identifier=id", "--pagesize=4096", "--timestamp=none", "--force", "--continue", "--dryrun", "--json", "--all-architectures", "--generate-entitlement-der", "--force-library-entitlements", "--runtime-version=27.1.2", "--entitlements=e", "--options=runtime", "file"}, "sign", 0},
		{[]string{"--display", "--verbose", "--", "-filename"}, "display", 1},
		{[]string{"-s", "-", "-i", "id", "-a", "arm64", "-r=identifier \"id\"", "-P", "4096", "-o", "hard,kill", "file"}, "sign", 0},
		{[]string{"-v", "-R=identifier \"id\"", "file"}, "verify", 0},
		{[]string{"--verify", "--test-requirement=always", "file"}, "verify", 0},
		{[]string{"--verify", "--test-requirement", "req", "file"}, "verify", 0},
		{[]string{"--sign", "-", "--requirements", "req", "--config", "config", "file"}, "sign", 0},
		{[]string{"-v", "-R", "req", "file"}, "verify", 0},
	} {
		o, err := parse(tc.args)
		if err != nil || o.operation != tc.op || o.verbose != tc.verbose {
			t.Fatalf("%q: %+v %v", tc.args, o, err)
		}
	}
	for _, args := range [][]string{{"-d", "-s-"}, {"--sign", "-", "--verify"}, {"-i"}, {"--identifier"}, {"-z"}, {"--unknown"}, {"--timestamp="}, {"--timestamp=https://example.test"}, {"-h", "1"}, {"--pagesize=oops"}, {"-Pbad"}, {"--options=bad"}, {"-obad"}, {"--runtime-version=27.1.999"}, {"--verbose=bad"}} {
		if _, err := parse(args); err == nil {
			t.Fatal("accepted", args)
		}
	}
	for _, s := range []string{"none", "adhoc,hard,kill,expires,restrict,enforcement,library,runtime,linker-signed", "0x10000"} {
		if _, err := parseFlags(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"", "1.2.3.4", "1.256", "bad", "65536"} {
		if _, err := parseVersion(s); err == nil {
			t.Fatal("accepted version", s)
		}
	}
}

func TestCommands(t *testing.T) {
	unsigned := file(t, "unsigned-arm64")
	signed := file(t, "adhoc-arm64")
	universal := file(t, "adhoc-universal")
	missing := filepath.Join(t.TempDir(), "missing")
	for _, v := range []string{"-d", "-dv", "-dvv", "-dvvv", "-dvvvv"} {
		_, err, code := invoke(t, v, signed)
		if code != 0 || !strings.Contains(err, "Executable=") {
			t.Fatal(code, err)
		}
	}
	out, err, code := invoke(t, "-d", "--json", universal)
	if code != 0 || !json.Valid([]byte(out)) {
		t.Fatal(out, err, code)
	}
	if _, _, code := invoke(t, "-d", "-a", "arm64", universal); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-d", "-a", "none", universal); code != 1 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-d", unsigned); code != 1 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-vv", signed); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "--verify", "--json", signed); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "--verify", `-R=identifier "wrong"`, signed); code != 3 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "--verify", `-R=identifier "wrong"`, signed, unsigned); code != 1 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "--verify", `-R=identifier "wrong"`, unsigned, signed); code != 1 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-s", "-", "--dryrun", unsigned); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-s", "-", "-i", "test", unsigned); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-s", "-", unsigned); code != 1 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-fs", "-", unsigned); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "--remove-signature", unsigned); code != 0 {
		t.Fatal(code)
	}
	for _, args := range [][]string{{"-s", "Developer ID", unsigned}, {"-d", "--requirements=req", signed}, {"-s", "-", "--requirements", missing, unsigned}, {"-s", "-", "-r=unknown", unsigned}, {"--verify", "-R", missing, signed}, {"-s", "-", "--entitlements", missing, unsigned}, {"-d", missing}, {"-s", "-", "--dryrun", missing}, {"-s", "-", "--continue", missing, unsigned}} {
		if _, _, code := invoke(t, args...); code != 1 {
			t.Fatal(args, code)
		}
	}
	if _, _, code := invoke(t, "--help"); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t); code != 2 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-s"); code != 2 {
		t.Fatal(code)
	}
	req := write(t, "req", []byte(`identifier "org.example.fixture"`))
	if _, _, code := invoke(t, "-v", "-R", req, signed); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-fs", "-", "-i", "org.example.fixture", "-r", req, unsigned); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-fs", "-", "-r=never", unsigned); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-vv", unsigned); code != 3 {
		t.Fatal(code)
	}
	ent, readErr := os.ReadFile("../../testdata/entitlements.plist")
	if readErr != nil {
		t.Fatal(readErr)
	}
	entPath := write(t, "e.plist", ent)
	if _, _, code := invoke(t, "-fs", "-", "--entitlements", entPath, unsigned); code != 0 {
		t.Fatal(code)
	}
	out, err, code = invoke(t, "-d", "--entitlements", ":-", unsigned)
	if code != 0 || out != string(ent) {
		t.Fatal(code, out, err)
	}
	if _, _, code := invoke(t, "-d", "--entitlements", filepath.Join(t.TempDir(), "out"), unsigned); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-d", "--entitlements", "-", signed); code != 0 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-d", "--entitlements", "-", "-a", "none", signed); code != 1 {
		t.Fatal(code)
	}
}

func TestConfiguration(t *testing.T) {
	t.Setenv("MACOSCODESIGN_CONFIG", "")
	if err := configure(&options{}); err != nil {
		t.Fatal(err)
	}
	valid := write(t, "config.yaml", []byte("json: true\n"))
	o := options{config: valid}
	if err := configure(&o); err != nil || !o.json {
		t.Fatal(o, err)
	}
	t.Setenv("MACOSCODESIGN_CONFIG", valid)
	o = options{}
	if err := configure(&o); err != nil || !o.json {
		t.Fatal(o, err)
	}
	bad := write(t, "bad.yaml", []byte("[bad: yaml"))
	if _, _, code := invoke(t, "--config", bad, "-d", "x"); code != 2 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "--config", valid, "-d", file(t, "adhoc-arm64")); code != 0 {
		t.Fatal(code)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken output") }
func TestOutputErrorsAndHelpers(t *testing.T) {
	signed := file(t, "adhoc-arm64")
	var stderr bytes.Buffer
	for _, op := range []string{"-d", "-v"} {
		if code := Run(context.Background(), []string{op, "--json", signed}, nil, failWriter{}, &stderr); code != 1 {
			t.Fatal(code)
		}
	}
	for _, err := range []error{codesign.ErrUnsigned, codesign.ErrSigned, codesign.ErrRequirement, codesign.ErrDesignatedRequirement, errors.New("other")} {
		if diagnostic(err) == "" {
			t.Fatal("empty diagnostic")
		}
	}
	for _, v := range []uint8{0, 1, 2, 3, 4} {
		if hashName(v) == "" {
			t.Fatal("hash name")
		}
	}
	if flagNames(0) != "none" || !strings.Contains(flagNames(0x33f02), "runtime") {
		t.Fatal("flag names")
	}
	r := &codesign.Report{Architectures: []codesign.Architecture{{Name: "arm64"}}}
	if err := extractEntitlements(&stderr, r, options{}); !errors.Is(err, codesign.ErrUnsigned) {
		t.Fatal(err)
	}
	r.Architectures[0].Signature = &codesign.Signature{Directories: []codesign.Directory{{Raw: []byte{1}, TeamID: "TEAM", HashType: 1}}, Blobs: []codesign.Blob{{Slot: codesign.SlotEntitlements, Data: make([]byte, 9)}}}
	if err := extractEntitlements(failWriter{}, r, options{entitlements: "-"}); err == nil {
		t.Fatal("write failure ignored")
	}
	if err := display(&stderr, r, options{verbose: 4}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := Run(ctx, []string{"-d", signed}, nil, &stderr, &stderr); code != 1 {
		t.Fatal(code)
	}
}

func TestTimestampArguments(t *testing.T) {
	for _, args := range [][]string{{"-s", "identity.pem", "--timestamp", "file"}, {"-s", "identity.pem", "--timestamp=http://127.0.0.1:1234", "--timestamp-root", "root.pem", "--timestamp-timeout", "2s", "file"}, {"-s", "-", "--timestamp", "file"}} {
		o, err := parse(args)
		if err != nil || o.timestamp == "" {
			t.Fatal(args, o, err)
		}
	}
	for _, args := range [][]string{{"--timestamp-timeout", "0s"}, {"--timestamp-timeout", "-1s"}, {"--timestamp-timeout", "invalid"}, {"--timestamp-timeout"}} {
		if _, err := parse(args); err == nil {
			t.Fatal(args)
		}
	}
	path := file(t, "unsigned-arm64")
	for _, args := range [][]string{{"-s", "-", "--timestamp-timeout", "1s", path}, {"-s", "-", "--timestamp-root", "apple", path}, {"-s", "missing.pem", "--timestamp=none", "--timestamp-root", "apple", path}, {"-d", "--timestamp-timeout", "1s", path}} {
		if _, _, code := invoke(t, args...); code != 2 {
			t.Fatal(args, code)
		}
	}
	for _, option := range []string{"--timestamp=", "--timestamp=https://example.test"} {
		if _, _, code := invoke(t, "-s", "-", option, path); code != 1 {
			t.Fatal(option, code)
		}
	}
	// Constructed options remain validated even when parse is bypassed.
	var out, stderr bytes.Buffer
	if code := execute(context.Background(), options{operation: "sign", identity: "identity.pem", timestamp: "https://example.test"}, &out, &stderr); code != 2 {
		t.Fatal(code)
	}
	for _, root := range []string{"apple", "missing.pem", write(t, "invalid.pem", []byte("invalid"))} {
		if _, _, code := invoke(t, "-s", "missing.pem", "--timestamp", "--timestamp-root", root, path); code != 1 {
			t.Fatal(root, code)
		}
	}
	if _, _, code := invoke(t, "-s", "missing.pem", "--timestamp", path); code != 1 {
		t.Fatal(code)
	}
}
