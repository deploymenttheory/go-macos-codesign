//go:build ignore

// Research only: native compressed Mach-O lifecycle and released SDK eligibility.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(program string, args ...string) ([]byte, string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, program, args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, err := c.Output()
	code := 0
	if err != nil {
		var ok bool
		var e *exec.ExitError
		e, ok = err.(*exec.ExitError)
		if !ok {
			panic(err)
		}
		code = e.ExitCode()
	}
	if ctx.Err() != nil {
		panic(ctx.Err())
	}
	return b, stderr.String(), code
}
func checked(program string, args ...string) []byte {
	b, e, c := run(program, args...)
	if c != 0 {
		panic(fmt.Sprintf("%s: exit %d: %s", program, c, e))
	}
	return b
}

type state struct {
	Flags      uint32 `json:"flags"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Attribute  []byte `json:"attribute,omitempty"`
	ForkSHA256 string `json:"fork_sha256,omitempty"`
}
type result struct {
	Shape        string `json:"shape"`
	Operation    string `json:"operation"`
	Preserve     bool   `json:"preserve"`
	Before       state  `json:"before"`
	After        state  `json:"after"`
	Exit         int    `json:"exit"`
	Diagnostic   string `json:"diagnostic"`
	SameIdentity bool   `json:"same_identity"`
	SDKError     string `json:"sdk_error"`
}

func main() {
	out := flag.String("out", "testdata/research/compressed-signing.json", "capture output")
	flag.Parse()
	dir, err := os.MkdirTemp("", "codesign-compressed-")
	must(err)
	defer os.RemoveAll(dir)
	var module struct{ Dir, Version, Sum string }
	must(json.Unmarshal(checked("go", "list", "-m", "-json", "github.com/deploymenttheory/go-apfs-v2"), &module))
	// This is the SDK's existing independent C producer, compiled against the
	// host headers. It invokes AppleFSCompression only in research, never in Go
	// production. Pin its released bytes alongside the observed SDK version.
	cSource := filepath.Join(module.Dir, "testdata/appledouble/native/decmpfs-formats.c")
	helper := filepath.Join(dir, "compression-native")
	checked("clang", "-Wall", "-Wextra", "-framework", "CoreFoundation", cSource, "-o", helper)
	snapshot := func(path, prefix string) state {
		// The producer's install action cannot inspect an existing file; use
		// the small public-header observer retained in this project instead.
		var s state
		must(json.Unmarshal(checked(filepath.Join(dir, "observe"), path, prefix), &s))
		s.SHA256 = hash(read(path))
		if b, e := os.ReadFile(prefix + ".attr"); e == nil {
			s.Attribute = b
		} else if !os.IsNotExist(e) {
			must(e)
		}
		if b, e := os.ReadFile(prefix + ".fork"); e == nil {
			s.ForkSHA256 = hash(b)
		} else if !os.IsNotExist(e) {
			must(e)
		}
		return s
	}
	checked("clang", "-Wall", "-Wextra", "testdata/research/compressed-signing.c", "-o", filepath.Join(dir, "observe"))
	var cases []result
	for _, shape := range []string{"standalone", "bundle"} {
		for _, operation := range []string{"sign", "resign", "dryrun", "remove"} {
			for _, preserve := range []bool{false, true} {
				caseDir := filepath.Join(dir, fmt.Sprintf("%s-%s-%t", shape, operation, preserve))
				must(os.Mkdir(caseDir, 0700))
				operand := filepath.Join(caseDir, "hello")
				executable := operand
				if shape == "bundle" {
					operand = filepath.Join(caseDir, "Compression.app")
					executable = filepath.Join(operand, "Contents/MacOS/hello")
					must(os.MkdirAll(filepath.Dir(executable), 0755))
					must(os.WriteFile(filepath.Join(operand, "Contents/Info.plist"), []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>hello</string><key>CFBundleIdentifier</key><string>org.example.compression</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>`), 0644))
				}
				must(os.WriteFile(executable, read("testdata/removal/unsigned-arm64.macho"), 0755))
				if operation == "resign" || operation == "remove" {
					checked("/usr/bin/codesign", "-s", "-", "-i", "org.example.compression", "--timestamp=none", operand)
				}
				checked(helper, "produce", "3", executable, filepath.Join(caseDir, "producer"))
				before := snapshot(executable, filepath.Join(caseDir, "before"))
				if before.Flags&hostdata.UFCompressed == 0 {
					panic("native producer did not compress")
				}
				identity, err := os.Stat(executable)
				must(err)
				f, err := os.Open(executable)
				must(err)
				var sdkErr error
				if shape == "standalone" {
					r, e := hostdata.PrepareReplacement(f, caseDir)
					sdkErr = e
					if r != nil {
						must(r.Close())
					}
				} else {
					root, e := os.OpenRoot(filepath.Dir(executable))
					must(e)
					r, e := hostdata.PrepareReplacementAt(f, root, ".")
					sdkErr = e
					if r != nil {
						must(r.Close())
					}
					must(root.Close())
				}
				must(f.Close())
				args := []string{"-s", "-", "-i", "org.example.compression", "--timestamp=none"}
				if operation == "resign" {
					args = append(args, "-f")
				}
				if operation == "dryrun" {
					args = append(args, "--dryrun")
				}
				if operation == "remove" {
					args = []string{"--remove-signature"}
				}
				if preserve {
					args = append(args, "--preserve-afsc")
				}
				args = append(args, operand)
				stdout, stderr, exit := run("/usr/bin/codesign", args...)
				if len(stdout) != 0 {
					panic("unexpected native stdout")
				}
				after := snapshot(executable, filepath.Join(caseDir, "after"))
				afterInfo, err := os.Stat(executable)
				must(err)
				row := result{Shape: shape, Operation: operation, Preserve: preserve, Before: before, After: after, Exit: exit, Diagnostic: strings.ReplaceAll(stderr, operand, "<code>"), SameIdentity: os.SameFile(identity, afterInfo)}
				if sdkErr != nil {
					row.SDKError = sdkErr.Error()
				}
				cases = append(cases, row)
				fmt.Printf("%s %s preserve=%t native=%d flags=%#x/%#x sdk=%v\n", shape, operation, preserve, exit, before.Flags, after.Flags, sdkErr)
			}
		}
	}
	sources := map[string]string{}
	for _, p := range []string{"scripts/probe-compressed-signing.go", "testdata/research/compressed-signing.c", "testdata/removal/unsigned-arm64.macho", "go.mod", "go.sum", "/usr/bin/codesign"} {
		sources[p] = hash(read(p))
	}
	capture := map[string]any{"schema": 1, "source_sha256": sources, "sdk": module.Version, "sdk_sum": module.Sum, "native_producer_sha256": hash(read(cSource)), "native_producer_path": "testdata/appledouble/native/decmpfs-formats.c", "host": string(checked("sw_vers")), "cases": cases}
	b, err := json.MarshalIndent(capture, "", "  ")
	must(err)
	must(os.WriteFile(*out, append(b, '\n'), 0644))
}
