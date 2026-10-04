//go:build ignore

// Research-only controlled live-process oracle; never uses a user keychain.
package main

import (
	"bufio"
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
	"runtime"
	"strconv"
	"strings"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func read(p string) []byte    { b, e := os.ReadFile(p); must(e); return b }
func output(command string, args ...string) []byte {
	b, e := exec.Command(command, args...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s %v: %v %s", command, args, e, b))
	}
	return b
}

type result struct {
	ID        string   `json:"id"`
	Arguments []string `json:"arguments"`
	Stdout    string   `json:"stdout"`
	Stderr    string   `json:"stderr"`
	Exit      int      `json:"exit"`
}

func main() {
	out := flag.String("out", "testdata/research/process-context.json", "native observations")
	check := flag.Bool("check", false, "require recorded native outcomes")
	flag.Parse()
	if runtime.GOOS != "darwin" {
		panic("native research requires macOS")
	}
	d, e := os.MkdirTemp("", "codesign-process-context-")
	must(e)
	defer os.RemoveAll(d)
	d, e = filepath.EvalSymlinks(d)
	must(e)
	binary := filepath.Join(d, "oracle")
	output("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "scripts/oracles/process-context.c", "-framework", "Security", "-framework", "CoreFoundation", "-o", binary)
	cmd := exec.Command(binary)
	stdin, e := cmd.StdinPipe()
	must(e)
	stdout, e := cmd.StdoutPipe()
	must(e)
	cmd.Stderr = os.Stderr
	must(cmd.Start())
	defer func() { _ = stdin.Close(); _ = cmd.Wait() }()
	line, e := bufio.NewReader(stdout).ReadBytes('\n')
	must(e)
	var api map[string]int
	must(json.Unmarshal(line, &api))
	if api["pid"] != cmd.Process.Pid || api["self"] != 0 || api["host"] != 0 || api["static"] != 0 || api["status_result"] != 0 || api["validity"] != 0 {
		panic(fmt.Sprintf("invalid native process control: %s", line))
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	cases := []result{
		{ID: "live-verify", Arguments: []string{"--verify", pid}},
		{ID: "live-verbose-verify", Arguments: []string{"--verify", "--verbose=4", pid}},
		{ID: "live-hosting", Arguments: []string{"--hosting", pid}},
		{ID: "static-verify", Arguments: []string{"--verify", binary}},
		{ID: "static-hosting-rejected", Arguments: []string{"--hosting", binary}},
		{ID: "numeric-relative-path", Arguments: []string{"--verify", "./" + pid}},
	}
	for i := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c := exec.CommandContext(ctx, "/usr/bin/codesign", cases[i].Arguments...)
		c.Dir = d
		c.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
		var out, err bytes.Buffer
		c.Stdout = &out
		c.Stderr = &err
		e := c.Run()
		cancel()
		if e != nil {
			exit, ok := e.(*exec.ExitError)
			if !ok || exit.ExitCode() < 0 {
				panic(e)
			}
			cases[i].Exit = exit.ExitCode()
		}
		cases[i].Stdout, cases[i].Stderr = out.String(), err.String()
	}
	// Only the disposable child's PID/path vary. Keep raw values and declare exactly
	// those substitutions for comparison; do not normalize policy/status differences.
	normalize := func(value string, pid, dir string) string {
		return strings.ReplaceAll(strings.ReplaceAll(value, dir, "<fixture-dir>"), pid, "<fixture-pid>")
	}
	if *check {
		var prior struct {
			Native    string            `json:"codesign_sha256"`
			Sources   map[string]string `json:"source_sha256"`
			Cases     []result
			PID       string `json:"pid"`
			Directory string `json:"directory"`
		}
		must(json.Unmarshal(read("testdata/research/process-context.json"), &prior))
		if prior.Native != hash(read("/usr/bin/codesign")) {
			panic("native codesign binary drift")
		}
		for _, path := range []string{"scripts/probe-process-context.go", "scripts/oracles/process-context.c"} {
			if prior.Sources[path] != hash(read(path)) {
				panic("stale process oracle: " + path)
			}
		}
		if len(prior.Cases) != len(cases) {
			panic("missing native process cases")
		}
		for i, c := range cases {
			p := prior.Cases[i]
			if len(c.Arguments) != len(p.Arguments) {
				panic("native argument drift")
			}
			for j, arg := range c.Arguments {
				if normalize(arg, pid, d) != normalize(p.Arguments[j], prior.PID, prior.Directory) {
					panic("native argument drift")
				}
			}
			if c.ID != p.ID || c.Exit != p.Exit || normalize(c.Stdout, pid, d) != normalize(p.Stdout, prior.PID, prior.Directory) || normalize(c.Stderr, pid, d) != normalize(p.Stderr, prior.PID, prior.Directory) {
				panic(fmt.Sprintf("native process drift: %s: %#v", c.ID, c))
			}
		}
	}
	data := map[string]any{"schema": 1, "binary_sha256": hash(read(binary)), "pid": pid, "directory": d, "api": api, "cases": cases, "scope": "Own disposable Clang-built process only; SDK introspection and native CLI observations do not establish portable kernel state access.", "macos": string(output("/usr/bin/sw_vers")), "architecture": runtime.GOARCH, "codesign_sha256": hash(read("/usr/bin/codesign")), "source_sha256": map[string]string{"scripts/probe-process-context.go": hash(read("scripts/probe-process-context.go")), "scripts/oracles/process-context.c": hash(read("scripts/oracles/process-context.c"))}, "compiler": string(output("xcrun", "clang", "--version"))}
	b, e := json.MarshalIndent(data, "", "  ")
	must(e)
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	must(os.WriteFile(*out, append(b, '\n'), 0644))
	fmt.Println("Captured six native process/path cases and five SDK controls")
}
