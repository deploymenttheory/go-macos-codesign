//go:build ignore

// Research only: build a CommonCrypto oracle with Clang and retain its output.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type capture struct {
	Schema   int               `json:"schema"`
	Scope    string            `json:"scope"`
	Compiler string            `json:"compiler"`
	Host     string            `json:"host"`
	SDK      string            `json:"sdk"`
	Sources  map[string]string `json:"source_sha256"`
	Cases    json.RawMessage   `json:"cases"`
}

func run(name string, args ...string) []byte {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		panic(fmt.Sprintf("%s: %v: %s", name, err, stderr.String()))
	}
	return bytes.TrimSpace(out)
}
func sha(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func main() {
	check := flag.Bool("check", false, "compare complete digest corpus to committed capture")
	out := flag.String("out", "testdata/research/hash-streams.json", "capture destination")
	flag.Parse()
	tmp, err := os.MkdirTemp("", "codesign-hashes-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)
	sdk := string(run("xcrun", "--show-sdk-path"))
	binary := filepath.Join(tmp, "hash-streams")
	run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-isysroot", sdk, "scripts/oracles/hash-streams.c", "-o", binary)
	c := capture{Schema: 1, Scope: "CommonCrypto digest output for deterministic streams; not native codesign I/O or large-file acceptance", Compiler: string(run("clang", "--version")), Host: string(run("sw_vers")), SDK: filepath.Base(sdk), Sources: map[string]string{}, Cases: run(binary)}
	for _, p := range []string{"scripts/oracles/hash-streams.c", "scripts/probe-hash-streams.go"} {
		c.Sources[p] = sha(p)
	}
	c.Sources["CommonCrypto/CommonDigest.h"] = sha(filepath.Join(sdk, "usr/include/CommonCrypto/CommonDigest.h"))
	c.Sources["oracle_binary"] = sha(binary)
	if *check {
		b, err := os.ReadFile("testdata/research/hash-streams.json")
		if err != nil {
			panic(err)
		}
		var baseline capture
		if err = json.Unmarshal(b, &baseline); err != nil {
			panic(err)
		}
		var a, bcompact bytes.Buffer
		if err = json.Compact(&a, c.Cases); err != nil {
			panic(err)
		}
		if err = json.Compact(&bcompact, baseline.Cases); err != nil {
			panic(err)
		}
		if !bytes.Equal(a.Bytes(), bcompact.Bytes()) {
			panic("native hash corpus differs")
		}
		for _, p := range []string{"scripts/oracles/hash-streams.c", "scripts/probe-hash-streams.go"} {
			if c.Sources[p] != baseline.Sources[p] {
				panic("stale provenance: " + p)
			}
		}
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		panic(err)
	}
	if err = os.WriteFile(*out, append(b, '\n'), 0644); err != nil {
		panic(err)
	}
	fmt.Println("Wrote", *out)
}
