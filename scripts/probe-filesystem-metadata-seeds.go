//go:build ignore

// Produce genuine packed metadata inputs and Clang AST evidence for real-volume
// codesign acceptance. This is research/test infrastructure, not a build backend.
package main

import (
	"bytes"
	"compress/gzip"
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
	"time"
)

func main() {
	output := flag.String("out", "testdata/filesystem-metadata/native-seeds.json", "native seed report")
	flag.Parse()
	if err := captureFilesystemSeeds(*output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func captureFilesystemSeeds(output string) (err error) {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native seeds require macOS")
	}
	work, err := os.MkdirTemp("", "codesign-filesystem-seeds-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	run := func(exe string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		fmt.Fprintf(os.Stderr, "START %s %q\n", exe, args)
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.WaitDelay = time.Second
		data, e := cmd.Output()
		fmt.Fprintf(os.Stderr, "END %s error=%v context=%v\n", exe, e, ctx.Err())
		if e != nil {
			if failure, ok := e.(*exec.ExitError); ok {
				return nil, fmt.Errorf("%s: %w: %s", exe, e, failure.Stderr)
			}
			return nil, e
		}
		return data, nil
	}
	source := "testdata/filesystem-metadata/seed.c"
	binary := filepath.Join(work, "seed")
	if _, err = run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", binary); err != nil {
		return err
	}
	hashes := map[string]string{}
	hash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	for _, name := range []string{source, "scripts/probe-filesystem-metadata-seeds.go", "go.mod", "go.sum"} {
		data, e := os.ReadFile(name)
		if e != nil {
			return e
		}
		hashes[name] = hash(data)
	}
	exe, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	binaryHash := hash(exe)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-arch", arch, "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if e != nil {
			return e
		}
		if !json.Valid(ast) {
			return fmt.Errorf("invalid %s AST", arch)
		}
		var packed bytes.Buffer
		zipped := gzip.NewWriter(&packed)
		if _, e = zipped.Write(ast); e != nil {
			return e
		}
		if e = zipped.Close(); e != nil {
			return e
		}
		astPath := filepath.Join(filepath.Dir(output), "seed-"+arch+".ast.json.gz")
		if e = os.MkdirAll(filepath.Dir(astPath), 0755); e != nil {
			return e
		}
		if e = os.WriteFile(astPath, packed.Bytes(), 0600); e != nil {
			return e
		}
		hashes[filepath.Base(astPath)] = hash(packed.Bytes())
	}
	seeds := map[string][]byte{}
	for _, kind := range []string{"strip", "remove", "clean", "fork", "finder", "both", "ordinary", "generic-clean", "generic-populated", "generic-empty", "discovery"} {
		input, packed := filepath.Join(work, kind), filepath.Join(work, kind+".ad")
		if err = os.WriteFile(input, []byte("payload"), 0600); err != nil {
			return err
		}
		if _, err = run(binary, input, packed, kind); err != nil {
			return err
		}
		seeds[kind], err = os.ReadFile(packed)
		if err != nil {
			return err
		}
	}
	host, err := run("sw_vers")
	if err != nil {
		return err
	}
	compiler, err := run("xcrun", "clang", "--version")
	if err != nil {
		return err
	}
	sdk, err := run("xcrun", "--show-sdk-path")
	if err != nil {
		return err
	}
	report := map[string]any{"schema": 1, "complete": true, "host": string(host), "compiler": string(compiler), "sdk": string(sdk), "source_sha256": hashes, "binary_sha256": binaryHash, "seeds": seeds}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(output, append(raw, '\n'), 0600)
}
