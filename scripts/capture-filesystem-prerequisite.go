//go:build ignore

// Capture native filesystem writer controls and the released SDK prerequisite.
// This is discovery evidence, not a passing codesign parity acceptance gate.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

type filesystemCommand struct {
	Args   []string `json:"argv"`
	Stdout string   `json:"stdout"`
	Stderr string   `json:"stderr"`
	Exit   int      `json:"exit"`
}

func filesystemRun(name string, args ...string) filesystemCommand {
	command := exec.Command(name, args...)
	var out, stderr bytes.Buffer
	command.Stdout = &out
	command.Stderr = &stderr
	err := command.Run()
	status := 0
	if err != nil {
		status = -1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			status = exit.ExitCode()
		} else {
			stderr.WriteString(err.Error())
		}
	}
	return filesystemCommand{append([]string{name}, args...), out.String(), stderr.String(), status}
}
func filesystemHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func filesystemError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func main() {
	output := flag.String("output", "testdata/research/filesystem-prerequisite.json", "capture destination")
	flag.Parse()
	if err := captureFilesystems(*output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func captureFilesystems(output string) (result error) {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native filesystem capture requires macOS")
	}
	root, err := os.MkdirTemp("", "codesign-filesystem-research-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(root)) }()
	commands := []filesystemCommand{}
	run := func(name string, args ...string) (filesystemCommand, error) {
		record := filesystemRun(name, args...)
		commands = append(commands, record)
		if record.Exit != 0 {
			return record, fmt.Errorf("%s %v: status %d: %s", name, args, record.Exit, record.Stderr)
		}
		return record, nil
	}
	provenance := map[string]any{}
	for name, args := range map[string][]string{"sw_vers": {}, "uname": {"-a"}, "go": {"list", "-m", "-json", "github.com/deploymenttheory/go-apfs-v2"}, "git": {"rev-parse", "HEAD"}} {
		record, err := run(name, args...)
		if err != nil {
			return err
		}
		provenance[name] = strings.TrimSpace(record.Stdout)
	}
	hashes := map[string]string{}
	for _, path := range []string{"/usr/bin/codesign", "scripts/capture-filesystem-prerequisite.go", "testdata/removal/unsigned-arm64.macho", "spec/apple-writer.json", "go.mod", "go.sum"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hashes[path] = filesystemHash(data)
	}
	original, err := os.ReadFile("testdata/removal/unsigned-arm64.macho")
	if err != nil {
		return err
	}
	records := []map[string]any{}
	for _, filesystem := range []string{"APFS", "HFS+"} {
		err := func() (result error) {
			image := filepath.Join(root, strings.ReplaceAll(filesystem, "+", "plus")+".dmg")
			mount := filepath.Join(root, "mount")
			if err := os.Mkdir(mount, 0700); err != nil {
				return err
			}
			defer func() { result = errors.Join(result, os.Remove(mount)) }()
			if _, err := run("/usr/bin/hdiutil", "create", "-size", "128m", "-fs", filesystem, "-volname", "CodesignPhase02", image); err != nil {
				return err
			}
			if _, err := run("/usr/bin/hdiutil", "attach", "-nobrowse", "-owners", "on", "-mountpoint", mount, image); err != nil {
				return err
			}
			defer func() { _, err := run("/usr/bin/hdiutil", "detach", mount); result = errors.Join(result, err) }()
			for _, operation := range []string{"sign", "dryrun", "remove"} {
				nativePath := filepath.Join(mount, operation)
				if err := os.WriteFile(nativePath, original, 0755); err != nil {
					return err
				}
				if operation == "remove" {
					if _, err := run("/usr/bin/codesign", "--sign", "-", "--identifier", "phase02", nativePath); err != nil {
						return err
					}
				}
				before, err := os.ReadFile(nativePath)
				if err != nil {
					return err
				}
				args := []string{"--force", "--sign", "-", "--identifier", "phase02"}
				if operation == "dryrun" {
					args = append(args, "--dryrun")
				}
				if operation == "remove" {
					args = []string{"--remove-signature"}
				}
				native, err := run("/usr/bin/codesign", append(args, nativePath)...)
				if err != nil {
					return err
				}
				after, err := os.ReadFile(nativePath)
				if err != nil {
					return err
				}
				goPath := nativePath + "-go"
				if err := os.WriteFile(goPath, before, 0755); err != nil {
					return err
				}
				var goErr error
				if operation == "remove" {
					goErr = codesign.Remove(context.Background(), goPath, codesign.RemoveOptions{})
				} else {
					goErr = codesign.Sign(context.Background(), goPath, codesign.SignOptions{Identifier: "phase02", Force: true, DryRun: operation == "dryrun"})
				}
				goAfter, err := os.ReadFile(goPath)
				if err != nil {
					return err
				}
				source, err := os.Open(goPath)
				if err != nil {
					return err
				}
				replacement, prepareErr := hostdata.PrepareReplacement(source, mount)
				var cleanupErr error
				if replacement != nil {
					cleanupErr = replacement.Close()
				}
				cleanupErr = errors.Join(cleanupErr, source.Close())
				if cleanupErr != nil {
					return cleanupErr
				}
				records = append(records, map[string]any{"id": "p02.metadata." + strings.ToLower(strings.ReplaceAll(filesystem, "+", "plus")) + "." + operation, "filesystem": filesystem, "operation": operation, "native": native, "input_sha256": filesystemHash(before), "native_output_sha256": filesystemHash(after), "go_output_sha256": filesystemHash(goAfter), "go_error": filesystemError(goErr), "sdk_prepare_error": filesystemError(prepareErr), "output_bytes_match": bytes.Equal(after, goAfter)})
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	report := map[string]any{"schema": 1, "purpose": "phase 02 prerequisite discovery, not complete lifecycle qualification", "provenance": provenance, "source_sha256": hashes, "commands": commands, "cases": records}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	return os.WriteFile(output, append(data, '\n'), 0644)
}
