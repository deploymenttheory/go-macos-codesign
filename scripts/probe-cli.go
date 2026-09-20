//go:build ignore

// Research only: inventory the installed native parser and bounded applicability
// probes. No real keychain, detached database, remote service or helper is used.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type observation struct {
	Arguments   []string          `json:"arguments,omitempty"`
	Exit        int               `json:"exit"`
	Signal      string            `json:"signal,omitempty"`
	Stdout      string            `json:"stdout,omitempty"`
	Stderr      string            `json:"stderr,omitempty"`
	Before      map[string]string `json:"before_sha256,omitempty"`
	After       map[string]string `json:"after_sha256,omitempty"`
	Unavailable string            `json:"unavailable,omitempty"`
}

func execute(dir string, args ...string) observation {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "/usr/bin/codesign", args...)
	c.Dir = dir
	// Do not inherit allocator, remote-signing, proxy or user configuration.
	c.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "TZ=UTC"}
	var out, stderr bytes.Buffer
	c.Stdout = &out
	c.Stderr = &stderr
	err := c.Run()
	status := 0
	signal := ""
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			status = e.ExitCode()
			if wait, ok := e.Sys().(syscall.WaitStatus); ok && wait.Signaled() {
				signal = wait.Signal().String()
			}
		} else {
			panic(err)
		}
	}
	if ctx.Err() != nil {
		panic("native probe exceeded deadline: " + strings.Join(args, " "))
	}
	return observation{Arguments: args, Exit: status, Signal: signal, Stdout: out.String(), Stderr: stderr.String()}
}

func snapshot(dir string) map[string]string {
	result := map[string]string{}
	must(filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(rel)] = hash(read(p))
		return nil
	}))
	return result
}

func main() {
	if runtime.GOOS != "darwin" {
		panic("native macOS research only")
	}
	manual := read("/usr/share/man/man1/codesign.1")
	binary := read("/usr/bin/codesign")
	var compat struct {
		Baseline struct {
			Tool   string `json:"codesign_sha256"`
			Manual string `json:"manual_sha256"`
		} `json:"baseline"`
	}
	must(json.Unmarshal(read("spec/compatibility.json"), &compat))
	if hash(binary) != compat.Baseline.Tool || hash(manual) != compat.Baseline.Manual {
		panic("native baseline drift; review before recording")
	}
	dir, err := os.MkdirTemp("", "codesign-cli-inventory-")
	must(err)
	defer os.RemoveAll(dir)
	fixture := read("testdata/macho/adhoc-arm64")
	plist := []byte(`<?xml version="1.0"?><plist version="1.0"><dict/></plist>`)
	manualNames := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\.It Fl (?:[^\n,]+, )?-([a-z][a-z-]*)([^\n]*)`).FindAllStringSubmatch(string(manual), -1) {
		manualNames[m[1]] = m[0]
	}
	if len(manualNames) != 47 {
		panic(fmt.Sprintf("manual inventory changed: %d", len(manualNames)))
	}
	candidates := map[string]bool{}
	for name := range manualNames {
		candidates[name] = true
	}
	namePattern := regexp.MustCompile(`^[a-z][a-z0-9]+(?:-[a-z0-9]+)+$`)
	for _, text := range regexp.MustCompile(`[ -~]{4,}`).FindAllString(string(binary), -1) {
		if namePattern.MatchString(text) {
			candidates[text] = true
		}
	}
	names := []string{}
	for name := range candidates {
		names = append(names, name)
	}
	slices.Sort(names)
	values := map[string]string{
		"architecture": "arm64", "bundle-version": "A", "identifier": "org.example.probe", "options": "runtime", "pagesize": "4096", "sign": "-",
		"requirements": "=designated => true", "test-requirement": "=true", "entitlements": "input.plist", "extract-certificates": "cert",
		"detached": "detached.sig", "file-list": "files.txt", "prefix": "org.example.", "preserve-metadata": "identifier", "timestamp": "none", "runtime-version": "27.0",
		"launch-constraint-self": "input.plist", "launch-constraint-parent": "input.plist", "launch-constraint-responsible": "input.plist", "library-constraint": "input.plist",
		"signature-slot": "0", "input-detached-certificates": "missing.cert", "output-detached-certificates": "output.cert",
		"digest-algorithm": "sha256", "resource-rules": "input.plist", "constraint-category": "0", "platform-identifier": "1", "signature-size": "16384",
		"signing-time": "none", "team-identifier": "PUBLIC1234", "verify-resource": "fixture", "edit-arch": "arm64", "dump-cms": "cms.der",
	}
	exclusions := map[string]string{
		"detached-database":  "Requires the actual system database and privileges; no system writes are performed.",
		"keychain":           "Requires isolated authorized keychain state; production keychains are not accessed.",
		"check-notarization": "Requires an authenticated live service and legitimate ticket fixtures; no online lookup is performed.",
		"check-revocation":   "Requires controlled revocation/trust state and service evidence.",
		"remote-signing":     "External signer/provider protocol and authorization unavailable.",
		"signing-dylib":      "Executes an external signing helper and conflicts with the no-helper production boundary.",
		"edit-cms":           "CMS editing protocol and external input require a separate isolated fixture.",
	}
	operations := []struct {
		name string
		args []string
	}{
		{"sign", []string{"--sign", "-", "--force", "--timestamp=none", "--dryrun"}},
		{"verify", []string{"--verify"}}, {"display", []string{"--display"}}, {"remove", []string{"--remove-signature"}},
		{"hosting", nil}, {"validate-constraint", []string{"--validate-constraint"}}, {"merge-detached-certificates", nil},
	}
	options := map[string]any{}
	rejected := map[string]any{}
	for _, name := range names {
		parser := execute(dir, "--"+name)
		unknown := strings.Contains(parser.Stderr, "unrecognized option") || strings.Contains(parser.Stderr, "unknown option")
		if unknown && manualNames[name] == "" {
			rejected[name] = parser
			continue
		}
		entry := map[string]any{"documented": manualNames[name] != "", "manual_entry": manualNames[name], "parser_probe": parser, "recognized": !unknown}
		matrix := map[string]observation{}
		for _, op := range operations {
			reason := exclusions[name]
			if op.name == "hosting" {
				reason = "No controlled dynamic process/hosting context supplied; parser recognition does not establish live-state equivalence."
			}
			if op.name == "merge-detached-certificates" {
				reason = "No legitimate native hybrid detached-certificate input supplied; merge wire format and policy remain unknown."
			}
			if reason != "" {
				matrix[op.name] = observation{Exit: -1, Unavailable: reason}
				continue
			}
			probeDir := filepath.Join(dir, name+"-"+op.name)
			must(os.Mkdir(probeDir, 0700))
			must(os.WriteFile(filepath.Join(probeDir, "fixture"), fixture, 0755))
			must(os.WriteFile(filepath.Join(probeDir, "input.plist"), plist, 0600))
			args := append([]string{}, op.args...)
			flag := "--" + name
			if value, ok := values[name]; ok {
				flag += "=" + value
			}
			args = append(args, flag)
			target := "fixture"
			if op.name == "validate-constraint" {
				target = "input.plist"
			}
			args = append(args, target)
			before := snapshot(probeDir)
			result := execute(probeDir, args...)
			result.Before = before
			result.After = snapshot(probeDir)
			matrix[op.name] = result
		}
		entry["applicability_probes"] = matrix
		options["--"+name] = entry
	}
	var fs syscall.Statfs_t
	must(syscall.Statfs(dir, &fs))
	fsname := []byte{}
	for _, b := range fs.Fstypename {
		if b == 0 {
			break
		}
		fsname = append(fsname, byte(b))
	}
	must(os.WriteFile(filepath.Join(dir, "CaseProbe"), nil, 0600))
	_, caseErr := os.Stat(filepath.Join(dir, "caseprobe"))
	host, err := exec.Command("/usr/bin/sw_vers").Output()
	must(err)
	record := map[string]any{
		"schema": 1, "recorded_at": time.Now().UTC().Format(time.RFC3339), "host": string(host), "architecture": runtime.GOARCH, "locale": "C", "timezone": "UTC", "filesystem": string(fsname), "case_sensitive": os.IsNotExist(caseErr),
		"codesign_sha256": hash(binary), "manual_sha256": hash(manual), "fixture": "testdata/macho/adhoc-arm64", "fixture_sha256": hash(fixture), "driver_sha256": hash(read("scripts/probe-cli.go")),
		"scope":      "Parser recognition plus five-operation probes on a single signed arm64 Mach-O and an empty constraint plist. Each probe uses fresh disposable state; signing always includes dryrun and an ad-hoc identity. Repeated/conflicting operation flags are deliberately recorded. Success, failure, or identical bytes in this profile do not establish general applicability, ignored-option semantics, trust, or feature equivalence. Hosting and certificate merging retain explicit missing-context cells. No unavailable cell is a passing test.",
		"source_gap": "The pinned security_systemkeychain revision supplies cs_utils.cpp but does not publish the current codesign main/parser. Binary strings are candidates only; parser probes separate recognized switches from unrelated strings. Existing SDK and writer AST records remain separate evidence.",
		"options":    options, "rejected_binary_candidates": rejected,
		"environment_hooks": []any{map[string]any{"name": "CODESIGN_ALLOCATE", "evidence": "installed manual ENVIRONMENT section", "status": "blocked", "reason": "Arbitrary external allocator execution conflicts with the no-helper production requirement; default allocation remains independently implemented."}},
		"unresolved": map[string]string{
			"hosting": "Needs an authorized target process, host/guest chain and dynamic validity, including PID races.", "live-process-verification": "Needs actual loaded code and kernel signing state, not just file bytes.",
			"keychain": "Needs authorized search lists, preferences, unlock/ACL decisions and usable key provider.", "detached-database": "Needs real database schema, lookup/update behavior and isolated authorized persistence.", "hardware-identities": "Needs the original non-exportable key and authorized device/service operation.",
			"hybrid-pqc": "Needs legitimate native algorithm, signature-slot and certificate-interchange fixtures; do not infer algorithms from option names.", "notarization": "Needs authenticated ticket/protocol fixtures, verified trust/binding and portable transport without the forbidden dependency graph.",
		},
	}
	out, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-cli-inventory.json", append(out, '\n'), 0644))
	fmt.Printf("Recorded %d documented options, %d recognized/candidate inventory entries, %d rejected binary strings\n", len(manualNames), len(options), len(rejected))
}
