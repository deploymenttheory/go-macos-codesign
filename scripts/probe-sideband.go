//go:build ignore

// Mac-only research oracle. Native tools act only on fresh private fixtures.
// This records observations; it does not claim Go codesign parity.
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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-macos-codesign/internal/sideband"
	"golang.org/x/sys/unix"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type invocation struct {
	Args   []string `json:"args"`
	Status int      `json:"status"`
	Stdout string   `json:"stdout"`
	Stderr string   `json:"stderr"`
}

func invoke(dir, executable string, args ...string) invocation {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = dir
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	status := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() < 0 || ctx.Err() != nil {
			panic(fmt.Sprintf("native termination: %v, %s", err, stderr.String()))
		}
		status = exit.ExitCode()
	}
	return invocation{args, status, out.String(), stderr.String()}
}

var names = []string{"com.apple.ResourceFork", "com.apple.FinderInfo", "user.sideband-control"}

type entry struct {
	Mode   string            `json:"mode"`
	SHA256 string            `json:"sha256,omitempty"`
	Attrs  map[string]string `json:"attrs_hex"`
}

func snapshot(root string) map[string]entry {
	result := map[string]entry{}
	must(filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		v := entry{Mode: info.Mode().String(), Attrs: map[string]string{}}
		if info.Mode().IsRegular() {
			v.SHA256 = hash(read(path))
		} else if !info.IsDir() {
			return fmt.Errorf("unexpected fixture type %s", path)
		}
		for _, name := range names {
			buf := make([]byte, 4096)
			n, err := unix.Lgetxattr(path, name, buf)
			if errors.Is(err, unix.ENOATTR) {
				continue
			}
			if err != nil {
				return fmt.Errorf("snapshot %s %s: %w", rel, name, err)
			}
			v.Attrs[name] = hex.EncodeToString(buf[:n])
		}
		result[filepath.ToSlash(rel)] = v
		return nil
	}))
	return result
}

func copyTree(source, target string) {
	must(filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(target, rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("unexpected fixture type %s", path)
		}
		return os.WriteFile(dest, read(path), 0755)
	}))
}

// Cross-check only the metadata adapter here. Native CLI policy, traversal and
// diagnostic assertions below remain independent and unchanged.
func inspectAdapter(path string, carrier appledouble.Value) []string {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	a, err := sideband.Inspect(context.Background(), f, carrier)
	must(err)
	return a.Names()
}

func capturedCarrier(attrs map[string]string) []byte {
	fork, err := hex.DecodeString(attrs[names[0]])
	must(err)
	finder, err := hex.DecodeString(attrs[names[1]])
	must(err)
	f := appledouble.File{ResourceFork: fork}
	copy(f.FinderInfo[:], finder)
	b, err := f.Encode()
	must(err)
	return b
}

func main() {
	check := flag.Bool("check", false, "assert the measured Mac verification profile, including exact diagnostics and unchanged snapshots")
	fixtures := flag.String("fixtures", "", "write portable native metadata fixtures to this directory after all checks pass (requires -check)")
	flag.Parse()
	if *fixtures != "" && !*check {
		panic("fixture export requires -check")
	}
	if runtime.GOOS != "darwin" {
		panic("requires the native Mac reference host")
	}
	root, err := os.MkdirTemp("", "codesign-sideband-")
	must(err)
	defer os.RemoveAll(root)
	// Native diagnostics spell the physical path (/private/var rather than
	// /var on this host). Resolve only our private root before forming fixtures.
	root, err = filepath.EvalSymlinks(root)
	must(err)
	template := filepath.Join(root, "template")
	must(os.Mkdir(template, 0700))
	source := "testdata/removal/unsigned-arm64.macho"
	input := read(source)
	must(os.WriteFile(filepath.Join(template, "tool"), input, 0755))
	app := filepath.Join(template, "Probe.app")
	must(os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0755))
	must(os.MkdirAll(filepath.Join(app, "Contents", "Resources"), 0755))
	must(os.WriteFile(filepath.Join(app, "Contents", "MacOS", "tool"), input, 0755))
	must(os.WriteFile(filepath.Join(app, "Contents", "Resources", "data"), []byte("resource\n"), 0644))
	plist := []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>test.sideband</string><key>CFBundleExecutable</key><string>tool</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string></dict></plist>`)
	must(os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), plist, 0644))
	var signing []invocation
	for _, operand := range []string{"tool", "Probe.app"} {
		v := invoke(template, "/usr/bin/codesign", "--sign", "-", "--timestamp=none", "--identifier", "test.sideband", operand)
		if v.Status != 0 {
			panic(v)
		}
		signing = append(signing, v)
	}
	policies := []struct {
		name string
		args []string
	}{
		{"default", nil},
		{"sideband", []string{"--strict=sideband"}},
		{"all", []string{"--strict=all"}},
		{"ignore-resources", []string{"--strict=sideband", "--ignore-resources"}},
		{"no-strict", []string{"--strict=sideband", "--no-strict"}},
		{"strip", []string{"--strict=sideband", "--strip-disallowed-xattrs"}},
		{"strip-dry-run", []string{"--strict=sideband", "--strip-disallowed-xattrs", "--dryrun"}},
	}
	var cases []map[string]any
	var captures []map[string]any
	var failures []string
	executed, unavailable := 0, 0
	for _, location := range []struct{ name, operand, path string }{
		{"standalone", "tool", "tool"},
		{"bundle-root", "Probe.app", "Probe.app"},
		{"executable", "Probe.app", "Probe.app/Contents/MacOS/tool"},
		{"resource", "Probe.app", "Probe.app/Contents/Resources/data"},
		{"signature-directory", "Probe.app", "Probe.app/Contents/_CodeSignature"},
	} {
		for _, state := range []string{"clean", "empty-control", "empty-fork", "fork", "zero-finder", "finder", "both"} {
			for _, policy := range policies {
				dir := filepath.Join(root, "case")
				copyTree(template, dir)
				path := filepath.Join(dir, filepath.FromSlash(location.path))
				setupError := ""
				set := func(name string, data []byte) {
					err := unix.Lsetxattr(path, name, data, 0)
					if name == names[0] && (location.name == "bundle-root" || location.name == "signature-directory") && errors.Is(err, unix.EPERM) {
						setupError = "directory ResourceFork fixture: " + err.Error()
						return
					}
					must(err)
				}
				set(names[2], []byte("keep"))
				switch state {
				case "empty-control":
					set(names[2], nil)
				case "empty-fork":
					set(names[0], nil)
				case "zero-finder":
					set(names[1], make([]byte, 32))
				case "fork", "finder", "both":
					if state != "finder" {
						set(names[0], []byte("fork"))
					}
					if state != "fork" {
						set(names[1], append([]byte("TEXTttxt"), make([]byte, 24)...))
					}
				}
				before := snapshot(dir)
				if setupError != "" {
					unavailable++
					cases = append(cases, map[string]any{"location": location.name, "attribute_state": state, "policy": policy.name, "unavailable": setupError, "before": before})
					must(os.RemoveAll(dir))
					continue
				}
				args := append([]string{"--verify", "--verbose=4"}, policy.args...)
				v := invoke(dir, "/usr/bin/codesign", append(args, location.operand)...)
				// Inspect the exact held object, then an explicit snapshot with
				// a clean native object. The latter is the same portable path used
				// on Linux and Windows, without restoring or deleting attributes.
				attrs := before[location.path].Attrs
				carrier := capturedCarrier(attrs)
				observed := inspectAdapter(path, nil)
				transported := inspectAdapter(filepath.Join(template, "tool"), bytes.NewReader(carrier))
				var expectedNames []string
				for _, name := range names[:2] {
					if len(attrs[name]) > 0 {
						expectedNames = append(expectedNames, name)
					}
				}
				after := snapshot(dir)
				executed++
				cases = append(cases, map[string]any{"location": location.name, "attribute_state": state, "policy": policy.name, "invocation": v, "before": before, "after": after,
					"adapter_native": observed, "adapter_appledouble": transported, "appledouble_hex": hex.EncodeToString(carrier)})
				if policy.name == "sideband" {
					captures = append(captures, map[string]any{"location": location.name, "attribute_state": state,
						"attrs_hex": attrs, "appledouble_hex": hex.EncodeToString(carrier), "native_status": v.Status,
						"native_stdout": strings.ReplaceAll(v.Stdout, dir, "$FIXTURE"), "native_stderr": v.Stderr})
				}
				if *check {
					if !reflect.DeepEqual(observed, expectedNames) || !reflect.DeepEqual(transported, expectedNames) {
						failures = append(failures, "adapter/"+location.name+"/"+state+"/"+policy.name)
					}
					status, stdout := 0, ""
					scope := ""
					if policy.name == "ignore-resources" {
						scope = " (not all contents verified)"
					}
					stderr := fmt.Sprintf("%s: valid on disk%s\n%s: satisfies its Designated Requirement\n", location.operand, scope, location.operand)
					prohibited := state == "fork" || state == "finder" || state == "both"
					if prohibited && location.name != "signature-directory" && policy.name != "default" && policy.name != "no-strict" && !(location.name == "resource" && policy.name == "ignore-resources") {
						status = 1
						stderr = location.operand + ": resource fork, Finder information, or similar detritus not allowed\n"
						attrs := []string{names[0]}
						if state == "finder" {
							attrs = []string{names[1]}
						} else if state == "both" && location.name == "resource" {
							attrs = names[:2]
						}
						for _, attr := range attrs {
							stdout += fmt.Sprintf("file with invalid attached data: Disallowed xattr %s found on %s\n", attr, path)
						}
					}
					if v.Status != status || v.Stdout != stdout || v.Stderr != stderr || !reflect.DeepEqual(before, after) {
						failures = append(failures, location.name+"/"+state+"/"+policy.name)
					}
				}
				must(os.RemoveAll(dir))
			}
		}
	}
	report := map[string]any{
		"schema": 2, "scope": "Native observations plus held-object/explicit-AppleDouble metadata adapter comparisons on fresh ad-hoc arm64 standalone/app fixtures; not full Go CLI, traversal, ACL, link, compression, signing or failure-ordering parity.",
		"go": runtime.Version(), "host": invoke("", "/usr/bin/sw_vers"), "codesign_sha256": hash(read("/usr/bin/codesign")),
		"driver_sha256": hash(read("scripts/probe-sideband.go")), "input_sha256": map[string]string{source: hash(input)}, "signing": signing, "cases": cases,
		"checked": *check, "executed": executed, "unavailable": unavailable, "failures": failures,
	}
	b, err := json.MarshalIndent(report, "", "  ")
	must(err)
	must(os.MkdirAll("artifacts/sideband", 0755))
	must(os.WriteFile("artifacts/sideband/native.json", append(b, '\n'), 0644))
	// Retain a compact status/diagnostic summary for review alongside the full
	// before/after byte and attribute snapshots in the ignored evidence artifact.
	for _, c := range cases {
		if unavailable, ok := c["unavailable"]; ok {
			fmt.Printf("%s/%s/%s: NOT EXECUTED: %s\n", c["location"], c["attribute_state"], c["policy"], unavailable)
			continue
		}
		v := c["invocation"].(invocation)
		fmt.Printf("%s/%s/%s: %d %s\n", c["location"], c["attribute_state"], c["policy"], v.Status, strings.ReplaceAll(strings.TrimSpace(v.Stderr), "\n", " | "))
	}
	if *check && (executed != 203 || unavailable != 42 || len(failures) != 0) {
		panic(fmt.Sprintf("native sideband profile mismatch: executed=%d unavailable=%d failures=%v; raw evidence retained", executed, unavailable, failures))
	}
	if *fixtures != "" {
		capture := map[string]any{"schema": 1, "scope": report["scope"], "host": report["host"], "codesign_sha256": report["codesign_sha256"],
			"driver_sha256": report["driver_sha256"], "input_sha256": report["input_sha256"], "cases": captures}
		data, err := json.MarshalIndent(capture, "", "  ")
		must(err)
		data = append(data, '\n')
		must(os.MkdirAll(*fixtures, 0755))
		must(os.WriteFile(filepath.Join(*fixtures, "policy.json"), data, 0644))
		manifest, err := json.MarshalIndent(map[string]any{"files": map[string]string{"policy.json": hash(data)}}, "", "  ")
		must(err)
		must(os.WriteFile(filepath.Join(*fixtures, "manifest.json"), append(manifest, '\n'), 0644))
	}
}
