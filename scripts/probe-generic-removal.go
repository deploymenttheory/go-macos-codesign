//go:build ignore

// Capture native generic-removal and partial-failure evidence. No signing key
// or keychain is accessed. Run from the repository root on macOS.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func read(p string) []byte   { b, e := os.ReadFile(p); must(e); return b }
func main() {
	names := []string{"CodeDirectory", "CodeRequirements", "CodeResources", "CodeTopDirectory", "CodeEntitlements", "CodeRepSpecific", "CodeEntitlementDER", "LaunchConstraintSelf", "LaunchConstraintParent", "LaunchConstraintResponsible", "LibraryConstraint", "CodeSignature", "CodeRequirements-1", "Unknown"}
	base, e := os.MkdirTemp("", "generic-probe-")
	must(e)
	defer os.RemoveAll(base)
	m := read("testdata/macho/adhoc-arm64")
	obj := append([]byte{}, m...)
	binary.LittleEndian.PutUint32(obj[12:], 1)
	data := [][]byte{nil, []byte("hello"), []byte("#!/bin/sh\nexit 0\n"), m[:4], m[:27], m[:32], obj, m}
	shapes := []string{"empty", "text", "script", "short-magic", "short-header", "truncated-macho", "object", "macho"}
	var cases []map[string]any
	for i, shape := range shapes {
		for _, deny := range []string{"", "readextattr", "writeextattr", "write", "read"} {
			p := filepath.Join(base, "input")
			must(os.WriteFile(p, data[i], 0755))
			f, e := os.Open(p)
			must(e)
			before := map[string]string{}
			for _, n := range names {
				name := "com.apple.cs." + n
				value := []byte(n)
				must(hostdata.SetXattr(f, name, value))
				before[name] = hex.EncodeToString(value)
			}
			must(f.Close())
			if deny != "" {
				o, e := exec.Command("/bin/chmod", "+a", "everyone deny "+deny, p).CombinedOutput()
				if e != nil {
					panic(string(o))
				}
			}
			o, e := exec.Command("/usr/bin/codesign", "--remove-signature", p).CombinedOutput()
			status := 0
			if e != nil {
				status = e.(*exec.ExitError).ExitCode()
			}
			must(exec.Command("/bin/chmod", "-N", p).Run())
			f, e = os.Open(p)
			must(e)
			after := map[string]string{}
			for n := range before {
				value, present, e := hostdata.ReadXattr(f, n, hostdata.MaxXattrReadSize)
				must(e)
				if present {
					after[n] = hex.EncodeToString(value)
				}
			}
			must(f.Close())
			cases = append(cases, map[string]any{"shape": shape, "denial": deny, "status": status, "output": strings.ReplaceAll(string(o), base, "$PROBE"), "before_attrs": before, "after_attrs": after, "before_sha256": digest(data[i]), "after_sha256": digest(read(p))})
			must(os.Remove(p))
		}
	}
	host, e := exec.Command("/usr/bin/sw_vers").Output()
	must(e)
	result := map[string]any{"schema": 1, "driver_sha256": digest(read("scripts/probe-generic-removal.go")), "fixture_sha256": digest(m), "native_sha256": digest(read("/usr/bin/codesign")), "macos": string(host), "cases": cases}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.MkdirAll("testdata/generic-removal", 0755))
	must(os.WriteFile("testdata/generic-removal/native.json", append(b, '\n'), 0644))
	fmt.Printf("captured %d native cases\n", len(cases))
}
