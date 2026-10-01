//go:build ignore

// Research only: retain native ACL inheritance and failure-artifact observations.
// Run from the repository root on macOS. An optional -candidate CLI is observed
// at the same fresh operand path. Differences are evidence, not parity claims.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func run(name string, args ...string) (string, int) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if e, ok := err.(*exec.ExitError); ok {
		return string(out), e.ExitCode()
	}
	panic(err)
}
func chmod(args ...string) {
	out, status := run("/bin/chmod", args...)
	if status != 0 {
		panic(out)
	}
}
func acl(path string) any {
	f, err := os.Open(path)
	if err != nil {
		return err.Error()
	}
	defer f.Close()
	m, err := hostdata.NewHeldMetadata(f)
	if err != nil {
		return err.Error()
	}
	a, err := m.CaptureACL()
	if err != nil {
		return err.Error()
	}
	return a.Security.ACL
}
func snapshot(root string) map[string]string {
	result := map[string]string{}
	must(filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(rel)] = digest(data)
		return nil
	}))
	return result
}
func main() {
	candidate := flag.String("candidate", "", "optional Go codesign binary to observe alongside native")
	flag.Parse()
	executables := []string{"/usr/bin/codesign"}
	if *candidate != "" {
		executables = append(executables, *candidate)
	}
	native, err := os.ReadFile(executables[0])
	must(err)
	host, status := run("/usr/bin/sw_vers")
	if status != 0 {
		panic(host)
	}
	var cases []map[string]any
	for _, shape := range []string{"standalone", "app-main", "app-resource"} {
		for _, policy := range []struct{ name, parent, source string }{
			{"writeattr", "", "everyone deny writeattr"},
			{"writesecurity", "", "everyone deny writesecurity"},
			{"append", "", "everyone deny append"},
			{"readsecurity", "", "everyone deny readsecurity"},
			{"delete", "", "everyone deny delete"},
			{"parent-inherit", "everyone allow read,file_inherit", ""},
			{"explicit-and-inherited", "everyone allow read,file_inherit", "everyone deny write"},
		} {
			for _, operation := range []string{"resign", "dryrun", "remove"} {
				dir, err := os.MkdirTemp("", "codesign-security-probe-")
				must(err)
				func() {
					defer func() { chmod("-RN", dir); must(os.RemoveAll(dir)) }()
					var observations []map[string]any
					for _, exe := range executables {
						root := filepath.Join(dir, "input")
						must(os.Mkdir(root, 0700))
						operand := filepath.Join(root, "tool")
						target := operand
						if shape == "standalone" {
							data, err := os.ReadFile("testdata/macho/adhoc-arm64")
							must(err)
							must(os.WriteFile(operand, data, 0755))
						} else {
							operand = filepath.Join(root, "Fixture.app")
							must(os.CopyFS(operand, os.DirFS("testdata/bundles/arm64.app")))
							target = filepath.Join(operand, "Contents/MacOS/hello")
							if shape == "app-resource" {
								target = filepath.Join(operand, "Contents/Resources/message.txt")
							}
						}
						before := snapshot(root)
						if policy.parent != "" {
							chmod("+a", policy.parent, filepath.Dir(target))
						}
						if policy.source != "" {
							chmod("+a", policy.source, target)
						}
						aclBefore := acl(target)
						args := []string{"-fs", "-", "-i", "org.example.security"}
						if operation == "dryrun" {
							args = append(args, "--dryrun")
						}
						if operation == "remove" {
							args = []string{"--remove-signature"}
						}
						output, status := run(exe, append(args, operand)...)
						aclAfter := acl(target)
						// Preserve ACL observations before clearing restrictions for complete
						// byte/path inspection, including failed temporary replacements.
						chmod("-RN", root)
						observations = append(observations, map[string]any{"executable": exe, "status": status, "output": strings.ReplaceAll(output, dir, "$PROBE"), "acl_before": aclBefore, "acl_after": aclAfter, "before": before, "after": snapshot(root)})
						must(os.RemoveAll(root))
					}
					cases = append(cases, map[string]any{"shape": shape, "policy": policy.name, "operation": operation, "observations": observations})
				}()
			}
		}
	}
	result := map[string]any{"macos": host, "native_sha256": digest(native), "note": "Exploratory observations, including known unqualified differences; no expected outputs are rewritten.", "cases": cases}
	data, err := json.MarshalIndent(result, "", "  ")
	must(err)
	fmt.Println(string(data))
}
