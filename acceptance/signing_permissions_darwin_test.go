package acceptance

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// Real ACLs distinguish EACCES from the EPERM ignored by Apple's presence query.
// Each implementation receives a fresh identical operand at the same pathname.
func TestSigningNativePermissions(t *testing.T) {
	for _, shape := range []string{"arm64", "x86_64", "universal", "app-root", "app-main", "app-resource", "framework-main", "framework-resource", "recursive-child-main"} {
		for _, deny := range []string{"readextattr", "writeextattr", "write", "readattr"} {
			for _, state := range []string{"finder", "fork", "both"} {
				if shape == "app-root" && state != "finder" {
					continue
				} // Darwin directories have no ResourceFork.
				for _, policy := range []string{"default", "strip", "dryrun", "no-strict"} {
					t.Run(shape+"/"+deny+"/"+state+"/"+policy, func(t *testing.T) {
						dir := extractionDirectory(t)
						type observation struct {
							out, stderr  string
							status       int
							before, data []byte
							attrs        map[string]string
							replaced     bool
						}
						var results []observation
						var evidence []map[string]any
						for _, exe := range []string{apple(t), binaryPath} {
							operand, target := filepath.Join(dir, "tool"), filepath.Join(dir, "tool")
							bundle := strings.Contains(shape, "-")
							if bundle {
								kind, location, _ := strings.Cut(shape, "-")
								var paths map[string]string
								operand, paths = sidebandBundleFixture(t, dir, kind)
								target = paths[location]
							} else {
								copyFixture(t, "unsigned-"+shape, target)
							}
							metadata := appledouble.File{Attrs: []appledouble.Attr{{Name: "user.codesign-control", Value: []byte("keep")}}}
							if state != "fork" {
								metadata.FinderInfo[0] = 1
							}
							if state != "finder" {
								metadata.ResourceFork = []byte("fork")
							}
							setSidebandObject(t, target, metadata)
							before := signingSidebandBytes(t, operand, bundle)
							attrsBefore := sidebandObjectAttrs(t, target)
							infoBefore := accessFileInfo(t, target)
							mustRun(t, "/bin/chmod", "+a", "everyone deny "+deny, target)
							t.Cleanup(func() {
								if _, err := os.Lstat(target); err == nil {
									mustRun(t, "/bin/chmod", "-N", target)
								}
							})
							args := []string{"-fs", "-", "-i", "org.example.permissions", "--deep"}
							if policy != "default" {
								args = append(args, "--strip-disallowed-xattrs")
							}
							if policy == "dryrun" {
								args = append(args, "--dryrun")
							}
							if policy == "no-strict" {
								args = append(args, "--no-strict")
							}
							out, stderr, status := run(t, exe, append(args, operand)...)
							mustRun(t, "/bin/chmod", "-N", target)
							after := signingSidebandBytes(t, operand, bundle)
							attrsAfter := sidebandObjectAttrs(t, target)
							// Before/after evidence includes all attributes, with an explicit control
							// assertion independent of the differential comparison.
							if attrsAfter["user.codesign-control"] != attrsBefore["user.codesign-control"] {
								t.Fatal("unrelated attribute changed")
							}
							if policy == "dryrun" && !bytes.Equal(before, after) {
								t.Fatal("dry run changed code bytes")
							}
							replaced := !os.SameFile(infoBefore, accessFileInfo(t, target))
							results = append(results, observation{out, stderr, status, before, after, attrsAfter, replaced})
							evidence = append(evidence, map[string]any{"executable": exe, "args": append(args, operand), "status": status, "stdout": out, "stderr": stderr, "attrs_before": attrsBefore, "attrs_after": attrsAfter, "bytes_before": hash(before), "bytes_after": hash(after), "object_replaced": replaced})
							if err := os.RemoveAll(operand); err != nil {
								t.Fatal(err)
							}
						}
						n, g := results[0], results[1]
						record := map[string]any{"native": evidence[0], "go": evidence[1]}
						defer attest(t, record)
						nativeEqual(t, "permission initial bytes", g.before, n.before)
						if n.status != g.status || n.out != g.out || n.stderr != g.stderr {
							t.Fatalf("native %d %q %q; Go %d %q %q", n.status, n.out, n.stderr, g.status, g.out, g.stderr)
						}
						if n.status != 0 && policy != "dryrun" && strings.HasSuffix(shape, "-resource") {
							kind, _, _ := strings.Cut(shape, "-")
							// Compare complete independent workers against an actual successful
							// Apple signing control. A failed resource must leave every other
							// member unchanged; only whole independent code may have committed.
							operand, _ := sidebandBundleFixture(t, dir, kind)
							mustRun(t, apple(t), "-fs", "-", "-i", "org.example.permissions", "--deep", "--no-strict", operand)
							completed := signingSidebandBytes(t, operand, true)
							independent := "Contents/Helpers/tool"
							if kind == "framework" {
								independent = "Versions/A/Helpers/tool;Versions/A/helper"
							}
							record["independent_children"] = independent
							record["native_completion_control"] = executableDirectoryManifest(t, completed)
							record["native_manifest"] = executableDirectoryManifest(t, n.data)
							record["go_manifest"] = executableDirectoryManifest(t, g.data)
							signingSidebandPartial(t, n.before, completed, n.data, independent, true)
							signingSidebandPartial(t, g.before, completed, g.data, independent, false)
						} else {
							nativeEqual(t, "permission bytes", g.data, n.data)
						}
						if !maps.Equal(n.attrs, g.attrs) || n.replaced != g.replaced {
							t.Fatalf("native attributes %v replaced=%t; Go %v replaced=%t", n.attrs, n.replaced, g.attrs, g.replaced)
						}
					})
				}
			}
		}
	}
}
