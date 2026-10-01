package acceptance

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func signingSecurityACL(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := hostdata.NewHeldMetadata(f)
	if err != nil {
		return "capture error: " + err.Error()
	}
	acl, err := m.CaptureACL()
	if err != nil {
		return "capture error: " + err.Error()
	}
	b, err := json.Marshal(acl.Security.ACL)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Final security is part of the observable result, including failed commits.
// Every operand is recreated at the same path before the next implementation.
func TestSigningNativeSecurity(t *testing.T) {
	for _, shape := range []string{"arm64", "x86_64", "universal", "app-main", "app-resource", "framework-main", "framework-resource", "recursive-child-main"} {
		for _, right := range []string{"writeattr", "writesecurity", "append"} {
			for _, operation := range []string{"resign", "dryrun", "remove"} {
				t.Run(shape+"/"+right+"/"+operation, func(t *testing.T) {
					dir := extractionDirectory(t)
					bundle := strings.Contains(shape, "-")
					type observation struct {
						Status                              int
						Stdout, Stderr, ACLBefore, ACLAfter string
						Attrs                               map[string]string
						Replaced                            bool
					}
					var observations []observation
					var data [][]byte
					var evidence []map[string]any
					for _, exe := range []string{apple(t), binaryPath} {
						operand := filepath.Join(dir, "tool")
						target := operand
						if bundle {
							kind, location, _ := strings.Cut(shape, "-")
							var paths map[string]string
							operand, paths = sidebandBundleFixture(t, dir, kind)
							target = paths[location]
						} else {
							copyFixture(t, "adhoc-"+shape, target)
						}
						before := signingSidebandBytes(t, operand, bundle)
						info := accessFileInfo(t, target)
						mustRun(t, "/bin/chmod", "+a", "everyone deny "+right, target)
						t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-RN", dir).Run() })
						aclBefore := signingSecurityACL(t, target)
						args := []string{"-fs", "-", "-i", "org.example.security", "--deep"}
						if operation == "dryrun" {
							args = append(args, "--dryrun")
						}
						if operation == "remove" {
							args = []string{"--remove-signature"}
						}
						out, stderr, status := run(t, exe, append(args, operand)...)
						aclAfter := signingSecurityACL(t, target)
						after := signingSidebandBytes(t, operand, bundle)
						observed := observation{status, out, stderr, aclBefore, aclAfter, sidebandObjectAttrs(t, target), !os.SameFile(info, accessFileInfo(t, target))}
						observations = append(observations, observed)
						data = append(data, after)
						evidence = append(evidence, map[string]any{"executable": exe, "args": append(args, operand), "observation": observed, "before": hash(before), "after": hash(after)})
						if operation == "dryrun" && !bytes.Equal(before, after) {
							t.Fatal("dry run changed code")
						}
						mustRun(t, "/bin/chmod", "-RN", dir)
						if err := os.RemoveAll(operand); err != nil {
							t.Fatal(err)
						}
					}
					attest(t, map[string]any{"native": evidence[0], "go": evidence[1]})
					if !reflect.DeepEqual(observations[0], observations[1]) {
						t.Fatalf("native %#v; Go %#v", observations[0], observations[1])
					}
					nativeEqual(t, "security complete operand", data[1], data[0])
				})
			}
		}
	}
}
