package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type removalACLObservation struct {
	Status         int
	Entries, Error string
}

func removalACL(t *testing.T, path string) removalACLObservation {
	t.Helper()
	out, stderr, status := run(t, "/bin/ls", "-lde", path)
	// Drop the file-stat header (timestamps); retain every canonical ACL line.
	// Read-security/attribute denials may prohibit ACL observation itself. Retain
	// that exact error and status rather than inventing an absent ACL.
	_, entries, _ := strings.Cut(out, "\n")
	return removalACLObservation{status, entries, stderr}
}

// These rights deny different metadata/data operations. Shallow removal must
// preserve every unrelated inode, ACL observation and byte while removing the
// outer seal. No resource permission is lifted until the operation has finished.
func TestRemovalNativeResourcePermissions(t *testing.T) {
	for _, shape := range removalResourceShapes {
		for _, right := range []string{"read", "readattr", "readsecurity", "readextattr", "writeextattr"} {
			t.Run(shape+"/"+right, func(t *testing.T) {
				dir := extractionDirectory(t)
				type observation struct {
					Status              int
					Out, Err            string
					ACLBefore, ACLAfter removalACLObservation
					Replaced            bool
				}
				var seen []observation
				var data [][]byte
				var evidence []map[string]any
				for _, exe := range []string{apple(t), binaryPath} {
					operand, _, target := removalResourceFixture(t, dir, shape)
					before := layoutArchive(t, operand)
					original := accessFileInfo(t, target)
					mustRun(t, "/bin/chmod", "+a", "everyone deny "+right, target)
					t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-RN", dir).Run() })
					aclBefore := removalACL(t, target)
					out, stderr, status := run(t, exe, "--remove-signature", operand)
					aclAfter := removalACL(t, target)
					mustRun(t, "/bin/chmod", "-RN", dir)
					after := layoutArchive(t, operand)
					o := observation{status, out, stderr, aclBefore, aclAfter, !os.SameFile(original, accessFileInfo(t, target))}
					if status != 0 || out != "" || stderr != "" || o.Replaced || aclBefore != aclAfter {
						t.Fatalf("%s removal: %#v", exe, o)
					}
					seen = append(seen, o)
					data = append(data, after)
					evidence = append(evidence, map[string]any{"executable": exe, "target": target, "observation": o, "before": hash(before), "after": hash(after)})
					if err := os.RemoveAll(operand); err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(seen[0], seen[1]) {
					t.Fatalf("native %#v; Go %#v", seen[0], seen[1])
				}
				nativeEqual(t, "resource-denied removal", data[1], data[0])
				attest(t, map[string]any{"native": evidence[0], "go": evidence[1]})
			})
		}
	}
}

// An unreadable selected executable, unlike an unreadable resource, must fail
// before replacement or signature-directory cleanup. Metadata-read checks from
// bundle construction apply to removal too.
func TestRemovalNativeExecutablePermissions(t *testing.T) {
	for _, shape := range []string{"arm64", "x86_64", "universal", "app", "app-universal", "framework", "flat-framework", "recursive"} {
		for _, right := range []string{"read", "readextattr"} {
			t.Run(shape+"/"+right, func(t *testing.T) {
				dir := extractionDirectory(t)
				bundle := shape != "arm64" && shape != "x86_64" && shape != "universal"
				var evidence []map[string]any
				for _, exe := range []string{apple(t), binaryPath} {
					operand := filepath.Join(dir, "tool")
					target := operand
					if bundle {
						var paths map[string]string
						operand, paths = sidebandBundleFixture(t, dir, shape)
						target = paths["main"]
					} else {
						copyFixture(t, "adhoc-"+shape, target)
					}
					before := signingSidebandBytes(t, operand, bundle)
					original := accessFileInfo(t, target)
					mustRun(t, "/bin/chmod", "+a", "everyone deny "+right, target)
					t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-RN", dir).Run() })
					out, stderr, status := run(t, exe, "--remove-signature", operand)
					mustRun(t, "/bin/chmod", "-RN", dir)
					after := signingSidebandBytes(t, operand, bundle)
					if status != 1 || out != "" || stderr != operand+": Permission denied\n" {
						t.Fatalf("%s: %d %q %q", exe, status, out, stderr)
					}
					nativeEqual(t, "failed removal preserves complete operand", after, before)
					if !os.SameFile(original, accessFileInfo(t, target)) {
						t.Fatal("failed preflight replaced executable")
					}
					evidence = append(evidence, map[string]any{"executable": exe, "args": []string{"--remove-signature", operand}, "status": status, "stdout": out, "stderr": stderr, "before": hash(before), "after": hash(after)})
					if err := os.RemoveAll(operand); err != nil {
						t.Fatal(err)
					}
				}
				attest(t, map[string]any{"native": evidence[0], "go": evidence[1]})
			})
		}
	}
}
