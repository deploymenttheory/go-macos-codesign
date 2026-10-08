package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Generic removal is deliberately nontransactional: an attribute-list denial
// follows the fixed slot removals. Bundle discovery adds its own earlier query.
func TestGenericRemovalNativePermissions(t *testing.T) {
	for _, shape := range []string{"text", "object", "app", "framework"} {
		for _, right := range []string{"read", "write", "readextattr", "writeextattr", "writeattr", "delete"} {
			for _, state := range []string{"clean", "populated"} {
				t.Run(shape+"/"+right+"/"+state, func(t *testing.T) {
					dir := extractionDirectory(t)
					metadata := genericMetadata(state)
					type observation struct {
						Result              genericRemovalResult
						ACLBefore, ACLAfter removalACLObservation
					}
					var seen []observation
					for _, exe := range []string{apple(t), binaryPath} {
						operand, target, bundle := genericFixture(t, dir, shape)
						setSidebandObject(t, target, metadata)
						before := nativeRead(t, target)
						original := accessFileInfo(t, target)
						mustRun(t, "/bin/chmod", "+a", "everyone deny "+right, target)
						t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-RN", dir).Run() })
						aclBefore := removalACL(t, target)
						out, stderr, status := run(t, exe, "--remove-signature", operand)
						aclAfter := removalACL(t, target)
						mustRun(t, "/bin/chmod", "-RN", dir)
						nativeEqual(t, "generic denied data fork", nativeRead(t, target), before)
						attrs := genericAttrs(t, target, metadata, "")
						r := genericRemovalResult{Status: status, Out: out, Err: stderr, Data: hash(signingSidebandBytes(t, operand, bundle)), Attrs: attrs, SameFile: os.SameFile(original, accessFileInfo(t, target)), Platform: "darwin"}
						if !r.SameFile || aclBefore != aclAfter {
							t.Fatalf("identity/ACL changed: %#v %#v %#v", r, aclBefore, aclAfter)
						}
						if status != 0 && (status != 1 || out != "" || stderr != operand+": Permission denied\n") {
							t.Fatalf("unexpected diagnostic %#v", r)
						}
						// Assert the native failure boundary independently, then compare candidates.
						if !bundle && right == "readextattr" && state == "populated" {
							for _, name := range genericSlots[:12] {
								if _, ok := attrs["com.apple.cs."+name]; ok {
									t.Fatal("canonical slot survives list failure", name)
								}
							}
							if _, ok := attrs["com.apple.cs.Unknown"]; !ok {
								t.Fatal("unknown slot removed before failed listing")
							}
						}
						if right == "writeattr" || right == "delete" {
							if status != 0 {
								t.Fatal("irrelevant denial blocked removal", r)
							}
						}
						if status == 0 {
							for name := range attrs {
								if strings.HasPrefix(name, "com.apple.cs.") {
									t.Fatal("signature attribute remains", name)
								}
							}
						}
						seen = append(seen, observation{r, aclBefore, aclAfter})
						if err := os.RemoveAll(operand); err != nil {
							t.Fatal(err)
						}
					}
					if !reflect.DeepEqual(seen[0], seen[1]) {
						t.Fatalf("native %#v; Go %#v", seen[0], seen[1])
					}
					attest(t, map[string]any{"native": seen[0], "go": seen[1]})
				})
			}
		}
	}
}

func TestGenericRemovalNativeSignedScript(t *testing.T) {
	dir := extractionDirectory(t)
	operand, target, _ := genericFixture(t, dir, "script")
	mustRun(t, apple(t), "--sign", "-", "--identifier", "org.example.generic", operand)
	before := nativeRead(t, target)
	original := accessFileInfo(t, target)
	attrs := sidebandObjectAttrs(t, target)
	if _, ok := attrs["com.apple.cs.CodeDirectory"]; !ok {
		t.Fatal("native signing did not produce an attached signature")
	}
	mustRun(t, binaryPath, "--remove-signature", operand)
	nativeEqual(t, "native signed script", nativeRead(t, target), before)
	if !os.SameFile(original, accessFileInfo(t, target)) {
		t.Fatal("script replaced")
	}
	for name := range sidebandObjectAttrs(t, target) {
		if strings.HasPrefix(name, "com.apple.cs.") {
			t.Fatal("signature remains", name)
		}
	}
	out, stderr, status := run(t, apple(t), "--verify", operand)
	if status != 1 || out != "" || stderr != operand+": code object is not signed at all\n" {
		t.Fatalf("native verify %d %q %q", status, out, stderr)
	}
	attest(t, map[string]any{"path": filepath.Base(operand), "before_attributes": attrs, "verify_status": status, "verify_stderr": stderr})
}
