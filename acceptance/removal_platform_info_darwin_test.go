package acceptance

import (
	"maps"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRemovalPlatformInfoNativePermissions(t *testing.T) {
	for _, original := range platformInfoCases(t) {
		if original.State != "both" {
			continue
		}
		for _, right := range []string{"read", "readattr", "readsecurity", "readextattr", "write", "writeextattr"} {
			t.Run(original.Shape+"/"+right, func(t *testing.T) {
				tc := original
				tc.Files = maps.Clone(tc.Files)
				selected := tc.Main
				if right == "read" {
					selected = strings.TrimSuffix(selected, "platform") + "normal"
				}
				if right == "readattr" {
					selected = ""
					tc.Status, tc.Output, tc.Envelope = 1, "$BUNDLE: bundle format is ambiguous (could be app or framework)\n", true
				}
				for name, want := range tc.Files {
					want.Signature = name != selected
					tc.Files[name] = want
				}
				tc.BeforeRun = func(t *testing.T, operand string) func() {
					path := filepath.Join(operand, strings.TrimSuffix(tc.Info, ".plist")+"-macos.plist")
					mustRun(t, "/bin/chmod", "+a", "everyone deny "+right, path)
					t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
					before := removalACL(t, path)
					return func() {
						after := removalACL(t, path)
						if before != after {
							t.Fatal("platform plist ACL changed", before, after)
						}
						attest(t, map[string]any{"right": right, "acl_before": before, "acl_after": after})
						mustRun(t, "/bin/chmod", "-N", path)
					}
				}
				native := observeEmptyInfo(t, apple(t), tc, false)
				local := observeEmptyInfo(t, binaryPath, tc, false)
				carrier := observeEmptyInfo(t, binaryPath, tc, true)
				if !reflect.DeepEqual(native, local) || !reflect.DeepEqual(native, carrier) {
					t.Fatalf("native %#v; Go %#v; carrier %#v", native, local, carrier)
				}
				attest(t, map[string]any{"native": native, "go": local, "carrier": carrier})
			})
		}
	}
}
