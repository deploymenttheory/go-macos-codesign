package acceptance

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// Rooted stat must decide discovery before opening data. Metadata authorization
// failures select Info.plist; read/readextattr failures on a selected executable
// must fail without redirecting signature removal to the plist.
func TestRemovalFallbackNativeDiscoveryPermissions(t *testing.T) {
	for _, shape := range []string{"app", "framework", "flat-framework"} {
		for _, right := range []string{"readattr", "readsecurity", "read", "readextattr"} {
			t.Run(shape+"/"+right, func(t *testing.T) {
				dir := extractionDirectory(t)
				type result struct {
					Status              int
					Out, Err, Tree      string
					Main, Info          map[string]string
					MainSame, InfoSame  bool
					ACLBefore, ACLAfter removalACLObservation
				}
				var observations []result
				for _, exe := range []string{apple(t), binaryPath} {
					operand, paths := sidebandBundleFixture(t, dir, shape)
					metadata := genericMetadata("populated")
					setSidebandObject(t, paths["main"], metadata)
					setSidebandObject(t, paths["info"], metadata)
					mainBytes := nativeRead(t, paths["main"])
					infoBytes := nativeRead(t, paths["info"])
					mainInfo := accessFileInfo(t, paths["main"])
					infoInfo := accessFileInfo(t, paths["info"])
					beforeMain := genericAttrs(t, paths["main"], metadata, "")
					beforeInfo := genericAttrs(t, paths["info"], metadata, "")
					mustRun(t, "/bin/chmod", "+a", "everyone deny "+right, paths["main"])
					t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-RN", dir).Run() })
					aclBefore := removalACL(t, paths["main"])
					out, stderr, status := run(t, exe, "--remove-signature", operand)
					aclAfter := removalACL(t, paths["main"])
					mustRun(t, "/bin/chmod", "-RN", dir)
					nativeEqual(t, "unselected executable data", nativeRead(t, paths["main"]), mainBytes)
					nativeEqual(t, "plist data", nativeRead(t, paths["info"]), infoBytes)
					got := result{status, out, stderr, hash(layoutArchive(t, operand)), genericAttrs(t, paths["main"], metadata, ""), genericAttrs(t, paths["info"], metadata, ""), os.SameFile(mainInfo, accessFileInfo(t, paths["main"])), os.SameFile(infoInfo, accessFileInfo(t, paths["info"])), aclBefore, aclAfter}
					if !got.MainSame || !got.InfoSame || aclBefore != aclAfter || !reflect.DeepEqual(got.Main, beforeMain) {
						t.Fatal("unselected data or security changed", got)
					}
					fallback := right == "readattr" || right == "readsecurity"
					if fallback {
						if status != 0 || out != "" || stderr != "" {
							t.Fatal("metadata denial did not select fallback", got)
						}
						for n := range got.Info {
							if strings.HasPrefix(n, "com.apple.cs.") {
								t.Fatal("plist signature retained", n)
							}
						}
						_, err := os.Stat(paths["signature"])
						if !os.IsNotExist(err) {
							t.Fatal("envelope retained", err)
						}
					} else {
						if status != 1 || out != "" || stderr != operand+": Permission denied\n" || !reflect.DeepEqual(got.Info, beforeInfo) {
							t.Fatal("read error redirected removal", got)
						}
						if _, err := os.Stat(paths["signature"]); err != nil {
							t.Fatal("envelope changed after read error", err)
						}
					}
					observations = append(observations, got)
					if err := os.RemoveAll(operand); err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(observations[0], observations[1]) {
					t.Fatalf("native %#v; Go %#v", observations[0], observations[1])
				}
				attest(t, map[string]any{"native": observations[0], "go": observations[1]})
			})
		}
	}
}
