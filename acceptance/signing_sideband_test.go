package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestSigningSideband(t *testing.T) {
	for _, format := range []string{"arm64", "x86_64", "universal", "dmg", "app", "framework", "flat-framework", "recursive"} {
		locations := []string{"main"}
		if format == "app" || strings.Contains(format, "framework") {
			locations = []string{"root", "main", "resource", "info", "signature", "directory", "helper"}
		}
		if format == "framework" {
			locations = append(locations, "version-root")
		}
		if format == "recursive" {
			locations = []string{"child-root", "child-main", "child-resource", "grandchild-main"}
		}
		for _, location := range locations {
			states := []string{"clean", "finder", "fork", "both"}
			if location == "root" || location == "directory" || strings.HasSuffix(location, "-root") {
				states = []string{"clean", "finder"}
			}
			for _, state := range states {
				for _, policy := range []string{"default", "strip", "strip-dryrun", "no-strict", "strip-no-strict", "deep", "deep-strip", "already-strip"} {
					for _, transport := range []string{"native", "appledouble"} {
						t.Run(format+"/"+location+"/"+state+"/"+policy+"/"+transport, func(t *testing.T) {
							dir := extractionDirectory(t)
							var metadata appledouble.File
							if state == "finder" || state == "both" {
								copy(metadata.FinderInfo[:], "TEXTttxt")
							}
							if state == "fork" || state == "both" {
								metadata.ResourceFork = []byte("resource fork")
							}
							metadata.Attrs = []appledouble.Attr{{Name: "user.codesign-control", Value: []byte("preserve")}}
							var operand, target string
							bundle := format == "app" || format == "recursive" || strings.Contains(format, "framework")
							seed := func(native bool) {
								if bundle {
									var paths map[string]string
									operand, paths = sidebandBundleFixture(t, dir, format)
									target = paths[location]
								} else {
									fixture := "testdata/macho/adhoc-" + format
									if format == "dmg" {
										fixture = "testdata/dmg/native-adhoc-raw.dmg"
									}
									bundleWrite(t, dir, "fixture", nativeRead(t, filepath.Join(root, fixture)))
									operand, target = filepath.Join(dir, "fixture"), filepath.Join(dir, "fixture")
								}
								if native || transport == "native" {
									setSidebandObject(t, target, metadata)
								}
							}
							seed(false)
							args := []string{"--sign", "-", "--force", "--identifier", "org.example.sideband.signing"}
							strip := strings.Contains(policy, "strip")
							if strip {
								args = append(args, "--strip-disallowed-xattrs")
							}
							if strings.Contains(policy, "no-strict") {
								args = append(args, "--no-strict")
							}
							if strings.Contains(policy, "deep") {
								args = append(args, "--deep")
							}
							if policy == "strip-dryrun" {
								args = append(args, "--dryrun")
							}
							if policy == "already-strip" {
								args = append(args[:2], args[3:]...)
							}
							goArgs := append([]string{}, args...)
							carrierPath := filepath.Join(dir, "metadata.ad")
							if transport == "appledouble" {
								encoded, err := metadata.Encode()
								if err != nil {
									t.Fatal(err)
								}
								bundleWrite(t, dir, "metadata.ad", encoded)
								if bundle {
									rel, err := filepath.Rel(operand, target)
									if err != nil {
										t.Fatal(err)
									}
									manifest, err := json.Marshal(map[string]string{filepath.ToSlash(rel): "metadata.ad"})
									if err != nil {
										t.Fatal(err)
									}
									bundleWrite(t, dir, "metadata.json", manifest)
									goArgs = append(goArgs, "--appledouble-map", filepath.Join(dir, "metadata.json"))
								} else {
									goArgs = append(goArgs, "--appledouble", carrierPath)
								}
							}
							visited := format != "dmg" && location != "directory" && location != "signature" && (format != "app" || location != "info") && (format != "framework" || location != "root")
							if location == "helper" || strings.HasPrefix(location, "child-") || strings.HasPrefix(location, "grandchild-") {
								visited = strings.Contains(policy, "deep")
							}
							resource := location == "resource" || location == "child-resource" || location == "info"
							removed := visited && strip && policy != "already-strip" && (!strings.Contains(policy, "no-strict") || resource)
							prohibited := state != "clean" && (transport == "appledouble" || runtime.GOOS != "linux")
							wantStatus := 0
							if policy == "already-strip" || visited && prohibited && !strip && !strings.Contains(policy, "no-strict") {
								wantStatus = 1
							}
							if wantStatus != 0 {
								args = append(args, "--verbose=1")
								goArgs = append(goArgs, "--verbose=1")
							}
							independent := ""
							if wantStatus != 0 && policy == "deep" && resource {
								independent = "Contents/Helpers/tool"
								if format == "framework" {
									independent = "Versions/A/Helpers/tool;Versions/A/helper"
								}
								if format == "flat-framework" {
									independent = "Helpers/tool;helper"
								}
								if format == "recursive" {
									independent = recursiveApps[2]
								}
							}
							if wantStatus != 0 && policy == "deep" && location == "helper" {
								if format == "framework" {
									independent = "Versions/A/helper"
								}
								if format == "flat-framework" {
									independent = "helper"
								}
							}
							var completed []byte
							if independent != "" {
								mustRun(t, binaryPath, "-fs", "-", "--deep", "--no-strict", "-i", "org.example.sideband.signing", operand)
								completed = signingSidebandBytes(t, operand, bundle)
								if err := os.RemoveAll(operand); err != nil {
									t.Fatal(err)
								}
								seed(false)
							}
							before, err := os.Stat(target)
							if err != nil {
								t.Fatal(err)
							}
							beforeBytes := signingSidebandBytes(t, operand, bundle)
							attrs := sidebandObjectAttrs(t, target)
							beforeAttrs := maps.Clone(attrs)
							out, stderr, status := run(t, binaryPath, append(goArgs, operand)...)
							if status != wantStatus {
								t.Fatalf("status=%d want=%d stdout=%q stderr=%q", status, wantStatus, out, stderr)
							}
							afterBytes := signingSidebandBytes(t, operand, bundle)
							if status != 0 && independent == "" || policy == "strip-dryrun" && format != "dmg" {
								nativeEqual(t, "unchanged code bytes", beforeBytes, afterBytes)
							}
							if independent != "" {
								signingSidebandPartial(t, beforeBytes, completed, afterBytes, independent, false)
							}
							after, err := os.Stat(target)
							if err != nil {
								t.Fatal(err)
							}
							same := os.SameFile(before, after)
							if removed && transport == "native" && runtime.GOOS != "linux" {
								for name := range attrs {
									if name == appledouble.FinderInfoName || name == appledouble.ResourceForkName || runtime.GOOS == "windows" && (strings.EqualFold(name, appledouble.FinderInfoName) || strings.EqualFold(name, appledouble.ResourceForkName)) {
										delete(attrs, name)
									}
								}
							}
							afterAttrs := sidebandObjectAttrs(t, target)
							if !reflect.DeepEqual(attrs, afterAttrs) {
								t.Fatalf("native attributes changed incorrectly: expected=%v after=%v", attrs, afterAttrs)
							}
							if transport == "appledouble" {
								decoded, err := appledouble.Decode(nativeRead(t, carrierPath))
								if err != nil {
									t.Fatal(err)
								}
								expected := metadata
								if removed {
									expected.FinderInfo = [32]byte{}
									expected.ResourceFork = nil
								}
								if decoded.FinderInfo != expected.FinderInfo || !bytes.Equal(decoded.ResourceFork, expected.ResourceFork) || !reflect.DeepEqual(decoded.Attrs, expected.Attrs) {
									t.Fatalf("carrier metadata: got=%+v want=%+v", decoded, expected)
								}
							}
							referenceEvidence := map[string]any{}
							if runtime.GOOS == "darwin" {
								if err := os.RemoveAll(operand); err != nil {
									t.Fatal(err)
								}
								seed(true)
								nativeBefore, err := os.Stat(target)
								if err != nil {
									t.Fatal(err)
								}
								referenceAttrs := sidebandObjectAttrs(t, target)
								nativeOut, nativeErr, nativeStatus := run(t, apple(t), append(args, operand)...)
								if status != nativeStatus || out != nativeOut || stderr != nativeErr {
									t.Fatalf("native=(%d %q %q) Go=(%d %q %q)", nativeStatus, nativeOut, nativeErr, status, out, stderr)
								}
								if independent == "" {
									nativeEqual(t, "signed bytes", afterBytes, signingSidebandBytes(t, operand, bundle))
								} else {
									signingSidebandPartial(t, beforeBytes, completed, signingSidebandBytes(t, operand, bundle), independent, true)
								}
								nativeAfter, err := os.Stat(target)
								if err != nil {
									t.Fatal(err)
								}
								if same != os.SameFile(nativeBefore, nativeAfter) {
									t.Fatal("object replacement differs from native")
								}
								actual := sidebandObjectAttrs(t, target)
								referenceEvidence = map[string]any{"stdout": nativeOut, "stderr": nativeErr, "status": nativeStatus, "attributes_before": referenceAttrs, "attributes_after": actual, "tree_after_sha256": hash(signingSidebandBytes(t, operand, bundle))}
								expectedAttrs := maps.Clone(referenceAttrs)
								if removed {
									delete(expectedAttrs, appledouble.ResourceForkName)
									delete(expectedAttrs, appledouble.FinderInfoName)
								}
								if !reflect.DeepEqual(expectedAttrs, actual) {
									t.Fatal("native unrelated attribute changes", expectedAttrs, actual)
								}
								for _, name := range []string{appledouble.ResourceForkName, appledouble.FinderInfoName} {
									_, present := actual[name]
									want := !removed && (name == appledouble.ResourceForkName && len(metadata.ResourceFork) > 0 || name == appledouble.FinderInfoName && metadata.FinderInfo != [32]byte{})
									if present != want {
										t.Fatalf("native removal %s: present=%v want=%v", name, present, want)
									}
								}
								if independent != "" {
									mustRun(t, apple(t), "-fs", "-", "--deep", "--no-strict", "-i", "org.example.sideband.signing", operand)
									nativeEqual(t, "complete independent signing control", completed, signingSidebandBytes(t, operand, bundle))
								}
							}
							attest(t, map[string]any{"args": args, "status": status, "stdout": out, "stderr": stderr, "removed": removed, "same_object": same, "bytes_before": hash(beforeBytes), "bytes_after": hash(afterBytes), "attributes_before": beforeAttrs, "attributes_after": afterAttrs, "reference": referenceEvidence, "independent_child": independent, "native_compared": runtime.GOOS == "darwin"})
						})
					}
				}
			}
		}
	}
}

// A resource worker's failure prevents its ancestor signatures but does not
// roll back independent completed code. Native exception-aware dispatch may
// leave the whole independent child unstarted. Require the complete manifest
// of one of these two outcomes; no arbitrary changed member is tolerated.
func signingSidebandPartial(t *testing.T, before, completed, actual []byte, independent string, native bool) {
	t.Helper()
	prior, full, got := executableDirectoryManifest(t, before), executableDirectoryManifest(t, completed), executableDirectoryManifest(t, actual)
	if err := signingSidebandPartialResult(prior, full, got, independent, native); err != nil {
		t.Fatal(err)
	}
}

func signingSidebandPartialResult(prior, full, got map[string]string, independent string, native bool) error {
	expected := map[string]string{}
	for name, digest := range prior {
		expected[name] = digest
	}
	for _, prefix := range strings.Split(independent, ";") {
		unchanged := native
		for name := range full {
			if name == prefix || strings.HasPrefix(name, prefix+"/") {
				unchanged = unchanged && got[name] == prior[name]
			}
		}
		if unchanged {
			continue
		}
		for name, digest := range full {
			if name == prefix || strings.HasPrefix(name, prefix+"/") {
				expected[name] = digest
			}
		}
	}
	if reflect.DeepEqual(got, expected) {
		return nil
	}
	for name, digest := range expected {
		if got[name] != digest {
			return fmt.Errorf("unexpected partial result at %s: got=%s want=%s", name, got[name], digest)
		}
	}
	for name := range got {
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("unexpected new member %s", name)
		}
	}
	return fmt.Errorf("unexpected partial result")
}

func signingSidebandBytes(t *testing.T, operand string, bundle bool) []byte {
	t.Helper()
	if bundle {
		return layoutArchive(t, operand)
	}
	return nativeRead(t, operand)
}
