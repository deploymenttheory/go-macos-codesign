package acceptance

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

var genericShapes = []string{"empty", "text", "script", "object", "short-header", "app", "framework", "flat-framework", "recursive"}
var genericSlots = []string{"CodeDirectory", "CodeRequirements", "CodeResources", "CodeTopDirectory", "CodeEntitlements", "CodeRepSpecific", "CodeEntitlementDER", "LaunchConstraintSelf", "LaunchConstraintParent", "LaunchConstraintResponsible", "LibraryConstraint", "CodeSignature", "CodeRequirements-1", "Unknown"}

func genericMetadata(state string) appledouble.File {
	m := appledouble.File{ResourceFork: []byte("unrelated resource fork"), FinderInfo: [32]byte{'T', 'E', 'X', 'T'}, Attrs: []appledouble.Attr{{Name: "user.codesign-control", Value: []byte("keep")}, {Name: "com.apple.cs", Value: []byte("near prefix")}, {Name: "com.apple.csign", Value: []byte("not a signature")}}}
	if state != "clean" {
		for _, slot := range genericSlots {
			value := []byte(slot)
			if state == "empty" {
				value = nil
			}
			m.Attrs = append(m.Attrs, appledouble.Attr{Name: "com.apple.cs." + slot, Value: value})
		}
	}
	return m
}

func genericFixture(t *testing.T, dir, shape string) (operand, target string, bundle bool) {
	t.Helper()
	data := []byte("#!/bin/sh\nexit 0\n")
	switch shape {
	case "empty":
		data = nil
	case "text":
		data = []byte("not executable")
	case "object":
		data = bytes.Clone(nativeRead(t, filepath.Join(root, "testdata/macho/adhoc-arm64")))
		binary.LittleEndian.PutUint32(data[12:], 1)
	case "short-header":
		data = bytes.Clone(nativeRead(t, filepath.Join(root, "testdata/macho/adhoc-arm64"))[:27])
	}
	bundle = shape == "app" || shape == "framework" || shape == "flat-framework" || shape == "recursive"
	if bundle {
		var paths map[string]string
		operand, paths = sidebandBundleFixture(t, dir, shape)
		target = paths["main"]
	} else {
		operand = filepath.Join(dir, "tool")
		target = operand
	}
	if err := os.WriteFile(target, data, 0755); err != nil {
		t.Fatal(err)
	}
	return
}

// Read each supplied name rather than interpreting unrelated host bookkeeping.
// Attribute name spelling is preserved in the report, including on NTFS.
func genericAttrs(t *testing.T, target string, metadata appledouble.File, carrier string) map[string]string {
	t.Helper()
	if carrier != "" {
		f, err := appledouble.Decode(nativeRead(t, carrier))
		if err != nil {
			t.Fatal(err)
		}
		return genericValues(*f)
	}
	f, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	result := map[string]string{}
	names := []string{appledouble.ResourceForkName, appledouble.FinderInfoName}
	for _, a := range metadata.Attrs {
		names = append(names, a.Name)
	}
	for _, name := range names {
		query := name
		if runtime.GOOS == "linux" && strings.HasPrefix(query, "com.apple.") {
			query = "user." + query
		}
		value, present, err := hostdata.ReadXattr(f, query, hostdata.MaxXattrReadSize)
		if err != nil {
			t.Fatal(err)
		}
		if present {
			result[name] = hex.EncodeToString(value)
		}
	}
	return result
}
func genericValues(m appledouble.File) map[string]string {
	result := map[string]string{}
	if len(m.ResourceFork) > 0 {
		result[appledouble.ResourceForkName] = hex.EncodeToString(m.ResourceFork)
	}
	if m.FinderInfo != [32]byte{} {
		result[appledouble.FinderInfoName] = hex.EncodeToString(m.FinderInfo[:])
	}
	for _, a := range m.Attrs {
		result[a.Name] = hex.EncodeToString(a.Value)
	}
	return result
}

type genericRemovalResult struct {
	Status         int
	Out, Err, Data string
	Attrs          map[string]string
	SameFile       bool
}

func TestGenericRemoval(t *testing.T) {
	for _, shape := range genericShapes {
		for _, state := range []string{"clean", "populated", "empty"} {
			for _, transport := range []string{"native", "appledouble"} {
				t.Run(shape+"/"+state+"/"+transport, func(t *testing.T) {
					dir := extractionDirectory(t)
					metadata := genericMetadata(state)
					execute := func(exe string, explicit bool) genericRemovalResult {
						operand, target, bundle := genericFixture(t, dir, shape)
						before := nativeRead(t, target)
						original := accessFileInfo(t, target)
						args := []string{"--remove-signature"}
						carrier := ""
						if explicit {
							carrier = filepath.Join(dir, "metadata.ad")
							wire, err := metadata.Encode()
							if err != nil {
								t.Fatal(err)
							}
							bundleWrite(t, dir, "metadata.ad", wire)
							if bundle {
								rel, err := filepath.Rel(operand, target)
								if err != nil {
									t.Fatal(err)
								}
								manifest, err := json.Marshal(map[string]string{filepath.ToSlash(rel): carrier})
								if err != nil {
									t.Fatal(err)
								}
								bundleWrite(t, dir, "map.json", manifest)
								args = append(args, "--appledouble-map", filepath.Join(dir, "map.json"))
							} else {
								args = append(args, "--appledouble", carrier)
							}
						} else {
							setSidebandObject(t, target, metadata)
						}
						initialAttrs := genericAttrs(t, target, metadata, carrier)
						out, stderr, status := run(t, exe, append(args, operand)...)
						after := nativeRead(t, target)
						nativeEqual(t, "generic data fork", after, before)
						result := genericRemovalResult{status, out, stderr, hash(signingSidebandBytes(t, operand, bundle)), genericAttrs(t, target, metadata, carrier), os.SameFile(original, accessFileInfo(t, target))}
						if status != 0 || out != "" || stderr != "" || !result.SameFile {
							t.Fatalf("removal %s: %#v", exe, result)
						}
						want := initialAttrs
						if explicit || runtime.GOOS != "linux" {
							want = map[string]string{}
							for n, v := range initialAttrs {
								if !strings.HasPrefix(n, "com.apple.cs.") {
									want[n] = v
								}
							}
						}
						if !reflect.DeepEqual(result.Attrs, want) {
							t.Fatalf("attributes %#v; want %#v", result.Attrs, want)
						}
						if bundle {
							b := filepath.Join(operand, "Contents/_CodeSignature/CodeResources")
							if shape == "framework" {
								b = filepath.Join(operand, "Versions/A/_CodeSignature/CodeResources")
							}
							if shape == "flat-framework" {
								b = filepath.Join(operand, "_CodeSignature/CodeResources")
							}
							if _, err := os.Stat(b); !os.IsNotExist(err) {
								t.Fatalf("envelope remains: %v", err)
							}
						}
						if err := os.RemoveAll(operand); err != nil {
							t.Fatal(err)
						}
						return result
					}
					got := execute(binaryPath, transport == "appledouble")
					if runtime.GOOS == "darwin" {
						want := execute(apple(t), false)
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("Go %#v; native %#v", got, want)
						}
					}
					attest(t, got)
					if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" && transport == "appledouble" {
						wire, err := json.Marshal(got)
						if err != nil {
							t.Fatal(err)
						}
						bundleWrite(t, export, "generic-removal-"+shape+"-"+state+".json", wire)
					}
				})
			}
		}
	}
}

func TestGenericRemovalLarge(t *testing.T) {
	dir := extractionDirectory(t)
	path := filepath.Join(dir, "large")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	const size = int64(1<<30) + 4096
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("start"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("end"), size-3); err != nil {
		t.Fatal(err)
	}
	original, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := genericFileDigest(t, f, size)
	f.Close()
	mustRun(t, binaryPath, "--remove-signature", path)
	if runtime.GOOS == "darwin" {
		mustRun(t, apple(t), "--remove-signature", path)
	}
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != size || !os.SameFile(original, after) || !original.ModTime().Equal(after.ModTime()) {
		t.Fatal("large data fork replaced or resized")
	}
	if got := genericFileDigest(t, f, size); got != beforeHash {
		t.Fatalf("large data changed: %s; want %s", got, beforeHash)
	}
	var first [5]byte
	var last [3]byte
	if _, err := f.ReadAt(first[:], 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadAt(last[:], size-3); err != nil {
		t.Fatal(err)
	}
	if string(first[:]) != "start" || string(last[:]) != "end" {
		t.Fatal("large data fork altered")
	}
	attest(t, map[string]any{"size": size, "same_file": true, "sha256": beforeHash, "first": string(first[:]), "last": string(last[:])})
}

func genericFileDigest(t *testing.T, f *os.File, size int64) string {
	t.Helper()
	h := sha256.New()
	if n, err := io.Copy(h, io.NewSectionReader(f, 0, size)); err != nil || n != size {
		t.Fatal("hash complete generic data fork", n, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func verifyImportedGenericRemoval(t *testing.T, dir, reference string) {
	t.Helper()
	expected := map[string]genericRemovalResult{}
	for _, shape := range genericShapes {
		for _, state := range []string{"clean", "populated", "empty"} {
			operand, target, bundle := genericFixture(t, extractionDirectory(t), shape)
			metadata := genericMetadata(state)
			setSidebandObject(t, target, metadata)
			original := accessFileInfo(t, target)
			out, stderr, status := run(t, reference, "--remove-signature", operand)
			if status != 0 || out != "" || stderr != "" {
				t.Fatalf("native generic oracle %d %q %q", status, out, stderr)
			}
			expected["generic-removal-"+shape+"-"+state+".json"] = genericRemovalResult{status, out, stderr, hash(signingSidebandBytes(t, operand, bundle)), genericAttrs(t, target, metadata, ""), os.SameFile(original, accessFileInfo(t, target))}
		}
	}
	seen := map[string]int{}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "generic-removal-") {
			return nil
		}
		want, ok := expected[d.Name()]
		if !ok {
			t.Fatalf("unexpected generic artifact %s", path)
		}
		var got genericRemovalResult
		if err := json.Unmarshal(nativeRead(t, path), &got); err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: foreign %#v; native %#v", path, got, want)
		}
		seen[d.Name()]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name := range expected {
		if seen[name] != 2 {
			t.Fatalf("expected both producers for %s, got %d", name, seen[name])
		}
	}
	attest(t, map[string]any{"foreign_generic_removal_cases": len(expected), "per_case_producers": seen})
}

func TestGenericRemovalWriteDenial(t *testing.T) {
	for _, shape := range []string{"text", "object", "app", "framework"} {
		t.Run(shape, func(t *testing.T) {
			dir := extractionDirectory(t)
			operand, target, bundle := genericFixture(t, dir, shape)
			metadata := genericMetadata("populated")
			wire, err := metadata.Encode()
			if err != nil {
				t.Fatal(err)
			}
			carrier := filepath.Join(dir, "metadata.ad")
			bundleWrite(t, dir, "metadata.ad", wire)
			args := []string{"--remove-signature"}
			if bundle {
				rel, err := filepath.Rel(operand, target)
				if err != nil {
					t.Fatal(err)
				}
				manifest, err := json.Marshal(map[string]string{filepath.ToSlash(rel): carrier})
				if err != nil {
					t.Fatal(err)
				}
				bundleWrite(t, dir, "map.json", manifest)
				args = append(args, "--appledouble-map", filepath.Join(dir, "map.json"))
			} else {
				args = append(args, "--appledouble", carrier)
			}
			before := signingSidebandBytes(t, operand, bundle)
			original := accessFileInfo(t, target)
			restore := func() {}
			switch runtime.GOOS {
			case "darwin":
				mustRun(t, "/bin/chmod", "+a", "everyone deny write", target)
				restore = func() { mustRun(t, "/bin/chmod", "-N", target) }
			case "windows":
				mustRun(t, "icacls", target, "/deny", "*S-1-1-0:(WD)")
				restore = func() { mustRun(t, "icacls", target, "/remove:d", "*S-1-1-0") }
			case "linux":
				if err := os.Chmod(target, 0444); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if err := os.Chmod(target, original.Mode().Perm()); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Cleanup(restore)
			if f, err := os.OpenFile(target, os.O_RDWR, 0); err == nil {
				f.Close()
				t.Fatal("write denial is ineffective")
			} else if !os.IsPermission(err) {
				t.Fatal(err)
			}
			out, stderr, status := run(t, binaryPath, append(args, operand)...)
			restore()
			if status != 1 || out != "" || stderr != operand+": Permission denied\n" {
				t.Fatalf("denied writer: %d %q %q", status, out, stderr)
			}
			nativeEqual(t, "denied generic object", signingSidebandBytes(t, operand, bundle), before)
			nativeEqual(t, "denied generic carrier", nativeRead(t, carrier), wire)
			if !os.SameFile(original, accessFileInfo(t, target)) {
				t.Fatal("denied object replaced")
			}
			attest(t, map[string]any{"status": status, "stdout": out, "stderr": stderr, "before": hash(before), "carrier": hash(wire)})
		})
	}
}

func TestGenericRemovalAliases(t *testing.T) {
	for _, shape := range []string{"text", "object"} {
		for _, kind := range []string{"symlink", "hardlink"} {
			t.Run(shape+"/"+kind, func(t *testing.T) {
				dir := extractionDirectory(t)
				operand, target, _ := genericFixture(t, dir, shape)
				alias := filepath.Join(dir, "alias")
				if kind == "symlink" {
					if err := os.Symlink(filepath.Base(operand), alias); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Link(operand, alias); err != nil {
						t.Fatal(err)
					}
				}
				before := nativeRead(t, target)
				original := accessFileInfo(t, target)
				metadata := genericMetadata("populated")
				wire, err := metadata.Encode()
				if err != nil {
					t.Fatal(err)
				}
				carrier := filepath.Join(dir, "metadata.ad")
				bundleWrite(t, dir, "metadata.ad", wire)
				mustRun(t, binaryPath, "--remove-signature", "--appledouble", carrier, alias)
				nativeEqual(t, "alias target", nativeRead(t, target), before)
				nativeEqual(t, "alias data", nativeRead(t, alias), before)
				if !os.SameFile(original, accessFileInfo(t, target)) || !os.SameFile(original, accessFileInfo(t, alias)) {
					t.Fatal("generic alias replaced")
				}
				got := genericAttrs(t, target, metadata, carrier)
				for name := range got {
					if strings.HasPrefix(name, "com.apple.cs.") {
						t.Fatal("signature remains", name)
					}
				}
				if runtime.GOOS == "darwin" {
					setSidebandObject(t, target, metadata)
					mustRun(t, apple(t), "--remove-signature", alias)
					want := genericAttrs(t, target, metadata, "")
					if !reflect.DeepEqual(got, want) {
						t.Fatal(got, want)
					}
				}
				attest(t, map[string]any{"attrs": got, "same_file": true, "data": hash(before)})
			})
		}
	}
}

func TestGenericRemovalDryRun(t *testing.T) {
	for _, shape := range []string{"text", "app"} {
		t.Run(shape, func(t *testing.T) {
			dir := extractionDirectory(t)
			metadata := genericMetadata("populated")
			operand, target, bundle := genericFixture(t, dir, shape)
			carrier := filepath.Join(dir, "metadata.ad")
			wire, err := metadata.Encode()
			if err != nil {
				t.Fatal(err)
			}
			bundleWrite(t, dir, "metadata.ad", wire)
			args := []string{"--remove-signature", "--dryrun"}
			if bundle {
				rel, err := filepath.Rel(operand, target)
				if err != nil {
					t.Fatal(err)
				}
				manifest, err := json.Marshal(map[string]string{filepath.ToSlash(rel): carrier})
				if err != nil {
					t.Fatal(err)
				}
				bundleWrite(t, dir, "map.json", manifest)
				args = append(args, "--appledouble-map", filepath.Join(dir, "map.json"))
			} else {
				args = append(args, "--appledouble", carrier)
			}
			mustRun(t, binaryPath, append(args, operand)...)
			got := genericAttrs(t, target, metadata, carrier)
			for name := range got {
				if strings.HasPrefix(name, "com.apple.cs.") {
					t.Fatal("dry run suppressed removal", name)
				}
			}
			data := signingSidebandBytes(t, operand, bundle)
			if err := os.RemoveAll(operand); err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS == "darwin" {
				operand, target, bundle := genericFixture(t, dir, shape)
				setSidebandObject(t, target, metadata)
				mustRun(t, apple(t), "--remove-signature", "--dryrun", operand)
				if want := genericAttrs(t, target, metadata, ""); !reflect.DeepEqual(got, want) {
					t.Fatal(got, want)
				}
				nativeEqual(t, "generic dry run", data, signingSidebandBytes(t, operand, bundle))
			}
			attest(t, map[string]any{"attrs": got, "data": hash(data)})
		})
	}
}
