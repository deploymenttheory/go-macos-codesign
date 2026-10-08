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

var genericShapes = []string{"empty", "text", "script", "object", "short-header", "app", "framework", "flat-framework", "recursive", "fallback-app", "fallback-framework", "fallback-flat-framework", "fallback-installer", "fallback-missing-key", "fallback-empty-key", "fallback-bad-key", "fallback-historical-directory"}
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
	if strings.HasPrefix(shape, "fallback-") {
		return fallbackFixture(t, dir, strings.TrimPrefix(shape, "fallback-"))
	}
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
	return genericAttrsForPlatform(t, target, metadata, carrier, runtime.GOOS)
}

func genericAttrsForPlatform(t *testing.T, target string, metadata appledouble.File, carrier, platform string) map[string]string {
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
		if platform == "linux" && strings.HasPrefix(query, "com.apple.") {
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
	Platform       string
}

func TestGenericRemoval(t *testing.T) {
	for _, shape := range genericShapes {
		for _, state := range []string{"clean", "populated", "empty"} {
			t.Run(shape+"/"+state+"/native", func(t *testing.T) {
				dir := extractionDirectory(t)
				metadata := genericMetadata(state)
				execute := func(exe string) genericRemovalResult {
					operand, target, bundle := genericFixture(t, dir, shape)
					before := nativeRead(t, target)
					original := accessFileInfo(t, target)
					setSidebandObject(t, target, metadata)
					initialAttrs := genericAttrs(t, target, metadata, "")
					out, stderr, status := run(t, exe, "--remove-signature", operand)
					nativeEqual(t, "generic data fork", nativeRead(t, target), before)
					result := genericRemovalResult{Status: status, Out: out, Err: stderr,
						Data: hash(signingSidebandBytes(t, operand, bundle)), Attrs: genericAttrs(t, target, metadata, ""),
						SameFile: os.SameFile(original, accessFileInfo(t, target)), Platform: runtime.GOOS}
					if status != 0 || out != "" || stderr != "" || !result.SameFile {
						t.Fatalf("removal %s: %#v", exe, result)
					}
					assertNativeGenericRemoval(t, result.Attrs, initialAttrs)
					if bundle {
						path := filepath.Join(operand, "Contents/_CodeSignature/CodeResources")
						if strings.TrimPrefix(shape, "fallback-") == "framework" {
							path = filepath.Join(operand, "Versions/A/_CodeSignature/CodeResources")
						}
						if strings.TrimPrefix(shape, "fallback-") == "flat-framework" {
							path = filepath.Join(operand, "_CodeSignature/CodeResources")
						}
						if _, err := os.Stat(path); !os.IsNotExist(err) {
							t.Fatalf("envelope remains: %v", err)
						}
					}
					if err := os.RemoveAll(operand); err != nil {
						t.Fatal(err)
					}
					return result
				}
				got := execute(binaryPath)
				if runtime.GOOS == "darwin" {
					want := execute(apple(t))
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("Go %#v; native %#v", got, want)
					}
				}
				attest(t, got)
				if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
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
	beforeHash := genericFileDigest(t, f, size)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Windows can finalize the last-write timestamp when the writer closes.
	// Capture the operation's baseline only after fixture construction finishes.
	original := accessFileInfo(t, path)
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
	expected := map[string]map[string]genericRemovalResult{}
	for _, shape := range genericShapes {
		for _, state := range []string{"clean", "populated", "empty"} {
			name := "generic-removal-" + shape + "-" + state + ".json"
			expected[name] = map[string]genericRemovalResult{}
			for _, platform := range []string{"linux", "windows"} {
				operand, target, bundle := genericFixture(t, extractionDirectory(t), shape)
				metadata := genericMetadata(state)
				setSidebandObjectForPlatform(t, target, metadata, platform)
				original := accessFileInfo(t, target)
				out, stderr, status := run(t, reference, "--remove-signature", operand)
				if status != 0 || out != "" || stderr != "" {
					t.Fatalf("native generic oracle %d %q %q", status, out, stderr)
				}
				expected[name][platform] = genericRemovalResult{Status: status, Out: out, Err: stderr,
					Data: hash(signingSidebandBytes(t, operand, bundle)), Attrs: genericAttrsForPlatform(t, target, metadata, "", platform),
					SameFile: os.SameFile(original, accessFileInfo(t, target)), Platform: platform}
			}
		}
	}
	seen := map[string]map[string]bool{}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "generic-removal-") {
			return nil
		}
		profiles, ok := expected[d.Name()]
		if !ok {
			t.Fatal("unexpected generic artifact", path)
		}
		var got genericRemovalResult
		if err := json.Unmarshal(nativeRead(t, path), &got); err != nil {
			return err
		}
		want, ok := profiles[got.Platform]
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: foreign %#v; native %#v", path, got, want)
		}
		if seen[d.Name()] == nil {
			seen[d.Name()] = map[string]bool{}
		}
		if seen[d.Name()][got.Platform] {
			t.Fatal("duplicate generic producer", path, got.Platform)
		}
		seen[d.Name()][got.Platform] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name := range expected {
		if !seen[name]["linux"] || !seen[name]["windows"] {
			t.Fatal("expected both generic producers", name, seen[name])
		}
	}
	attest(t, map[string]any{"foreign_generic_removal_cases": len(expected), "per_case_producers": seen})
}

func TestGenericRemovalWriteDenial(t *testing.T) {
	for _, shape := range []string{"text", "object", "app", "framework", "fallback-app", "fallback-framework"} {
		t.Run(shape, func(t *testing.T) {
			dir := extractionDirectory(t)
			operand, target, bundle := genericFixture(t, dir, shape)
			metadata := genericMetadata("populated")
			setSidebandObject(t, target, metadata)
			initialAttrs := genericAttrs(t, target, metadata, "")
			args := []string{"--remove-signature"}
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
			if attrs := genericAttrs(t, target, metadata, ""); !reflect.DeepEqual(attrs, initialAttrs) {
				t.Fatal("denied writer changed metadata", attrs, initialAttrs)
			}
			if !os.SameFile(original, accessFileInfo(t, target)) {
				t.Fatal("denied object replaced")
			}
			attest(t, map[string]any{"status": status, "stdout": out, "stderr": stderr, "before": hash(before), "attrs": initialAttrs})
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
				setSidebandObject(t, target, metadata)
				initialAttrs := genericAttrs(t, target, metadata, "")
				mustRun(t, binaryPath, "--remove-signature", alias)
				nativeEqual(t, "alias target", nativeRead(t, target), before)
				nativeEqual(t, "alias data", nativeRead(t, alias), before)
				if !os.SameFile(original, accessFileInfo(t, target)) || !os.SameFile(original, accessFileInfo(t, alias)) {
					t.Fatal("generic alias replaced")
				}
				got := genericAttrs(t, target, metadata, "")
				assertNativeGenericRemoval(t, got, initialAttrs)
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
	for _, shape := range []string{"text", "app", "fallback-app", "fallback-framework"} {
		t.Run(shape, func(t *testing.T) {
			dir := extractionDirectory(t)
			metadata := genericMetadata("populated")
			operand, target, bundle := genericFixture(t, dir, shape)
			setSidebandObject(t, target, metadata)
			initialAttrs := genericAttrs(t, target, metadata, "")
			args := []string{"--remove-signature", "--dryrun"}
			mustRun(t, binaryPath, append(args, operand)...)
			got := genericAttrs(t, target, metadata, "")
			assertNativeGenericRemoval(t, got, initialAttrs)
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

func assertNativeGenericRemoval(t *testing.T, got, before map[string]string) {
	t.Helper()
	want := map[string]string{}
	for name, value := range before {
		// Linux's user.com.apple.cs.* names are foreign namespace values. Native
		// removal must retain them; actual FAT signature removal is tested separately.
		if runtime.GOOS == "linux" || !strings.HasPrefix(name, "com.apple.cs.") {
			want[name] = value
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("generic removal changed the wrong attributes", got, want)
	}
}
