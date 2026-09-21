package acceptance

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExecutableDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory mode bits are not a Windows permission model")
	}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, shape := range []string{"standalone", "alias", "parent", "first-child", "last-child", "grandchild", "helper"} {
			for _, profile := range []string{"writable", "readonly"} {
				for _, mode := range []os.FileMode{0755, 0551} {
					operations := []string{"sign", "resign", "remove", "remove-unsigned", "dryrun", "dryrun-unsigned"}
					if shape != "standalone" && shape != "alias" {
						operations = append(operations, "shallow", "shallow-dryrun")
					}
					for _, operation := range operations {
						t.Run(fmt.Sprintf("%s/%s/%s/%04o/%s", arch, shape, profile, mode, operation), func(t *testing.T) {
							_, got, record := executableDirectoryCase(t, binaryPath, arch, shape, profile, operation, mode)
							evidence := map[string]any{"producer": runtime.GOOS, "architecture": arch, "shape": shape, "profile": profile, "executable_mode": fmt.Sprintf("%04o", mode), "operation": operation, "go": record, "native_compared": runtime.GOOS == "darwin", "filesystem_profile": "POSIX readable and searchable executable directories"}
							if runtime.GOOS == "darwin" {
								before, want, native := executableDirectoryCase(t, apple(t), arch, shape, profile, operation, mode)
								skipped := native["undispatched_siblings"].([]string)
								if len(skipped) == 0 {
									nativeEqual(t, "complete executable-directory result", got, want)
								} else {
									prior, portable, observed := executableDirectoryManifest(t, before), executableDirectoryManifest(t, got), executableDirectoryManifest(t, want)
									if !reflect.DeepEqual(executableDirectoryExpectedManifest(prior, portable, skipped), observed) {
										t.Fatal("native tree differs beyond undispatched siblings")
									}
									evidence["undispatched_sibling_manifests"] = map[string]any{"before": prior, "go": portable, "native": observed}
									for _, name := range skipped {
										for _, side := range []map[string]any{record, native} {
											access := side["executables"].(map[string]any)[name].(map[string]any)["access"].(map[string]any)
											access["native_accessed"], access["known_difference"] = false, true
										}
									}
								}
								evidence["complete_tree_bytes_equal"] = bytes.Equal(got, want)
								if record["before_sha256"] != native["before_sha256"] {
									t.Fatal("different initial trees")
								}
								evidence["native"] = native
							}
							attest(t, evidence)
						})
					}
				}
			}
		}
	}
}

func executableDirectoryCase(t *testing.T, exe, arch, shape, profile, operation string, mode os.FileMode) ([]byte, []byte, map[string]any) {
	t.Helper()
	standalone := shape == "standalone" || shape == "alias"
	dry := strings.Contains(operation, "dryrun")
	removing := strings.HasPrefix(operation, "remove")
	shallow := strings.HasPrefix(operation, "shallow")
	signed := operation != "sign" && operation != "remove-unsigned"
	var operand, restricted string
	var alias standaloneAlias
	paths := map[string]string{}
	names := []string{"main"}
	dir := t.TempDir()
	if standalone {
		fixture := "unsigned-" + arch
		if signed && operation != "dryrun-unsigned" {
			fixture = "adhoc-" + arch
		}
		alias = newStandaloneAlias(t, "chain", nativeRead(t, filepath.Join(root, "testdata/macho", fixture)))
		paths["main"] = alias.target
		operand = alias.target
		if shape == "alias" {
			operand = alias.input
		}
	} else {
		operand = filepath.Join(dir, "Example.app")
		names = []string{"A", "B", "main"}
		if shape == "grandchild" {
			names = append([]string{"C"}, names...)
		}
		for _, name := range names {
			app := operand
			if name != "main" {
				app = filepath.Join(operand, "Contents/PlugIns", name+".app")
			}
			if name == "C" {
				app = filepath.Join(operand, "Contents/PlugIns/A.app/Contents/PlugIns/C.app")
			}
			bundleFixture(t, app, arch)
			paths[name] = filepath.Join(app, "Contents/MacOS/hello")
		}
		if shape == "helper" {
			paths["helper"] = filepath.Join(operand, "Contents/Helpers/helper")
			bundleWrite(t, operand, "Contents/Helpers/helper", nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+arch)))
			names = append([]string{"helper"}, names...)
		}
		if signed {
			mustRun(t, exe, "-fs", "-", "--deep", "--timestamp=none", operand)
			if operation == "dryrun-unsigned" {
				mustRun(t, exe, "--remove-signature", operand)
			}
		}
		for _, name := range names {
			if name == "helper" {
				continue
			}
			app := filepath.Dir(filepath.Dir(filepath.Dir(paths[name])))
			bundleWrite(t, app, "Contents/Resources/message.txt", []byte("changed resource\n"))
			if signed {
				bundleWrite(t, app, "Contents/_CodeSignature/CodeDirectory", []byte("stale signature component\n"))
			}
		}
	}
	bad := "main"
	switch shape {
	case "first-child":
		bad = "A"
	case "last-child":
		bad = "B"
	case "grandchild":
		bad = "C"
	case "helper":
		bad = "helper"
	}
	restricted = filepath.Dir(paths[bad])
	originals := map[string]os.FileInfo{}
	originalBytes := map[string][]byte{}
	neighbours := map[string]string{}
	for _, name := range names {
		path := paths[name]
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		neighbours[name] = filepath.Join(dir, name+"-neighbour")
		if err := os.Link(path, neighbours[name]); err != nil {
			t.Fatal(err)
		}
		originalBytes[name] = nativeRead(t, path)
	}
	snapshot := func() []byte {
		if standalone {
			return nativeRead(t, paths["main"])
		}
		return layoutArchive(t, operand)
	}
	before := snapshot()
	seed := time.Unix(978307200, 234567890)
	for _, name := range names {
		if err := os.Chtimes(paths[name], seed, time.Unix(946684800, 123456789)); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(paths[name])
		if err != nil {
			t.Fatal(err)
		}
		originals[name] = st
	}
	directoryMode := os.FileMode(0755)
	if profile == "readonly" {
		directoryMode = 0555
	}
	if err := os.Chmod(restricted, directoryMode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(restricted, 0755) })
	probe := filepath.Join(restricted, "permission-probe")
	err := os.Mkdir(probe, 0700)
	if err == nil {
		if err := os.Remove(probe); err != nil {
			t.Fatal(err)
		}
		if profile == "readonly" {
			t.Skip("host does not enforce the requested directory permission denial")
		}
	} else if profile == "writable" || !os.IsPermission(err) {
		t.Fatal(err)
	}
	args := []string{"-fs", "-", "--deep", "--timestamp=none"}
	if standalone {
		args = append(args, "-i", "org.example.directory")
	}
	switch operation {
	case "remove", "remove-unsigned":
		args = []string{"--remove-signature"}
	case "dryrun", "dryrun-unsigned":
		args = append(args, "--dryrun")
	case "shallow":
		args = []string{"-fs", "-", "--timestamp=none"}
	case "shallow-dryrun":
		args = []string{"-fs", "-", "--timestamp=none", "--dryrun"}
	}
	started := time.Now()
	out, stderr, status := run(t, exe, append(args, operand)...)
	finished := time.Now()
	failure := profile == "readonly" && (bad == "main" || !removing && !shallow)
	wantStatus := 0
	if failure {
		wantStatus = 1
	}
	if status != wantStatus {
		t.Fatalf("%s %q: exit %d want %d\n%s\n%s", exe, args, status, wantStatus, out, stderr)
	}
	directoryAfter, err := os.Stat(restricted)
	if err != nil || directoryAfter.Mode().Perm() != directoryMode {
		t.Fatalf("directory permission changed: %v", err)
	}
	// Restore only the probe's directory restriction before archiving and cleanup.
	if err := os.Chmod(restricted, 0755); err != nil {
		t.Fatal(err)
	}
	effects := map[string]any{}
	undispatched := []string{}
	for _, name := range names {
		ancestor := name == "main" && bad != "main" || shape == "grandchild" && name == "A"
		rewritten := !dry && (!failure || name != bad && !ancestor)
		if removing || shallow {
			rewritten = !dry && !failure && name == "main"
		}
		after, err := os.Stat(paths[name])
		if err != nil {
			t.Fatal(err)
		}
		other, err := os.Stat(neighbours[name])
		if err != nil {
			t.Fatal(err)
		}
		old := originals[name]
		// Apple's exception-aware dispatcher can leave an independent sibling unstarted.
		skipped := exe != binaryPath && failure && !removing && !shallow && !ancestor && name != bad && (name == "A" || name == "B") && executableDirectoryUnaccessed(old, after)
		if skipped {
			rewritten = false
			undispatched = append(undispatched, name)
		}
		if os.SameFile(old, after) == rewritten || !os.SameFile(old, other) {
			t.Fatalf("%s %s replacement: want %v", exe, name, rewritten)
		}
		if after.Mode() != old.Mode() || other.Mode() != old.Mode() || !other.ModTime().Equal(old.ModTime()) {
			t.Fatalf("mode or source modification time changed: %s", name)
		}
		if !rewritten && !after.ModTime().Equal(old.ModTime()) {
			t.Fatalf("uncommitted modification time changed: %s", name)
		}
		accessed := !removing || name == "main"
		if shallow {
			accessed = name == "main"
		}
		if failure && !removing && !shallow && ancestor {
			accessed = false
		}
		if skipped {
			accessed = false
		}
		effect := map[string]any{"inode_replaced": rewritten, "neighbour_preserved": true}
		effect["access"] = executableDirectoryAccess(t, old, after, other, accessed, started, finished)
		effects[name] = effect
	}
	for _, name := range names {
		nativeEqual(t, "external neighbour bytes", nativeRead(t, neighbours[name]), originalBytes[name])
		if !effects[name].(map[string]any)["inode_replaced"].(bool) {
			nativeEqual(t, "uncommitted executable bytes", nativeRead(t, paths[name]), originalBytes[name])
		}
	}
	after := snapshot()
	if dry || standalone && failure {
		nativeEqual(t, "unchanged bytes", after, before)
	}
	if standalone {
		alias.checkLinks(t)
		nativeEqual(t, "lexical decoy", nativeRead(t, alias.decoy), originalBytes["main"])
	}
	scanRoot := operand
	if standalone {
		scanRoot = filepath.Dir(paths["main"])
	}
	if err := filepath.WalkDir(scanRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".apfs-replacement-") || strings.HasSuffix(d.Name(), ".cstemp") {
			t.Fatalf("temporary allocation leaked: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !failure && !dry && !removing && !shallow {
		mustRun(t, binaryPath, "--verify", "--deep", operand)
		if runtime.GOOS == "darwin" {
			mustRun(t, apple(t), "--verify", "--strict", "--deep", operand)
		}
	}
	return before, after, map[string]any{"argv": append(args, operand), "stdout": out, "stderr": stderr, "exit": status, "started": started, "finished": finished, "before_sha256": hash(before), "tree_sha256": hash(after), "executables": effects, "undispatched_siblings": undispatched, "directory_mode_preserved": true, "staging_removed": true}
}

func executableDirectoryManifest(t *testing.T, archive []byte) map[string]string {
	t.Helper()
	result := map[string]string{}
	r := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			return result
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		header, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		result[h.Name] = hash(append(header, data...))
	}
}

func executableDirectoryExpectedManifest(before, signed map[string]string, undispatched []string) map[string]string {
	result := make(map[string]string, len(signed))
	for name, digest := range signed {
		result[name] = digest
	}
	for _, sibling := range undispatched {
		prefix := "Contents/PlugIns/" + sibling + ".app"
		for name := range result {
			if name == prefix || strings.HasPrefix(name, prefix+"/") {
				delete(result, name)
			}
		}
		for name, digest := range before {
			if name == prefix || strings.HasPrefix(name, prefix+"/") {
				result[name] = digest
			}
		}
	}
	return result
}

func TestExecutableDirectoryUndispatchedComparison(t *testing.T) {
	reference := apple(t)
	makeTree := func() string {
		app := filepath.Join(t.TempDir(), "Example.app")
		for _, name := range []string{"", "Contents/PlugIns/A.app", "Contents/PlugIns/B.app"} {
			bundleFixture(t, filepath.Join(app, name), "arm64")
		}
		return app
	}
	portable, native := makeTree(), makeTree()
	before := executableDirectoryManifest(t, layoutArchive(t, native))
	for _, name := range []string{"A", "B"} {
		mustRun(t, binaryPath, "-fs", "-", "--timestamp=none", filepath.Join(portable, "Contents/PlugIns", name+".app"))
	}
	mustRun(t, reference, "-fs", "-", "--timestamp=none", filepath.Join(native, "Contents/PlugIns/B.app"))
	expected := executableDirectoryExpectedManifest(before, executableDirectoryManifest(t, layoutArchive(t, portable)), []string{"A"})
	if !reflect.DeepEqual(expected, executableDirectoryManifest(t, layoutArchive(t, native))) {
		t.Fatal("complete native tree with an untouched sibling differs")
	}
	for _, name := range []string{"Contents/Resources/message.txt", "Contents/PlugIns/A.app/Contents/Resources/message.txt", "Contents/PlugIns/B.app/Contents/Resources/message.txt"} {
		path := filepath.Join(native, name)
		original := nativeRead(t, path)
		bundleWrite(t, native, name, []byte("unexpected mutation\n"))
		if reflect.DeepEqual(expected, executableDirectoryManifest(t, layoutArchive(t, native))) {
			t.Fatalf("accepted mutation outside the allowed completion outcome: %s", name)
		}
		bundleWrite(t, native, name, original)
	}
}
