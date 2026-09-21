package acceptance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The envelope write precedes this bundle's executable commit, but follows
// descendant commits. A directory at CodeResources is therefore a write failure,
// not a reason to reject a dry run or roll back already committed children.
func TestBundleEnvelopeDirectory(t *testing.T) {
	for _, layout := range append([]string{"app"}, bundleLayouts...) {
		for _, profile := range []string{"directory", "populated-directory"} {
			for _, operation := range []string{"sign", "resign", "dryrun", "dryrun-unsigned", "no-force", "verify"} {
				t.Run(layout+"/"+profile+"/"+operation, func(t *testing.T) {
					execute := func(exe string) ([]byte, map[string]any) {
						dir := t.TempDir()
						app, main, envelope, resource, executables := writerBundle(t, dir, layout, "arm64")
						if operation != "sign" && operation != "dryrun-unsigned" {
							mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
						}
						path := filepath.Join(app, envelope)
						if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
						if err := os.MkdirAll(path, 0755); err != nil {
							t.Fatal(err)
						}
						if profile == "populated-directory" {
							bundleWrite(t, path, "keep", []byte("retained directory contents\n"))
						}
						directoryBefore, err := os.Stat(path)
						if err != nil {
							t.Fatal(err)
						}
						bundleWrite(t, app, resource, []byte("changed resource\n"))
						bundleWrite(t, filepath.Dir(path), "n23", []byte("stale before envelope\n"))
						bundleWrite(t, filepath.Dir(path), "CodeDirectory", []byte("stale after envelope\n"))
						identities := make([]os.FileInfo, len(executables))
						originalBytes := make([][]byte, len(executables))
						neighbours := make([]string, len(executables))
						for i, name := range executables {
							p := filepath.Join(app, name)
							identities[i], err = os.Stat(p)
							if err != nil {
								t.Fatal(err)
							}
							originalBytes[i] = nativeRead(t, p)
							neighbours[i] = filepath.Join(dir, strings.ReplaceAll(name, "/", "-"))
							if err := os.Link(p, neighbours[i]); err != nil {
								t.Fatal(err)
							}
						}
						before := layoutArchive(t, app)
						args := []string{"-fs", "-", "--deep", "--timestamp=none"}
						statusWant := 1
						switch operation {
						case "dryrun", "dryrun-unsigned":
							args = append(args, "--dryrun")
							// A native dry run seals the on-disk child signatures. Unsigned
							// descendants still fail sealing, independently of the envelope.
							if operation == "dryrun" || len(executables) == 1 {
								statusWant = 0
							}
						case "no-force":
							args = []string{"-s", "-", "--deep", "--timestamp=none"}
						case "verify":
							args = []string{"--verify", "--deep"}
						}
						out, stderr, status := run(t, exe, append(args, app)...)
						if status != statusWant {
							t.Fatalf("%s exit %d want %d: %s %s", exe, status, statusWant, out, stderr)
						}
						effects := map[string]bool{}
						mutating := operation == "sign" || operation == "resign"
						for i, name := range executables {
							current, err := os.Stat(filepath.Join(app, name))
							if err != nil {
								t.Fatal(err)
							}
							replaced := mutating && name != main
							if os.SameFile(identities[i], current) == replaced {
								t.Fatalf("%s replacement: want %t", name, replaced)
							}
							other, err := os.Stat(neighbours[i])
							if err != nil || !os.SameFile(identities[i], other) {
								t.Fatalf("neighbour identity: %v", err)
							}
							nativeEqual(t, "external executable bytes", nativeRead(t, neighbours[i]), originalBytes[i])
							if !replaced {
								nativeEqual(t, "uncommitted executable", nativeRead(t, filepath.Join(app, name)), nativeRead(t, neighbours[i]))
							}
							effects[name] = replaced
						}
						current, err := os.Stat(path)
						if err != nil || !os.SameFile(directoryBefore, current) {
							t.Fatalf("envelope directory changed: %v", err)
						}
						after := layoutArchive(t, app)
						if !mutating {
							nativeEqual(t, "non-mutating envelope failure", after, before)
						}
						return after, map[string]any{"argv": append(args, app), "stdout": out, "stderr": stderr, "exit": status, "before_sha256": hash(before), "tree_sha256": hash(after), "executables_replaced": effects, "envelope_directory_retained": true, "neighbours_preserved": true}
					}
					got, record := execute(binaryPath)
					evidence := map[string]any{"producer": runtime.GOOS, "layout": layout, "profile": profile, "operation": operation, "go": record, "native_compared": runtime.GOOS == "darwin"}
					if runtime.GOOS == "darwin" {
						want, native := execute(apple(t))
						nativeEqual(t, "complete envelope-directory failure tree", got, want)
						evidence["native"] = native
					}
					attest(t, evidence)
				})
			}
		}
	}
}

// Two siblings expose an earlier successful commit and a later envelope failure.
// The parent and failing child's executable must stay unchanged. The same
// structure also exercises unreadable old envelopes and outer-only removal.
func envelopeNestedCase(t *testing.T, exe, profile, position, operation string) ([]byte, map[string]any) {
	t.Helper()
	dir := t.TempDir()
	app := filepath.Join(dir, "Example.app")
	roots := []string{app, filepath.Join(app, "Contents/PlugIns/A.app"), filepath.Join(app, "Contents/PlugIns/B.app")}
	for _, p := range roots {
		bundleFixture(t, p, "arm64")
	}
	mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
	badIndex := 0
	if position == "child" {
		badIndex = 2
	}
	envelope := filepath.Join(roots[badIndex], "Contents/_CodeSignature/CodeResources")
	if profile == "directory" || profile == "populated-directory" {
		if err := os.Remove(envelope); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(envelope, 0755); err != nil {
			t.Fatal(err)
		}
		if profile == "populated-directory" {
			bundleWrite(t, envelope, "keep", []byte("directory preserved\n"))
		}
	}
	originals := make([]os.FileInfo, len(roots))
	originalBytes := make([][]byte, len(roots))
	for i, p := range roots {
		var err error
		main := filepath.Join(p, "Contents/MacOS/hello")
		originals[i], err = os.Stat(main)
		if err != nil {
			t.Fatal(err)
		}
		originalBytes[i] = nativeRead(t, main)
		if err := os.Link(main, filepath.Join(dir, filepath.Base(p)+"-neighbour")); err != nil {
			t.Fatal(err)
		}
		bundleWrite(t, p, "Contents/Resources/message.txt", []byte("changed resource\n"))
	}
	envelopeBefore, err := os.Stat(envelope)
	if err != nil {
		t.Fatal(err)
	}
	before := layoutArchive(t, app)
	permission := profile == "readonly" || profile == "writeonly"
	if permission {
		mode := os.FileMode(0444)
		if profile == "writeonly" {
			mode = 0200
		}
		if err := os.Chmod(envelope, mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(envelope, 0644) })
		// Do not count root/bypassed permissions as a successful permission test.
		flags := os.O_WRONLY
		if profile == "writeonly" {
			flags = os.O_RDONLY
		}
		if f, err := os.OpenFile(envelope, flags, 0); err == nil {
			f.Close()
			t.Skip("host does not enforce the requested permission denial")
		} else if !os.IsPermission(err) {
			t.Fatal(err)
		}
	}
	args := []string{"-fs", "-", "--deep", "--timestamp=none"}
	dry := operation == "dryrun" || operation == "shallow-dryrun"
	shallow := strings.HasPrefix(operation, "shallow")
	removing := operation == "remove"
	if shallow {
		args = []string{"-fs", "-", "--timestamp=none"}
	}
	if dry {
		args = append(args, "--dryrun")
	}
	if removing {
		args = []string{"--remove-signature"}
	}
	out, stderr, status := run(t, exe, append(args, app)...)
	failure := !dry && !removing && profile != "writeonly" && (!shallow || position != "child")
	statusWant := 0
	if failure || removing && !permission && position == "parent" {
		statusWant = 1
	}
	if status != statusWant {
		t.Fatalf("%s exit %d want %d: %s %s", exe, status, statusWant, out, stderr)
	}
	if permission {
		current, err := os.Stat(envelope)
		if !removing || position == "child" {
			if err != nil || !os.SameFile(envelopeBefore, current) || current.Mode().Perm() != map[string]os.FileMode{"readonly": 0444, "writeonly": 0200}[profile] {
				t.Fatalf("envelope identity/mode: %v", err)
			}
		} else if !os.IsNotExist(err) {
			t.Fatalf("outer envelope not removed: %v", err)
		}
		// Normalize the probe's access restriction only after recording its mode,
		// so full byte trees can be compared and fixtures can be cleaned up.
		if err := os.Chmod(envelope, 0644); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	effects := map[string]bool{}
	for i, p := range roots {
		replaced := !dry
		if removing {
			replaced = replaced && i == 0
		} else if shallow {
			replaced = replaced && i == 0 && !failure
		} else if failure {
			replaced = replaced && i != 0 && (badIndex == 0 || i < badIndex)
		}
		main := filepath.Join(p, "Contents/MacOS/hello")
		current, err := os.Stat(main)
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(originals[i], current) == replaced {
			t.Fatalf("%s replacement: want %t", p, replaced)
		}
		neighbour := filepath.Join(dir, filepath.Base(p)+"-neighbour")
		other, err := os.Stat(neighbour)
		if err != nil || !os.SameFile(originals[i], other) {
			t.Fatalf("neighbour identity: %v", err)
		}
		nativeEqual(t, "external neighbour bytes", nativeRead(t, neighbour), originalBytes[i])
		if !replaced {
			nativeEqual(t, "uncommitted executable bytes", nativeRead(t, main), originalBytes[i])
		}
		effects[filepath.Base(p)] = replaced
	}
	after := layoutArchive(t, app)
	if dry {
		nativeEqual(t, "nested dry-run tree", after, before)
	}
	if !dry && !shallow && !removing && !failure {
		mustRun(t, binaryPath, "--verify", "--deep", app)
		if runtime.GOOS == "darwin" {
			mustRun(t, apple(t), "--verify", "--strict", "--deep", app)
		}
	}
	return after, map[string]any{"argv": append(args, app), "stdout": out, "stderr": stderr, "exit": status, "before_sha256": hash(before), "tree_sha256": hash(after), "executables_replaced": effects, "neighbours_preserved": true}
}

func TestBundleEnvelopeNestedDirectory(t *testing.T) {
	for _, profile := range []string{"directory", "populated-directory"} {
		for _, position := range []string{"parent", "child"} {
			for _, operation := range []string{"resign", "dryrun", "shallow", "shallow-dryrun", "remove"} {
				t.Run(profile+"/"+position+"/"+operation, func(t *testing.T) {
					got, record := envelopeNestedCase(t, binaryPath, profile, position, operation)
					evidence := map[string]any{"producer": runtime.GOOS, "profile": profile, "position": position, "operation": operation, "go": record, "native_compared": runtime.GOOS == "darwin"}
					if runtime.GOOS == "darwin" {
						want, native := envelopeNestedCase(t, apple(t), profile, position, operation)
						nativeEqual(t, "complete nested envelope-directory tree", got, want)
						evidence["native"] = native
					}
					attest(t, evidence)
				})
			}
		}
	}
}

func TestBundleEnvelopePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX read/write permission bits are not a Windows permission model")
	}
	for _, profile := range []string{"readonly", "writeonly"} {
		for _, position := range []string{"parent", "child"} {
			for _, operation := range []string{"resign", "dryrun", "shallow", "shallow-dryrun", "remove"} {
				t.Run(profile+"/"+position+"/"+operation, func(t *testing.T) {
					got, record := envelopeNestedCase(t, binaryPath, profile, position, operation)
					evidence := map[string]any{"producer": runtime.GOOS, "profile": profile, "position": position, "operation": operation, "go": record, "native_compared": runtime.GOOS == "darwin", "filesystem_profile": "POSIX owner mode permissions"}
					if runtime.GOOS == "darwin" {
						want, native := envelopeNestedCase(t, apple(t), profile, position, operation)
						nativeEqual(t, "complete envelope-permission tree", got, want)
						evidence["native"] = native
					}
					attest(t, evidence)
				})
			}
		}
	}
}
