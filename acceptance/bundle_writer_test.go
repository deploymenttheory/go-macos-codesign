package acceptance

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writerBundle(t *testing.T, dir, kind, arch string) (app, main, envelope, resource string, executables []string) {
	t.Helper()
	if kind == "app" {
		app = filepath.Join(dir, "Example.app")
		nestedFixture(t, app, arch)
		bundleFixture(t, filepath.Join(app, "Contents/PlugIns/Child.app"), arch)
		main, envelope, resource = "Contents/MacOS/hello", "Contents/_CodeSignature/CodeResources", "Contents/Resources/message.txt"
		executables = append([]string{main, "Contents/PlugIns/Child.app/Contents/MacOS/hello"}, nestedHelpers...)
	} else {
		app = layoutFixture(t, dir, kind, arch, "xml")
		_, base, _, executable := layoutPaths(kind)
		main, envelope, resource = base+executable, base+"_CodeSignature/CodeResources", base+"Resources/message.txt"
		executables = []string{main}
		if kind == "framework" || kind == "versioned" {
			executables = append(executables, base+"helper")
		}
	}
	return
}

// Compare bytes and inode effects separately. Equal signatures alone miss the
// old writer's mutation of every external hard-link name.
func TestBundleWriterParity(t *testing.T) {
	for _, kind := range append([]string{"app"}, bundleLayouts...) {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, operation := range []string{"sign-new", "sign", "resign", "remove", "remove-unsigned", "dryrun"} {
				t.Run(kind+"/"+arch+"/"+operation, func(t *testing.T) {
					execute := func(exe string) ([]byte, map[string]any) {
						dir := t.TempDir()
						app, main, envelope, resource, executables := writerBundle(t, dir, kind, arch)
						if operation == "resign" || operation == "remove" || operation == "dryrun" {
							mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
						}
						type link struct {
							name, neighbour string
							info            os.FileInfo
							data            []byte
						}
						links := []link{}
						for i, name := range executables {
							path, neighbour := filepath.Join(app, filepath.FromSlash(name)), filepath.Join(dir, fmt.Sprintf("neighbour-%d", i))
							if err := os.Link(path, neighbour); err != nil {
								t.Fatal(err)
							}
							st, err := os.Stat(path)
							if err != nil {
								t.Fatal(err)
							}
							other, err := os.Stat(neighbour)
							if err != nil || !os.SameFile(st, other) {
								t.Fatalf("initial link: %v", err)
							}
							links = append(links, link{name, neighbour, st, nativeRead(t, path)})
						}
						envelopePath := filepath.Join(app, filepath.FromSlash(envelope))
						var envelopeBefore os.FileInfo
						var envelopeData []byte
						neighbour := filepath.Join(dir, "envelope-neighbour")
						if operation != "sign-new" {
							envelopeData = []byte("previous unsigned envelope")
							if data, err := os.ReadFile(envelopePath); err == nil {
								envelopeData = data
							}
							if err := os.MkdirAll(filepath.Dir(envelopePath), 0755); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(neighbour, envelopeData, 0644); err != nil {
								t.Fatal(err)
							}
							if err := os.Remove(envelopePath); err != nil && !os.IsNotExist(err) {
								t.Fatal(err)
							}
							// Darwin restricts linking FROM CodeResources. Link TO it.
							if err := os.Link(neighbour, envelopePath); err != nil {
								t.Fatal(err)
							}
							var err error
							envelopeBefore, err = os.Stat(envelopePath)
							if err != nil {
								t.Fatal(err)
							}
							other, err := os.Stat(neighbour)
							if err != nil || !os.SameFile(envelopeBefore, other) {
								t.Fatalf("envelope link: %v", err)
							}
						}
						if operation == "resign" {
							bundleWrite(t, app, resource, []byte("changed resource\n"))
						}
						before := layoutArchive(t, app)
						args := []string{"-fs", "-", "--deep", "--timestamp=none"}
						removing := strings.HasPrefix(operation, "remove")
						if removing {
							args = []string{"--remove-signature"}
						}
						if operation == "dryrun" {
							args = append(args, "--dryrun")
						}
						out, stderr, status := run(t, exe, append(args, app)...)
						if status != 0 {
							t.Fatalf("%s %q: %d\n%s\n%s", exe, args, status, out, stderr)
						}
						effects := map[string]any{}
						for _, linked := range links {
							path := filepath.Join(app, filepath.FromSlash(linked.name))
							after, err := os.Stat(path)
							if err != nil {
								t.Fatal(err)
							}
							other, err := os.Stat(linked.neighbour)
							if err != nil {
								t.Fatal(err)
							}
							replaced := operation != "dryrun" && (!removing || linked.name == main)
							if os.SameFile(linked.info, after) == replaced || !os.SameFile(linked.info, other) || after.Mode() != linked.info.Mode() {
								t.Fatalf("wrong executable inode/mode: %s replaced=%t", linked.name, replaced)
							}
							nativeEqual(t, "external neighbour", nativeRead(t, linked.neighbour), linked.data)
							effects[linked.name] = map[string]any{"inode_replaced": replaced, "neighbour_sha256": hash(linked.data), "mode": after.Mode().String()}
						}
						if envelopeBefore != nil {
							other, err := os.Stat(neighbour)
							if err != nil || !os.SameFile(envelopeBefore, other) {
								t.Fatalf("envelope neighbour replaced: %v", err)
							}
							if removing {
								if _, err := os.Stat(envelopePath); !os.IsNotExist(err) {
									t.Fatalf("envelope not unlinked: %v", err)
								}
								nativeEqual(t, "unlinked envelope neighbour", nativeRead(t, neighbour), envelopeData)
							} else {
								after, err := os.Stat(envelopePath)
								if err != nil || !os.SameFile(envelopeBefore, after) {
									t.Fatalf("envelope inode changed: %v", err)
								}
								nativeEqual(t, "shared envelope", nativeRead(t, neighbour), nativeRead(t, envelopePath))
							}
						}
						after := layoutArchive(t, app)
						if operation == "dryrun" {
							nativeEqual(t, "dry-run tree", after, before)
						}
						if bytes.Contains(after, []byte(".apfs-replacement-")) {
							t.Fatal("staging directory leaked")
						}
						if !removing {
							mustRun(t, binaryPath, "--verify", "--deep", app)
							if runtime.GOOS == "darwin" {
								mustRun(t, apple(t), "--verify", "--strict", "--deep", app)
							}
							if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" && exe == binaryPath {
								bundleWrite(t, export, "signed-bundle-writer-"+kind+"-"+arch+"-"+operation+".tar", after)
							}
						}
						return after, map[string]any{"argv": append(args, app), "stdout": out, "stderr": stderr, "exit": status, "tree_sha256": hash(after), "executables": effects, "envelope_unlinked": removing, "envelope_existed": envelopeBefore != nil}
					}
					got, record := execute(binaryPath)
					evidence := map[string]any{"producer": runtime.GOOS, "layout": kind, "architecture": arch, "operation": operation, "go": record, "native_compared": runtime.GOOS == "darwin"}
					if runtime.GOOS == "darwin" {
						want, native := execute(apple(t))
						nativeEqual(t, "complete bundle tree", got, want)
						evidence["native"] = native
					}
					attest(t, evidence)
				})
			}
		}
	}
}

func verifyBundleWriterArchive(t *testing.T, reference, archive string) {
	t.Helper()
	name := strings.TrimPrefix(filepath.Base(archive), "signed-bundle-writer-")
	name = strings.TrimPrefix(name, "signed-bundle-cleanup-")
	kind, _, ok := strings.Cut(name, "-")
	if !ok {
		t.Fatal("invalid writer archive", archive)
	}
	ext, _, _, _ := layoutPaths(kind)
	base := "Fixture." + ext
	if kind == "app" {
		base = "Example.app"
	}
	bundle := filepath.Join(t.TempDir(), base)
	extractLayout(t, nativeRead(t, archive), bundle)
	mustRun(t, reference, "--verify", "--strict", "--deep", bundle)
}
