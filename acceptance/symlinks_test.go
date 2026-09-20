package acceptance

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

// Both CLIs receive independently constructed trees with the same physical
// basename. Alias names deliberately differ, exposing identifier mistakes.
type standaloneAlias struct {
	input, target, neighbour, decoy string
	links                           map[string]string
}

func newStandaloneAlias(t *testing.T, kind string, data []byte) standaloneAlias {
	t.Helper()
	dir := t.TempDir()
	if kind == "relative-input" {
		// Windows may put TEMP on a different drive from the checkout. A
		// relative CLI argument must be constructed on the working drive.
		local, err := os.MkdirTemp(".", ".codesign-alias-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(local); err != nil {
				t.Error(err)
			}
		})
		dir, err = filepath.Abs(local)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "real", "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	f := standaloneAlias{target: filepath.Join(dir, "real", "actual-tool"), neighbour: filepath.Join(dir, "real", "neighbour"), decoy: filepath.Join(dir, "actual-tool"), links: map[string]string{}}
	for _, p := range []string{f.target, f.decoy} {
		if err := os.WriteFile(p, data, 0751); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(f.target, f.neighbour); err != nil {
		t.Fatal(err)
	}
	alias, target := filepath.Join(dir, "alias-name"), filepath.Join("real", "actual-tool")
	switch kind {
	case "absolute":
		target = f.target
	case "chain":
		f.links[filepath.Join(dir, "second-alias")] = target
		target = "second-alias"
	case "parent":
		alias, target = filepath.Join(dir, "parent-alias"), filepath.Join("real", "nested")
	}
	f.links[alias] = target
	for name, destination := range f.links {
		if err := os.Symlink(destination, name); err != nil {
			t.Fatal(err)
		}
	}
	f.input = alias
	if kind == "parent" {
		// Join/Clean would erase the very path semantics under test.
		f.input += string(filepath.Separator) + ".." + string(filepath.Separator) + "actual-tool"
	}
	if kind == "relative-input" {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		f.input, err = filepath.Rel(cwd, alias)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f standaloneAlias) checkLinks(t *testing.T) {
	t.Helper()
	for name, destination := range f.links {
		got, err := os.Readlink(name)
		if err != nil || got != destination {
			t.Fatalf("alias changed: %s -> %q, want %q: %v", name, got, destination, err)
		}
	}
}

func checkAliasDisplay(t *testing.T, f standaloneAlias) {
	t.Helper()
	physical, err := filepath.EvalSymlinks(f.target)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"-d", "-dv", "-dvv", "-dvvv", "-dvvvv"} {
		out, stderr, code := run(t, binaryPath, flag, f.input)
		if code != 0 || !strings.HasPrefix(stderr, "Executable="+physical+"\n") {
			t.Fatalf("display did not select physical target: %d %s%s", code, out, stderr)
		}
		if runtime.GOOS == "darwin" {
			no, ne, nc := run(t, apple(t), flag, f.input)
			if out != no || stderr != ne || code != nc {
				t.Fatalf("alias display mismatch (%s):\nGo: %d %s%s\nApple: %d %s%s", flag, code, out, stderr, nc, no, ne)
			}
		}
	}
}

func TestStandaloneSymlinkWrites(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, kind := range []string{"relative", "absolute", "chain", "parent", "relative-input"} {
			for _, identifier := range []string{"default", "explicit"} {
				for _, operation := range []string{"sign", "resign", "remove", "remove-unsigned", "dryrun"} {
					t.Run(arch+"/"+kind+"/"+identifier+"/"+operation, func(t *testing.T) {
						fixture := "unsigned-" + arch
						args := []string{"-fs", "-", "--timestamp=none"}
						if identifier == "explicit" {
							args = append(args, "-i", "org.example.alias")
						}
						if operation == "resign" || operation == "remove" {
							fixture = "adhoc-" + arch
						}
						if strings.HasPrefix(operation, "remove") {
							args = []string{"--remove-signature"}
						} else if operation == "dryrun" {
							args = append(args, "--dryrun")
						}
						input := nativeRead(t, filepath.Join(root, "testdata", "macho", fixture))
						execute := func(exe string) []byte {
							f := newStandaloneAlias(t, kind, input)
							before, err := os.Stat(f.target)
							if err != nil {
								t.Fatal(err)
							}
							linked, err := os.Stat(f.neighbour)
							// Cache Windows FileInfo IDs before rename (resolved lazily).
							if err != nil || !os.SameFile(before, linked) {
								t.Fatalf("input not hard linked: %v", err)
							}
							mustRun(t, exe, append(args, f.input)...)
							f.checkLinks(t)
							after, err := os.Stat(f.target)
							if err != nil {
								t.Fatal(err)
							}
							other, err := os.Stat(f.neighbour)
							if err != nil || !os.SameFile(before, other) || os.SameFile(before, after) != (operation == "dryrun") || after.Mode() != before.Mode() {
								t.Fatalf("wrong target/neighbor inode or mode outcome: %v", err)
							}
							for _, p := range []string{f.neighbour, f.decoy} {
								nativeEqual(t, "untouched neighbour "+p, nativeRead(t, p), input)
							}
							if operation == "dryrun" {
								nativeEqual(t, "dryrun unchanged", nativeRead(t, f.target), input)
							}
							if operation == "sign" || operation == "resign" {
								mustRun(t, binaryPath, "--verify", f.input)
								if runtime.GOOS == "darwin" {
									mustRun(t, apple(t), "--verify", "--strict", f.input)
								}
								if exe == binaryPath {
									checkAliasDisplay(t, f)
								}
							}
							entries, err := os.ReadDir(filepath.Dir(f.target))
							if err != nil || len(entries) != 3 {
								t.Fatalf("staging leaked: %v %v", entries, err)
							}
							return nativeRead(t, f.target)
						}
						got := execute(binaryPath)
						if runtime.GOOS == "darwin" {
							nativeEqual(t, "native alias output", got, execute(apple(t)))
						}
						attest(t, map[string]any{"architecture": arch, "alias": kind, "identifier": identifier, "operation": operation, "aliases_preserved": true, "neighbours_preserved": true, "inode_replaced": operation != "dryrun", "native_byte_equal": runtime.GOOS == "darwin", "output_sha256": hash(got)})
					})
				}
			}
		}
	}
}

func TestDMGSymlinkWritesRemainInPlace(t *testing.T) {
	for _, kind := range []string{"relative", "absolute", "chain", "parent", "relative-input"} {
		for _, identifier := range []string{"default", "explicit"} {
			t.Run(kind+"/"+identifier, func(t *testing.T) {
				input := dmgFixture(t, "raw")
				execute := func(exe string) []byte {
					f := newStandaloneAlias(t, kind, input)
					before, err := os.Stat(f.target)
					if err != nil {
						t.Fatal(err)
					}
					linked, err := os.Stat(f.neighbour)
					if err != nil || !os.SameFile(before, linked) {
						t.Fatalf("DMG input not linked: %v", err)
					}
					args := []string{"-fs", "-", "--timestamp=none"}
					if identifier == "explicit" {
						args = append(args, "-i", "org.example.alias.dmg")
					}
					for range 2 { // signing and re-signing must retain both names
						mustRun(t, exe, append(args, f.input)...)
						f.checkLinks(t)
						after, err := os.Stat(f.target)
						if err != nil || !os.SameFile(before, after) {
							t.Fatalf("DMG target replaced: %v", err)
						}
						nativeEqual(t, "shared DMG bytes", nativeRead(t, f.target), nativeRead(t, f.neighbour))
						nativeEqual(t, "untouched lexical neighbour", nativeRead(t, f.decoy), input)
						mustRun(t, binaryPath, "--verify", f.input)
						if runtime.GOOS == "darwin" {
							mustRun(t, apple(t), "--verify", "--strict", f.input)
						}
					}
					if exe == binaryPath {
						checkAliasDisplay(t, f)
					}
					return nativeRead(t, f.target)
				}
				got := execute(binaryPath)
				if runtime.GOOS == "darwin" {
					nativeEqual(t, "native DMG alias output", got, execute(apple(t)))
				}
				attest(t, map[string]any{"alias": kind, "identifier": identifier, "inode_retained": true, "aliases_preserved": true, "native_byte_equal": runtime.GOOS == "darwin", "output_sha256": hash(got)})
			})
		}
	}
}

func TestResigningAllocationPreservesTrailingBytes(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, identifier := range []string{"x", "org.example.alias", "org.example.a.much.longer.replacement.identifier"} {
			t.Run(arch+"/"+identifier, func(t *testing.T) {
				input := nativeRead(t, filepath.Join(root, "testdata", "macho", "adhoc-"+arch))
				r, err := codesign.InspectBytes(input)
				if err != nil {
					t.Fatal(err)
				}
				// Use nonzero allocation padding to expose both preservation and
				// zero initialization of any newly allocated bytes after growth.
				for _, a := range r.Architectures {
					start := a.Offset + a.SignatureOffset
					length := uint64(binary.BigEndian.Uint32(input[start+4:]))
					for i := start + length; i < start+uint64(a.SignatureSize); i++ {
						input[i] = 0xa5
					}
				}
				execute := func(exe string) []byte {
					p := filepath.Join(t.TempDir(), "actual-tool")
					if err := os.WriteFile(p, input, 0755); err != nil {
						t.Fatal(err)
					}
					mustRun(t, exe, "-fs", "-", "--timestamp=none", "-i", identifier, p)
					mustRun(t, binaryPath, "--verify", p)
					if runtime.GOOS == "darwin" {
						mustRun(t, apple(t), "--verify", "--strict", p)
					}
					return nativeRead(t, p)
				}
				got := execute(binaryPath)
				if runtime.GOOS == "darwin" {
					nativeEqual(t, "native allocation padding", got, execute(apple(t)))
				}
				attest(t, map[string]any{"architecture": arch, "identifier": identifier, "native_byte_equal": runtime.GOOS == "darwin", "output_sha256": hash(got)})
			})
		}
	}
}

func TestBrokenAndLoopingAliasesFailWithoutWrites(t *testing.T) {
	for _, kind := range []string{"broken", "loop"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "alias")
			target := "absent"
			if kind == "loop" {
				target = "alias"
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			executables := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				executables = append(executables, apple(t))
			}
			for _, exe := range executables {
				for _, args := range [][]string{{"-s", "-"}, {"-d"}, {"--verify"}, {"--remove-signature"}} {
					_, stderr, code := run(t, exe, append(args, path)...)
					if code == 0 {
						t.Fatalf("%s accepted %s %v: %s", exe, kind, args, stderr)
					}
					got, err := os.Readlink(path)
					if err != nil || got != target {
						t.Fatal("failure changed alias", got, err)
					}
					entries, err := os.ReadDir(dir)
					if err != nil || len(entries) != 1 {
						t.Fatal("failure created files", entries, err)
					}
				}
			}
			attest(t, map[string]any{"alias": kind, "failed_operations": 4, "alias_preserved": true, "no_files_created": true, "native_compared": runtime.GOOS == "darwin"})
		})
	}
}
