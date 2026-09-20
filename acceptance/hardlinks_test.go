package acceptance

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStandaloneHardlinkWrites(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mode := range []string{"sign", "resign", "remove", "remove-unsigned", "dryrun"} {
			t.Run(arch+"/"+mode, func(t *testing.T) {
				fixture := "unsigned-" + arch
				args := []string{"-fs", "-", "-i", "org.example.hardlink", "--timestamp=none"}
				switch mode {
				case "resign":
					fixture = "adhoc-" + arch
				case "remove":
					fixture = "adhoc-" + arch
					args = []string{"--remove-signature"}
				case "remove-unsigned":
					args = []string{"--remove-signature"}
				case "dryrun":
					args = append(args, "--dryrun")
				}
				input := nativeRead(t, filepath.Join(root, "testdata/macho", fixture))
				execute := func(exe string) []byte {
					dir := t.TempDir()
					path, neighbour := filepath.Join(dir, "target"), filepath.Join(dir, "neighbour")
					if err := os.WriteFile(path, input, 0751); err != nil {
						t.Fatal(err)
					}
					if err := os.Link(path, neighbour); err != nil {
						t.Fatal(err)
					}
					before, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					mustRun(t, exe, append(args, path)...)
					after, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					other, err := os.Stat(neighbour)
					if err != nil {
						t.Fatal(err)
					}
					if os.SameFile(before, after) != (mode == "dryrun") || !os.SameFile(before, other) {
						t.Fatal("incorrect hard-link detachment")
					}
					if before.Mode() != after.Mode() {
						t.Fatalf("mode changed: %v -> %v", before.Mode(), after.Mode())
					}
					nativeEqual(t, "neighbour unchanged", nativeRead(t, neighbour), input)
					if mode == "dryrun" {
						nativeEqual(t, "dryrun unchanged", nativeRead(t, path), input)
					}
					if mode == "sign" || mode == "resign" {
						mustRun(t, binaryPath, "--verify", path)
						if runtime.GOOS == "darwin" {
							mustRun(t, apple(t), "--verify", "--strict", path)
						}
					}
					entries, err := os.ReadDir(dir)
					if err != nil || len(entries) != 2 {
						t.Fatalf("staging cleanup: %v %v", entries, err)
					}
					return nativeRead(t, path)
				}
				got := execute(binaryPath)
				if runtime.GOOS == "darwin" {
					nativeEqual(t, "native hard-link output", got, execute(apple(t)))
				}
				attest(t, map[string]any{"architecture": arch, "operation": mode, "neighbour_preserved": true, "inode_replaced": mode != "dryrun", "native_byte_equal": runtime.GOOS == "darwin", "output_sha256": hash(got)})
			})
		}
	}
}

func TestDMGHardlinkWritesRemainInPlace(t *testing.T) {
	execute := func(exe string) []byte {
		dir := t.TempDir()
		path, other := filepath.Join(dir, "target.dmg"), filepath.Join(dir, "neighbour.dmg")
		if err := os.WriteFile(path, dmgFixture(t, "raw"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, other); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		mustRun(t, exe, "-s", "-", "-i", "org.example.hardlink.dmg", "--timestamp=none", path)
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		neighbour, err := os.Stat(other)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) || !os.SameFile(before, neighbour) {
			t.Fatal("DMG inode replaced")
		}
		nativeEqual(t, "DMG names share modified data", nativeRead(t, path), nativeRead(t, other))
		mustRun(t, binaryPath, "--verify", other)
		return nativeRead(t, path)
	}
	got := execute(binaryPath)
	if runtime.GOOS == "darwin" {
		nativeEqual(t, "native hard-link DMG", got, execute(apple(t)))
	}
	attest(t, map[string]any{"inode_retained": true, "both_names_verified": true, "native_byte_equal": runtime.GOOS == "darwin"})
}
