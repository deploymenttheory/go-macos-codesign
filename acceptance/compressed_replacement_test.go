package acceptance

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Live compression storage requires a Darwin filesystem. Portable logical-byte
// signing remains covered by the shared mutation matrix; this oracle additionally
// checks the hidden native storage that the replacement writer must discard.
// Recompression (--preserve-afsc) is a separate, still-open phase obligation.
func TestCompressedReplacementNative(t *testing.T) {
	native := apple(t)
	dir := t.TempDir()
	var module struct{ Dir string }
	out, diagnostic, exit := run(t, "go", "list", "-m", "-json", "github.com/deploymenttheory/go-apfs-v2")
	if exit != 0 {
		t.Fatal(diagnostic)
	}
	if err := json.Unmarshal([]byte(out), &module); err != nil {
		t.Fatal(err)
	}
	producer := filepath.Join(dir, "producer")
	observer := filepath.Join(dir, "observer")
	mustRun(t, "clang", "-Wall", "-Wextra", "-framework", "CoreFoundation", filepath.Join(module.Dir, "testdata/appledouble/native/decmpfs-formats.c"), "-o", producer)
	mustRun(t, "clang", "-Wall", "-Wextra", filepath.Join(root, "testdata/research/compressed-signing.c"), "-o", observer)
	type storage struct {
		Flags                 uint32 `json:"flags"`
		Size                  int64  `json:"size"`
		Data, Attribute, Fork []byte
	}
	snapshot := func(t *testing.T, path string) storage {
		t.Helper()
		prefix := filepath.Join(t.TempDir(), "storage")
		out, diagnostic, exit := run(t, observer, path, prefix)
		if exit != 0 {
			t.Fatal(diagnostic)
		}
		var s storage
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			t.Fatal(err)
		}
		s.Data = nativeRead(t, path)
		for suffix, target := range map[string]*[]byte{".attr": &s.Attribute, ".fork": &s.Fork} {
			b, err := os.ReadFile(prefix + suffix)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			*target = b
		}
		return s
	}
	for _, codec := range []string{"3", "7", "11"} {
		for _, shape := range []string{"standalone", "bundle"} {
			for _, operation := range []string{"sign", "resign", "dryrun", "remove"} {
				t.Run(fmt.Sprintf("codec-%s/%s/%s", codec, shape, operation), func(t *testing.T) {
					var states [2]storage
					var identities [2]bool
					var envelopes [2][]byte
					var envelopePresent [2]bool
					for i, tool := range []string{native, binaryPath} {
						base := t.TempDir()
						operand := filepath.Join(base, "hello")
						executable := operand
						if shape == "bundle" {
							operand = filepath.Join(base, "Compression.app")
							executable = filepath.Join(operand, "Contents/MacOS/hello")
							if err := os.MkdirAll(filepath.Dir(executable), 0755); err != nil {
								t.Fatal(err)
							}
							info := []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>hello</string><key>CFBundleIdentifier</key><string>org.example.compression</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>`)
							if err := os.WriteFile(filepath.Join(operand, "Contents/Info.plist"), info, 0644); err != nil {
								t.Fatal(err)
							}
						}
						if err := os.WriteFile(executable, nativeRead(t, filepath.Join(root, "testdata/removal/unsigned-arm64.macho")), 0755); err != nil {
							t.Fatal(err)
						}
						args := []string{"-s", "-", "-i", "org.example.compression", "--timestamp=none"}
						if operation == "resign" || operation == "remove" {
							mustRun(t, native, append(args, operand)...)
						}
						mustRun(t, producer, "produce", codec, executable, filepath.Join(base, "produced"))
						before := snapshot(t, executable)
						if before.Flags&0x20 == 0 || len(before.Attribute) < 16 {
							t.Fatal("producer did not create native compression")
						}
						kind := binary.LittleEndian.Uint32(before.Attribute[4:8])
						requested := map[string]uint32{"3": 3, "7": 7, "11": 11}[codec]
						if kind != requested && kind != requested+1 {
							t.Fatalf("producer substituted compression codec: requested=%s actual=%d", codec, kind)
						}
						t.Logf("tool=%s compression_type=%d logical_bytes=%d fork_bytes=%d", tool, kind, len(before.Data), len(before.Fork))
						identity, err := os.Stat(executable)
						if err != nil {
							t.Fatal(err)
						}
						switch operation {
						case "resign":
							args = append(args, "-f")
						case "dryrun":
							args = append(args, "--dryrun")
						case "remove":
							args = []string{"--remove-signature"}
						}
						mustRun(t, tool, append(args, operand)...)
						states[i] = snapshot(t, executable)
						after, err := os.Stat(executable)
						if err != nil {
							t.Fatal(err)
						}
						identities[i] = os.SameFile(identity, after)
						if operation == "dryrun" && (!bytes.Equal(before.Data, states[i].Data) || !bytes.Equal(before.Attribute, states[i].Attribute) || !bytes.Equal(before.Fork, states[i].Fork)) {
							t.Fatal("dry run changed compressed storage")
						}
						if shape == "bundle" {
							envelopes[i], err = os.ReadFile(filepath.Join(operand, "Contents/_CodeSignature/CodeResources"))
							envelopePresent[i] = err == nil
							if err != nil && !os.IsNotExist(err) {
								t.Fatal(err)
							}
						}
						if operation == "sign" || operation == "resign" {
							mustRun(t, native, "--verify", "--strict", operand)
						}
					}
					a, b := states[0], states[1]
					if envelopePresent[0] != envelopePresent[1] {
						t.Fatalf("native/Go envelope presence differs: %v", envelopePresent)
					}
					if a.Flags != b.Flags || a.Size != b.Size || identities[0] != identities[1] {
						t.Fatalf("native/Go flags=%#x/%#x size=%d/%d same identity=%v", a.Flags, b.Flags, a.Size, b.Size, identities)
					}
					for label, pair := range map[string][2][]byte{"logical bytes": {a.Data, b.Data}, "compression header": {a.Attribute, b.Attribute}, "resource fork": {a.Fork, b.Fork}, "bundle envelope": envelopes} {
						nativeEqual(t, label, pair[1], pair[0])
					}
				})
			}
		}
	}
}
