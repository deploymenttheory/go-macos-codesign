package acceptance

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

// These inputs come from independently recorded native signatures. Boundary
// mutations exercise deallocation, not validity of the altered signature.
func removalInputs(t *testing.T) map[string][]byte {
	t.Helper()
	inputs := map[string][]byte{}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mode := range []string{"adhoc", "runtime", "unsigned"} {
			inputs[mode+"-"+arch] = nativeRead(t, filepath.Join(root, "testdata/macho", mode+"-"+arch))
		}
		for _, identity := range []string{"rsa", "p256", "p384", "p521"} {
			inputs[identity+"-"+arch] = nativeRead(t, filepath.Join(root, "testdata/certificate-layout", identity+"-"+arch))
		}
		for _, kind := range []string{"bundle", "framework"} {
			dir := filepath.Join(t.TempDir(), "Fixture."+kind)
			extractLayout(t, nativeRead(t, filepath.Join(root, "testdata/layouts", kind+"-"+arch+".tar")), dir)
			_, base, _, executable := layoutPaths(kind)
			inputs[kind+"-"+arch] = nativeRead(t, filepath.Join(dir, base+executable))
		}
	}
	base := inputs["adhoc-arm64"]
	f, err := macho.NewFile(bytes.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	sig, sym, link, pos := 0, 0, 0, 32
	for _, load := range f.Loads {
		switch f.ByteOrder.Uint32(load.Raw()) {
		case 0x1d:
			sig = pos
		case 2:
			sym = pos
		}
		if s, ok := load.(*macho.Segment); ok && s.Name == "__LINKEDIT" {
			link = pos
		}
		pos += len(load.Raw())
	}
	if sig == 0 || sym == 0 || link == 0 {
		t.Fatal("missing probe commands")
	}
	o := f.ByteOrder
	for _, gap := range []uint32{0, 4, 12, 13, 16} {
		b := bytes.Clone(base)
		o.PutUint32(b[sym+20:], o.Uint32(b[sig+8:])-gap-o.Uint32(b[sym+16:]))
		inputs[fmt.Sprintf("string-gap-%d", gap)] = b
	}
	for _, name := range []string{"nonzero-padding", "zero-string-tail", "trailer-1", "trailer-7", "vm-large", "vm-zero", "dylinker", "kext"} {
		b := bytes.Clone(base)
		sigOffset := int(o.Uint32(b[sig+8:]))
		switch name {
		case "nonzero-padding":
			for i := sigOffset - 8; i < sigOffset; i++ {
				b[i] = 0x7f
			}
		case "zero-string-tail":
			clear(b[sigOffset-16 : sigOffset])
		case "trailer-1":
			b = append(b, 0x7f)
		case "trailer-7":
			b = append(b, bytes.Repeat([]byte{0x7f}, 7)...)
		case "vm-large":
			o.PutUint64(b[link+32:], 65536)
		case "vm-zero":
			o.PutUint64(b[link+32:], 0)
		case "dylinker":
			o.PutUint32(b[12:], 7)
		case "kext":
			o.PutUint32(b[12:], 11)
		}
		inputs[name] = b
	}
	for _, alignment := range []uint32{12, 16} {
		inputs[fmt.Sprintf("fat-align-%d", alignment)] = removalFat(t, inputs["adhoc-universal"], alignment, nil)
	}
	inputs["fat-unsigned"] = removalFat(t, inputs["unsigned-universal"], 12, nil)
	inputs["fat-mixed"] = removalFat(t, inputs["adhoc-universal"], 12, inputs["unsigned-arm64"])
	return inputs
}

// Independently repack the two recorded slices, including lower/higher-than-
// native alignment and a mixture of signed and unsigned architectures.
func removalFat(t *testing.T, data []byte, alignment uint32, unsigned []byte) []byte {
	t.Helper()
	f, err := macho.NewFatFile(bytes.NewReader(data))
	if err != nil || len(f.Arches) != 2 {
		t.Fatal(f, err)
	}
	o := binary.BigEndian
	out := bytes.Clone(data[:48])
	for i, arch := range f.Arches {
		part := data[arch.Offset : arch.Offset+arch.Size]
		if arch.Cpu == macho.CpuArm64 && unsigned != nil {
			part = unsigned
		}
		a := 1 << alignment
		offset := (len(out) + a - 1) &^ (a - 1)
		out = append(out, make([]byte, offset-len(out))...)
		out = append(out, part...)
		p := 8 + i*20
		o.PutUint32(out[p+8:], uint32(offset))
		o.PutUint32(out[p+12:], uint32(len(part)))
		o.PutUint32(out[p+16:], alignment)
	}
	return out
}

func TestRecordAppleRemovalFixtures(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_RECORD_REMOVAL") != "1" {
		t.Skip("opt-in native removal recording")
	}
	reference := apple(t)
	dir := filepath.Join(root, "testdata/removal")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "README.md" {
			t.Fatal("refusing to overwrite", entry.Name())
		}
	}
	hashes, inputs := map[string]string{}, map[string]string{}
	for name, data := range removalInputs(t) {
		path := filepath.Join(t.TempDir(), name)
		bundleWrite(t, filepath.Dir(path), name, data)
		mustRun(t, reference, "--remove-signature", path)
		out := nativeRead(t, path)
		assertRemoved(t, out)
		bundleWrite(t, dir, name+".macho", out)
		hashes[name+".macho"], inputs[name] = hash(out), hash(data)
	}
	host, _, _ := run(t, "/usr/bin/sw_vers")
	record := map[string]any{"schema": 1, "files": hashes, "input_sha256": inputs, "host": strings.TrimSpace(host), "codesign_sha256": hash(nativeRead(t, reference)), "source": "acceptance/removal_test.go: removalInputs and TestRecordAppleRemovalFixtures", "arguments": []string{"--remove-signature", "<input>"}, "scope": "Native deallocation of recorded signatures and explicit layout mutations; mutated signatures are not claimed valid or runnable. No Go implementation generates expected outputs."}
	b, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	bundleWrite(t, dir, "manifest.json", append(b, '\n'))
}

func assertRemoved(t *testing.T, data []byte) {
	t.Helper()
	r, err := codesign.InspectBytes(data)
	if err != nil || len(r.Architectures) == 0 {
		t.Fatal("invalid removed Mach-O", r, err)
	}
	for _, arch := range r.Architectures {
		if arch.Signature != nil {
			t.Fatal("retained signature", arch.Name)
		}
	}
}

func TestPortableRemovalFixtures(t *testing.T) {
	var manifest struct {
		Inputs map[string]string `json:"input_sha256"`
	}
	if err := json.Unmarshal(nativeRead(t, filepath.Join(root, "testdata/removal/manifest.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	inputs := removalInputs(t)
	if len(inputs) != len(manifest.Inputs) || len(inputs) != 44 {
		t.Fatal("incomplete removal corpus", len(inputs), len(manifest.Inputs))
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			if hash(data) != manifest.Inputs[name] {
				t.Fatal("native input provenance mismatch", hash(data), manifest.Inputs[name])
			}
			path := filepath.Join(t.TempDir(), name)
			bundleWrite(t, filepath.Dir(path), name, data)
			mustRun(t, binaryPath, "--remove-signature", path)
			got := nativeRead(t, path)
			want := nativeRead(t, filepath.Join(root, "testdata/removal", name+".macho"))
			nativeEqual(t, "native removal fixture", got, want)
			assertRemoved(t, got)
			mustRun(t, binaryPath, "--remove-signature", path)
			nativeEqual(t, "idempotent removal", nativeRead(t, path), want)
			if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
				bundleWrite(t, export, "removed-"+name+".macho", got)
			}
			attest(t, map[string]any{"native_removal_bytes_equal": true, "idempotent": true, "input_sha256": hash(data), "output_sha256": hash(got)})
		})
	}
}

func TestAppleRemovalParity(t *testing.T) {
	reference := apple(t)
	for name, data := range removalInputs(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, tool := range []struct{ name, program string }{{"native", reference}, {"portable", binaryPath}} {
				bundleWrite(t, dir, tool.name, data)
				mustRun(t, tool.program, "--remove-signature", filepath.Join(dir, tool.name))
			}
			got, want := nativeRead(t, filepath.Join(dir, "portable")), nativeRead(t, filepath.Join(dir, "native"))
			nativeEqual(t, "live native removal", got, want)
			assertRemoved(t, got)
			attest(t, map[string]any{"native_removal_bytes_equal": true, "input_sha256": hash(data), "output_sha256": hash(got)})
		})
	}
}

func TestAppleRemovalResigning(t *testing.T) {
	reference := apple(t)
	inputs := removalInputs(t)
	for _, kind := range []string{"adhoc", "bundle", "framework"} {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			t.Run(kind+"/"+arch, func(t *testing.T) {
				dir := t.TempDir()
				for _, tool := range []struct{ name, program string }{{"native", reference}, {"portable", binaryPath}} {
					path := filepath.Join(dir, tool.name)
					bundleWrite(t, dir, tool.name, inputs[kind+"-"+arch])
					mustRun(t, tool.program, "--remove-signature", path)
					mustRun(t, tool.program, "-s", "-", "-i", "org.example.resigned", "--timestamp=none", path)
					mustRun(t, reference, "--verify", "--strict", path)
				}
				nativeEqual(t, "re-signed after removal", nativeRead(t, filepath.Join(dir, "portable")), nativeRead(t, filepath.Join(dir, "native")))
				attest(t, map[string]any{"architecture": arch, "kind": kind, "resigned_bytes_equal": true, "native_strict_verified": true})
			})
		}
	}
}

func TestVerifyImportedRemoval(t *testing.T) {
	dir := os.Getenv("MACOSCODESIGN_IMPORT_DIR")
	if dir == "" {
		return
	}
	reference := apple(t)
	inputs, expected, seen := removalInputs(t), map[string][]byte{}, map[string]int{}
	for name, data := range inputs {
		path := filepath.Join(t.TempDir(), name)
		bundleWrite(t, filepath.Dir(path), name, data)
		mustRun(t, reference, "--remove-signature", path)
		expected[name] = nativeRead(t, path)
	}
	count := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "removed-") {
			return nil
		}
		name := strings.TrimSuffix(strings.TrimPrefix(d.Name(), "removed-"), ".macho")
		if expected[name] == nil {
			t.Fatal("unexpected removed artifact", name)
		}
		nativeEqual(t, "foreign removal "+path, nativeRead(t, path), expected[name])
		seen[name]++
		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range inputs {
		if seen[name] != 2 {
			t.Fatal("expected Linux and Windows removal artifacts", name, seen[name])
		}
	}
	attest(t, map[string]any{"imported_removed_artifacts_byte_equal": count, "native_removal_cases": len(inputs)})
}
