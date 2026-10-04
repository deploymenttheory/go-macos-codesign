package acceptance

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

type largeSigningCase struct {
	ContentLength              int64 `json:"content_length"`
	Prefix, Signature, Trailer []byte
	DrySignature               []byte `json:"dry_signature"`
	DryTrailer                 []byte `json:"dry_trailer"`
}

func largeSigningCases(t *testing.T) []largeSigningCase {
	t.Helper()
	var capture struct{ Cases []largeSigningCase }
	if err := json.Unmarshal(nativeRead(t, filepath.Join(root, "testdata/research/large-source.json")), &capture); err != nil {
		t.Fatal(err)
	}
	if len(capture.Cases) != 9 {
		t.Fatal("missing large signing cases")
	}
	return capture.Cases
}

func reconstructLargeDMG(t *testing.T, tc largeSigningCase, signature, trailer []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "large.dmg")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := prepareSparseFixture(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(tc.ContentLength + int64(len(signature)+len(trailer))); err != nil {
		t.Fatal(err)
	}
	for _, part := range []struct {
		at   int64
		data []byte
	}{{0, tc.Prefix}, {tc.ContentLength, signature}, {tc.ContentLength + int64(len(signature)), trailer}} {
		if _, err := f.WriteAt(part.data, part.at); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func largeDMGTail(t *testing.T, path string, offset int64) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() < offset+512 || st.Size()-offset > 1<<20 {
		t.Fatal("unexpected tail size", st.Size())
	}
	b := make([]byte, st.Size()-offset)
	if _, err = f.ReadAt(b, offset); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLargeDMGSigning(t *testing.T) {
	for _, tc := range largeSigningCases(t) {
		t.Run(fmt.Sprint(tc.ContentLength), func(t *testing.T) {
			var footer disk.DMGFooter
			if err := binary.Read(bytes.NewReader(tc.Trailer), binary.BigEndian, &footer); err != nil {
				t.Fatal(err)
			}
			footer.CodeSignatureOffset, footer.CodeSignatureLength = 0, 0
			var unsigned bytes.Buffer
			if err := binary.Write(&unsigned, binary.BigEndian, footer); err != nil {
				t.Fatal(err)
			}
			path := reconstructLargeDMG(t, tc, nil, unsigned.Bytes())
			before := accessFileInfo(t, path)
			link := filepath.Join(filepath.Dir(path), "hardlink.dmg")
			if err := os.Link(path, link); err != nil {
				t.Fatal(err)
			}
			args := []string{"-s", "-", "-i", "org.example.large-source", "--timestamp=none"}
			for _, operation := range []string{"sign", "resign", "dryrun", "recover"} {
				command := append([]string{}, args...)
				if operation == "resign" || operation == "dryrun" {
					command = append(command, "-f")
				}
				if operation == "dryrun" {
					command = append(command, "--dryrun")
				}
				started := time.Now()
				mustRun(t, binaryPath, append(command, path)...)
				t.Logf("operation=%s content=%d elapsed=%s", operation, tc.ContentLength, time.Since(started))
				want := append(bytes.Clone(tc.Signature), tc.Trailer...)
				if operation == "dryrun" {
					want = append(bytes.Clone(tc.DrySignature), tc.DryTrailer...)
				}
				for _, name := range []string{path, link} {
					if !os.SameFile(before, accessFileInfo(t, name)) {
						t.Fatal("changed inode", operation, name)
					}
					nativeEqual(t, "complete native tail "+operation, largeDMGTail(t, name, tc.ContentLength), want)
				}
				if operation == "dryrun" {
					assertUnsignedDMG(t, binaryPath, path)
				} else {
					mustRun(t, binaryPath, "--verify", "--strict", path)
				}
				if runtime.GOOS == "darwin" {
					if operation == "dryrun" {
						assertUnsignedDMG(t, apple(t), path)
					} else {
						mustRun(t, apple(t), "--verify", "--strict", path)
					}
				}
			}
			// Export only the actual produced tail plus the independently captured
			// sparse payload recipe. The Mac reconstructs and hashes the full file.
			if dir := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); dir != "" {
				tail := largeDMGTail(t, path, tc.ContentLength)
				tc.Signature, tc.Trailer = tail[:len(tail)-512], tail[len(tail)-512:]
				data, err := json.Marshal(tc)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("large-dmg-%d.json", tc.ContentLength)), data, 0644); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestVerifyImportedLargeDMGs(t *testing.T) {
	dir := os.Getenv("MACOSCODESIGN_IMPORT_DIR")
	if dir == "" {
		return
	}
	reference := apple(t)
	want := map[string]largeSigningCase{}
	for _, tc := range largeSigningCases(t) {
		want[fmt.Sprintf("large-dmg-%d.json", tc.ContentLength)] = tc
	}
	seen := map[string]int{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "large-dmg-") {
			return nil
		}
		tc, ok := want[d.Name()]
		if !ok {
			t.Fatalf("unexpected large DMG %s", path)
		}
		var got largeSigningCase
		if err := json.Unmarshal(nativeRead(t, path), &got); err != nil {
			return err
		}
		if got.ContentLength != tc.ContentLength || !bytes.Equal(got.Prefix, tc.Prefix) || !bytes.Equal(got.Signature, tc.Signature) || !bytes.Equal(got.Trailer, tc.Trailer) || !bytes.Equal(got.DrySignature, tc.DrySignature) || !bytes.Equal(got.DryTrailer, tc.DryTrailer) {
			t.Fatal("foreign recipe differs from native", path)
		}
		image := reconstructLargeDMG(t, got, got.Signature, got.Trailer)
		mustRun(t, reference, "--verify", "--strict", image)
		if err := os.Remove(image); err != nil {
			return err
		}
		seen[d.Name()]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range want {
		if seen[name] != 2 {
			t.Fatalf("expected both producers for %s, got %d", name, seen[name])
		}
	}
	attest(t, map[string]any{"large_images_verified": 18, "native_tail_equality": true, "full_payload_hashed": true})
}
