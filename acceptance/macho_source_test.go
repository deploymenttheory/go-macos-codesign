package acceptance

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type largeMachOOutcome struct {
	Exit       int    `json:"exit"`
	Diagnostic string `json:"diagnostic"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
}
type largeMachOCase struct {
	Populated                            bool   `json:"populated"`
	Name                                 string `json:"name"`
	Length                               int64  `json:"length"`
	Prefix                               []byte `json:"prefix"`
	Sign, Resign, DryRun, Remove, Verify largeMachOOutcome
}

func largeMachOCases(t *testing.T) []largeMachOCase {
	t.Helper()
	var capture struct{ Cases []largeMachOCase }
	if err := json.Unmarshal(nativeRead(t, filepath.Join(root, "testdata/research/large-macho.json")), &capture); err != nil {
		t.Fatal(err)
	}
	if len(capture.Cases) != 12 {
		t.Fatal("incomplete native Mach-O capture")
	}
	return capture.Cases
}

func assertLargeMachO(t *testing.T, path string, want largeMachOOutcome) {
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
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != want.Size || n != want.Size || hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
		t.Fatalf("full native byte comparison: length=%d/%d digest=%x/%s", n, want.Size, h.Sum(nil), want.SHA256)
	}
}

func exportLargeMachO(t *testing.T, path, name string) {
	t.Helper()
	dir := os.Getenv("MACOSCODESIGN_EXPORT_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	f, err := os.Create(filepath.Join(dir, "large-macho-"+name+".gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(z, source); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLargeMachOMutation(t *testing.T) {
	for _, tc := range largeMachOCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			// Use the runner's provisioned scratch storage for multi-GiB copies.
			// A local run keeps the normal OS temporary directory. Every case
			// still performs the full physical transfer and 30-second CLI check.
			dir, err := os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "codesign-large-macho-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(dir); err != nil {
					t.Error(err)
				}
			})
			path := filepath.Join(dir, "large.macho")
			t.Logf("fixture=%s logical_length=%d", path, tc.Length)
			f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0755)
			if err != nil {
				t.Fatal(err)
			}
			if err := prepareSparseFixture(f); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write(tc.Prefix); err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(tc.Length); err != nil {
				t.Fatal(err)
			}
			if tc.Populated {
				data := make([]byte, 4<<20+37)
				for i := range data {
					data[i] = byte(i % 251)
				}
				if _, err := f.WriteAt(data, 1<<29-17); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			args := []string{"-s", "-", "-i", "org.example.large-macho", "--timestamp=none"}
			type operation struct {
				name string
				args []string
				want largeMachOOutcome
			}
			operations := []operation{{"sign", args, tc.Sign}}
			if tc.Sign.Exit == 0 {
				operations = append(operations,
					operation{"resign", append([]string{"-f"}, args...), tc.Resign},
					operation{"dryrun", append([]string{"-f", "--dryrun"}, args...), tc.DryRun})
			}
			operations = append(operations, operation{"remove", []string{"--remove-signature"}, tc.Remove})
			for _, op := range operations {
				before := accessFileInfo(t, path)
				link := path + ".link"
				if err := os.Link(path, link); err != nil {
					t.Fatal(err)
				}
				// Windows Stat defers loading file IDs until SameFile. Capture
				// both identities before replacement, as in the writer harness.
				if !os.SameFile(before, accessFileInfo(t, link)) {
					t.Fatal("initial hard-link identity")
				}
				started := time.Now()
				out, diagnostic, exit := run(t, binaryPath, append(op.args, path)...)
				t.Logf("operation=%s length=%d elapsed=%s", op.name, tc.Length, time.Since(started))
				if out != "" || exit != op.want.Exit || strings.ReplaceAll(diagnostic, path, "<image>") != op.want.Diagnostic {
					t.Fatalf("operation=%s exit=%d/%d stdout=%q diagnostic=%q/%q", op.name, exit, op.want.Exit, out, diagnostic, op.want.Diagnostic)
				}
				assertLargeMachO(t, path, op.want)
				unchanged := op.name == "dryrun" || exit != 0
				selectedSame := os.SameFile(before, accessFileInfo(t, path))
				neighbourSame := os.SameFile(before, accessFileInfo(t, link))
				if selectedSame != unchanged || !neighbourSame {
					t.Fatalf("operation=%s selected_same=%t want=%t neighbour_same=%t", op.name, selectedSame, unchanged, neighbourSame)
				}
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if op.name == "sign" && exit == 0 {
					mustRun(t, binaryPath, "--verify", "--strict", path)
					if runtime.GOOS == "darwin" {
						mustRun(t, apple(t), "--verify", "--strict", path)
					}
					exportLargeMachO(t, path, tc.Name)
				}
			}
		})
	}
}

func TestVerifyImportedLargeMachO(t *testing.T) {
	dir := os.Getenv("MACOSCODESIGN_IMPORT_DIR")
	if dir == "" {
		return
	}
	reference := apple(t)
	want := map[string]largeMachOOutcome{}
	for _, tc := range largeMachOCases(t) {
		if tc.Sign.Exit == 0 {
			want["large-macho-"+tc.Name+".gz"] = tc.Sign
		}
	}
	seen := map[string]int{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "large-macho-") {
			return nil
		}
		expect, ok := want[d.Name()]
		if !ok {
			t.Fatal("unexpected foreign Mach-O", path)
		}
		source, err := os.Open(path)
		if err != nil {
			return err
		}
		defer source.Close()
		z, err := gzip.NewReader(source)
		if err != nil {
			return err
		}
		defer z.Close()
		image := filepath.Join(t.TempDir(), "foreign.macho")
		f, err := os.OpenFile(image, os.O_CREATE|os.O_RDWR, 0755)
		if err != nil {
			return err
		}
		defer f.Close()
		n, err := io.Copy(f, io.LimitReader(z, expect.Size+1))
		if err != nil {
			return err
		}
		if n != expect.Size {
			return fmt.Errorf("foreign Mach-O size %d, expected %d", n, expect.Size)
		}
		if err := f.Close(); err != nil {
			return err
		}
		assertLargeMachO(t, image, expect)
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
	attest(t, map[string]any{"large_macho_verified": 18, "full_native_byte_equality": true, "full_payload_hashed": true})
}
