package acceptance

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
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

type largeBundleMember struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Prefix    []byte `json:"prefix"`
	Populated bool   `json:"populated"`
}
type largeBundleFile struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type largeBundleOutcome struct {
	Exit           int                        `json:"exit"`
	Diagnostic     string                     `json:"diagnostic"`
	Files          map[string]largeBundleFile `json:"files"`
	ExecutableSame bool                       `json:"executable_same"`
	NeighbourSame  bool                       `json:"neighbour_same"`
}
type largeBundleCase struct {
	Name       string                        `json:"name"`
	Bundle     string                        `json:"bundle"`
	Executable string                        `json:"executable"`
	Members    []largeBundleMember           `json:"members"`
	Operations map[string]largeBundleOutcome `json:"operations"`
}

func largeBundleCases(t *testing.T) []largeBundleCase {
	t.Helper()
	var capture struct{ Cases []largeBundleCase }
	if err := json.Unmarshal(nativeRead(t, filepath.Join(root, "testdata/research/large-bundles.json")), &capture); err != nil {
		t.Fatal(err)
	}
	if len(capture.Cases) != 10 {
		t.Fatal("incomplete native large bundle capture")
	}
	return capture.Cases
}
func largeBundleScratch(t *testing.T) string {
	t.Helper()
	p, err := os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "codesign-large-bundle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(p); err != nil {
			t.Error(err)
		}
	})
	return p
}
func largeBundleSnapshot(t *testing.T, path string) map[string]largeBundleFile {
	t.Helper()
	states := map[string]largeBundleFile{}
	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(path, p)
		if err != nil {
			return err
		}
		states[filepath.ToSlash(name)] = largeBundleFile{n, hex.EncodeToString(h.Sum(nil))}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return states
}
func exportLargeBundle(t *testing.T, path string, tc largeBundleCase) {
	t.Helper()
	dir := os.Getenv("MACOSCODESIGN_EXPORT_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "large-bundle-"+tc.Name+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	w := tar.NewWriter(z)
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name, err := filepath.Rel(path, p)
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		st, err := src.Stat()
		if err != nil {
			return err
		}
		if err := w.WriteHeader(&tar.Header{Name: filepath.ToSlash(name), Mode: 0755, Size: st.Size(), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err = io.Copy(w, src)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestLargeBundleStreaming(t *testing.T) {
	for _, tc := range largeBundleCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			dir := largeBundleScratch(t)
			path := filepath.Join(dir, tc.Bundle)
			for _, m := range tc.Members {
				p := filepath.Join(path, filepath.FromSlash(m.Name))
				if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0755)
				if err != nil {
					t.Fatal(err)
				}
				if err := prepareSparseFixture(f); err != nil {
					t.Fatal(err)
				}
				if _, err := f.Write(m.Prefix); err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(m.Size); err != nil {
					t.Fatal(err)
				}
				if m.Populated {
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
			}
			args := []string{"-s", "-", "--deep", "--timestamp=none"}
			for _, op := range []struct {
				name string
				args []string
			}{{"sign", args}, {"verify", []string{"--verify", "--strict", "--deep"}}, {"resign", append([]string{"-f"}, args...)}, {"dryrun", append([]string{"-f", "--dryrun"}, args...)}, {"remove", []string{"--remove-signature"}}} {
				executable := filepath.Join(path, filepath.FromSlash(tc.Executable))
				link := filepath.Join(dir, "neighbour")
				if err := os.Link(executable, link); err != nil {
					t.Fatal(err)
				}
				before := accessFileInfo(t, executable)
				if !os.SameFile(before, accessFileInfo(t, link)) {
					t.Fatal("initial hardlink identity")
				}
				started := time.Now()
				out, diagnostic, exit := run(t, binaryPath, append(op.args, path)...)
				t.Logf("fixture=%s operation=%s elapsed=%s", path, op.name, time.Since(started))
				want := tc.Operations[op.name]
				if out != "" || exit != want.Exit || strings.ReplaceAll(diagnostic, path, "<bundle>") != want.Diagnostic {
					t.Fatalf("%s exit=%d/%d stdout=%q stderr=%q/%q", op.name, exit, want.Exit, out, diagnostic, want.Diagnostic)
				}
				actual := largeBundleSnapshot(t, path)
				if !reflect.DeepEqual(actual, want.Files) {
					t.Fatalf("%s full native member mismatch: got=%v want=%v", op.name, actual, want.Files)
				}
				if os.SameFile(before, accessFileInfo(t, executable)) != want.ExecutableSame || os.SameFile(before, accessFileInfo(t, link)) != want.NeighbourSame {
					t.Fatal("native hardlink behavior mismatch", op.name)
				}
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if op.name == "sign" {
					if runtime.GOOS == "darwin" {
						mustRun(t, apple(t), "--verify", "--deep", "--strict", path)
					}
					exportLargeBundle(t, path, tc)
				}
			}
		})
	}
}
func TestVerifyImportedLargeBundles(t *testing.T) {
	dir := os.Getenv("MACOSCODESIGN_IMPORT_DIR")
	if dir == "" {
		return
	}
	reference := apple(t)
	cases := map[string]largeBundleCase{}
	for _, tc := range largeBundleCases(t) {
		cases["large-bundle-"+tc.Name+".tar.gz"] = tc
	}
	seen := map[string]int{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "large-bundle-") {
			return nil
		}
		tc, ok := cases[d.Name()]
		if !ok {
			return fmt.Errorf("unexpected foreign bundle %s", p)
		}
		source, err := os.Open(p)
		if err != nil {
			return err
		}
		defer source.Close()
		z, err := gzip.NewReader(source)
		if err != nil {
			return err
		}
		defer z.Close()
		r := tar.NewReader(z)
		scratch := largeBundleScratch(t)
		bundle := filepath.Join(scratch, tc.Bundle)
		members := map[string]bool{}
		expected := tc.Operations["sign"].Files
		for {
			h, err := r.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			want, ok := expected[h.Name]
			if !ok || members[h.Name] || h.Typeflag != tar.TypeReg || h.Size != want.Size || !filepath.IsLocal(h.Name) {
				return fmt.Errorf("invalid foreign bundle member %q", h.Name)
			}
			members[h.Name] = true
			p := filepath.Join(bundle, filepath.FromSlash(h.Name))
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
			if err != nil {
				return err
			}
			n, copyErr := io.Copy(f, r)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if n != want.Size {
				return io.ErrUnexpectedEOF
			}
		}
		// Read through gzip EOF so CRC/truncation failures cannot be hidden by tar EOF.
		if _, err := io.Copy(io.Discard, z); err != nil {
			return err
		}
		if len(members) != len(expected) {
			return fmt.Errorf("missing foreign bundle members")
		}
		if got := largeBundleSnapshot(t, bundle); !reflect.DeepEqual(got, expected) {
			return fmt.Errorf("foreign bundle differs from complete native hashes: %s", tc.Name)
		}
		mustRun(t, reference, "--verify", "--deep", "--strict", bundle)
		if err := os.RemoveAll(scratch); err != nil {
			return err
		}
		seen[d.Name()]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range cases {
		if seen[name] != 2 {
			t.Fatalf("expected both producers for %s, got %d", name, seen[name])
		}
	}
	attest(t, map[string]any{"large_bundles_verified": 20, "complete_native_member_equality": true})
}
