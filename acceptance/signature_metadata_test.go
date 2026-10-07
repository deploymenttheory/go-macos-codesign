package acceptance

import (
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

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestSignatureMetadataBoundaries(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root, "testdata/research/signature-metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Schema          int
		SeedPrefixBytes int64
		Sources         map[string]string
		Compiler        string
		OracleSHA256    string
		SDKHeaders      map[string]string
		AST             map[string]map[string]int
		Cases           []struct {
			DirectorySize, FileSize int64
			SHA256                  string
			Parts                   []struct {
				Offset int64
				Data   []byte
			}
			Display, Verify struct {
				Exit int
				Text string
			}
			Framework struct {
				Create, Inspect, Verify int
				CDHash                  string
			}
		}
	}
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.Schema != 1 || len(capture.Cases) != 12 || len(capture.AST) != 2 || len(capture.Sources) != 6 {
		t.Fatal("incomplete metadata capture")
	}
	if capture.Compiler == "" || len(capture.OracleSHA256) != 64 || len(capture.SDKHeaders) != 2 || len(capture.SDKHeaders["SecCode.h"]) != 64 || len(capture.SDKHeaders["SecStaticCode.h"]) != 64 {
		t.Fatal("missing native SDK provenance")
	}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		if capture.AST[target]["CallExpr"] < 10 || capture.AST[target]["CompoundStmt"] == 0 {
			t.Fatal("missing compiled native probe", target)
		}
	}
	for _, path := range []string{"scripts/probe-signature-metadata.go", "testdata/research/signature-metadata.c", "testdata/dmg/native-adhoc-raw.dmg", "go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || hash(data) != capture.Sources[path] {
			t.Fatal("stale source", path, err)
		}
	}
	seed, err := os.ReadFile(filepath.Join(root, "testdata/dmg/native-adhoc-raw.dmg"))
	if err != nil || capture.SeedPrefixBytes <= 0 || capture.SeedPrefixBytes > int64(len(seed)) {
		t.Fatal("invalid seed", err)
	}
	boundaries := [...]int64{64 << 10, 16 << 20, 128 << 20, 1 << 30}
	for i, tc := range capture.Cases {
		if tc.DirectorySize != boundaries[i/3]+int64(i%3)-1 || tc.FileSize < tc.DirectorySize || len(tc.Parts) != 5 || len(tc.SHA256) != 64 || tc.Display.Exit != 0 || tc.Verify.Exit != 0 || tc.Framework.Create != 0 || tc.Framework.Inspect != 0 || tc.Framework.Verify != 0 || len(tc.Framework.CDHash) != 40 {
			t.Fatal("invalid or reordered native control", i, tc.DirectorySize)
		}
		t.Run(fmt.Sprint(tc.DirectorySize), func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "metadata.dmg")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			started := time.Now()
			zero := make([]byte, 64<<10)
			for left := tc.FileSize; left > 0; {
				n := min(left, int64(len(zero)))
				written, err := f.Write(zero[:n])
				if err != nil || int64(written) != n {
					t.Fatal("dense fixture write", written, n, err)
				}
				left -= n
			}
			if _, err := f.WriteAt(seed[:capture.SeedPrefixBytes], 0); err != nil {
				t.Fatal(err)
			}
			for _, p := range tc.Parts {
				if p.Offset < capture.SeedPrefixBytes || p.Offset > tc.FileSize-int64(len(p.Data)) {
					t.Fatal("invalid fixture part")
				}
				if _, err := f.WriteAt(p.Data, p.Offset); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			t.Logf("dense fixture populated: bytes=%d elapsed=%s", tc.FileSize, time.Since(started))
			for _, control := range []struct {
				args []string
				want string
			}{{[]string{"-dvvvv", path}, tc.Display.Text}, {[]string{"--verify", "--strict", "--verbose=4", path}, tc.Verify.Text}} {
				out, stderr, code := run(t, binaryPath, control.args...)
				if code != 0 || strings.ReplaceAll(out+stderr, path, "<image>") != control.want {
					t.Fatalf("portable metadata parity: exit=%d\nwant=%s\nstdout=%s\nstderr=%s", code, control.want, out, stderr)
				}
				if runtime.GOOS == "darwin" {
					out, stderr, code = run(t, apple(t), control.args...)
					if code != 0 || strings.ReplaceAll(out+stderr, path, "<image>") != control.want {
						t.Fatal("native metadata parity", code, out, stderr)
					}
				}
			}
			for _, budget := range []int64{64 << 10, 128 << 20, 256 << 20} {
				t.Run(fmt.Sprintf("budget=%d", budget), func(t *testing.T) {
					var stats codesign.WorkingStorageStats
					temp := t.TempDir()
					ctx := codesign.WithWorkingStorage(t.Context(), codesign.WorkingStorageOptions{MemoryBytes: budget, TemporaryDirectory: temp, Observe: func(s codesign.WorkingStorageStats) { stats = s }})
					var before, after runtime.MemStats
					runtime.ReadMemStats(&before)
					start := time.Now()
					calls := 0
					err := codesign.VisitVerification(ctx, path, codesign.VerifyOptions{}, func(r *codesign.Report, err error) error {
						calls++
						if err != nil || r == nil || !r.Valid || len(r.Architectures) != 1 {
							t.Fatal("borrowed verification", r, err)
						}
						d := r.Architectures[0].Signature.Directories[0]
						if d.Raw != nil || d.Size() != tc.DirectorySize || d.CDHash != tc.Framework.CDHash {
							t.Fatal("borrowed directory differs from SDK", d.Size(), d.CDHash)
						}
						return nil
					})
					runtime.ReadMemStats(&after)
					allocated := after.TotalAlloc - before.TotalAlloc
					t.Logf("metadata=%d budget=%d elapsed=%s allocated=%d storage=%+v", tc.DirectorySize, budget, time.Since(start), allocated, stats)
					if err != nil || calls != 1 || stats.MemoryBytes != 0 || stats.PeakMemoryBytes > budget || allocated > 8<<20 {
						t.Fatal("metadata reservation/allocation regression", calls, stats, allocated, err)
					}
					entries, err := os.ReadDir(temp)
					if err != nil || len(entries) != 0 {
						t.Fatal("metadata scratch leak", entries, err)
					}
				})
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			_, err = io.CopyBuffer(h, file, make([]byte, 64<<10))
			if closeErr := file.Close(); err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			if hex.EncodeToString(h.Sum(nil)) != tc.SHA256 {
				t.Fatal("complete native fixture bytes changed")
			}
		})
	}
}
