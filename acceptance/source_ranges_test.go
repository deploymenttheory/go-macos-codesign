package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLargeSourceVerification(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root, "testdata/research/large-source.json"))
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Cases []struct {
			ContentLength              int64 `json:"content_length"`
			Prefix, Signature, Trailer []byte
			Display, Verify            string
		}
	}
	if err = json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	if len(capture.Cases) != 9 {
		t.Fatal("missing large-file cases")
	}
	for _, tc := range capture.Cases {
		t.Run(fmt.Sprint(tc.ContentLength), func(t *testing.T) {
			started := time.Now()
			dir, err := filepath.Abs(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dir, err = filepath.EvalSymlinks(dir)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "large.dmg")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			// Reconstruct the native sparse-file recipe on every host, then write
			// the recorded independently signed ranges. Setup failure is never a skip.
			if err = prepareSparseFixture(f); err != nil {
				f.Close()
				t.Fatal(err)
			}
			total := tc.ContentLength + int64(len(tc.Signature)+len(tc.Trailer))
			if err = f.Truncate(total); err != nil {
				f.Close()
				t.Fatal(err)
			}
			for _, part := range []struct {
				at   int64
				data []byte
			}{{0, tc.Prefix}, {tc.ContentLength, tc.Signature}, {tc.ContentLength + int64(len(tc.Signature)), tc.Trailer}} {
				if _, err = f.WriteAt(part.data, part.at); err != nil {
					f.Close()
					t.Fatal(err)
				}
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			t.Logf("fixture ready: content=%d total=%d elapsed=%s", tc.ContentLength, total, time.Since(started))
			started = time.Now()
			out, stderr, code := run(t, binaryPath, "-dvvvv", path)
			t.Logf("display elapsed=%s exit=%d", time.Since(started), code)
			got := strings.ReplaceAll(out+stderr, path, "<image>")
			if code != 0 || got != tc.Display {
				t.Fatalf("display %d\nwant %s\ngot %s", code, tc.Display, got)
			}
			started = time.Now()
			out, stderr, code = run(t, binaryPath, "--verify", "--strict", "--verbose=4", path)
			t.Logf("verification elapsed=%s exit=%d", time.Since(started), code)
			got = strings.ReplaceAll(out+stderr, path, "<image>")
			if code != 0 || got != tc.Verify {
				t.Fatalf("verify %d\nwant %s\ngot %s", code, tc.Verify, got)
			}
			if runtime.GOOS == "darwin" {
				started = time.Now()
				out, stderr, code = run(t, apple(t), "--verify", "--strict", "--verbose=4", path)
				t.Logf("native verification elapsed=%s exit=%d", time.Since(started), code)
				if code != 0 || strings.ReplaceAll(out+stderr, path, "<image>") != tc.Verify {
					t.Fatal("native reconstruction verification", code, out, stderr)
				}
			}
			// Read-only operations must leave the signed trailer and allocation intact.
			f, err = os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			st, err := f.Stat()
			if err != nil || st.Size() != total {
				t.Fatal(st, err)
			}
			trailer := make([]byte, len(tc.Trailer))
			if _, err = f.ReadAt(trailer, total-int64(len(trailer))); err != nil || !bytes.Equal(trailer, tc.Trailer) {
				t.Fatal("trailer changed", err)
			}
			t.Logf("content=%d signature=%s total=%d", tc.ContentLength, hash(tc.Signature), total)
		})
	}
}
