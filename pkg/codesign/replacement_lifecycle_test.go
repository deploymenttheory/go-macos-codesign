package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Discover the checkpoints from a successful real-filesystem operation, then
// cancel each one on a fresh fixture. This includes the SDK's metadata transfer
// and restoration checkpoints, whose number differs between host filesystems.
// No production hooks, timing assumptions or platform skips are involved.
func TestReplacementLifecycleCheckpoints(t *testing.T) {
	for _, kind := range []string{"standalone", "standalone-dryrun", "bundle", "bundle-dryrun", "bundle-commit"} {
		t.Run(kind, func(t *testing.T) {
			run := func(t *testing.T, at int) int {
				t.Helper()
				app := testBundle(t)
				b, err := openAppBundle(app)
				if err != nil {
					t.Fatal(err)
				}
				defer b.close()
				path := filepath.Join(app, b.executable)
				original := readTestFile(t, path)
				before, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				neighbour := filepath.Join(t.TempDir(), "neighbour")
				if err := os.Link(path, neighbour); err != nil {
					t.Fatal(err)
				}
				changed := bytes.Repeat([]byte("replacement"), transferBufferSize/4)
				dryRun := strings.HasSuffix(kind, "-dryrun")
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				checks := 0
				observed := &observedCancelContext{Context: ctx, cancel: cancel, observe: func() bool {
					checks++
					return checks == at
				}}
				switch kind {
				case "standalone", "standalone-dryrun":
					err = writeFile(observed, path, changed, dryRun)
				case "bundle", "bundle-dryrun":
					err = applyBundleWrites(observed, []bundleWrite{{name: b.executable, data: changed, bundle: b}}, dryRun)
				case "bundle-commit":
					var prepared *preparedBundleExecutable
					prepared, err = prepareBundleExecutable(t.Context(), bundleWrite{name: b.executable, data: changed, bundle: b}, false)
					if err != nil {
						t.Fatal(err)
					}
					err = errors.Join(prepared.commit(observed), prepared.replacement.Close())
					for _, f := range []*os.File{prepared.replacement.source, prepared.replacement.File} {
						if closeErr := f.Close(); !errors.Is(closeErr, os.ErrClosed) {
							t.Fatalf("descriptor leaked: %v", closeErr)
						}
					}
				}
				if at == 0 {
					if err != nil || checks == 0 {
						t.Fatalf("control: checks=%d error=%v", checks, err)
					}
				} else if !errors.Is(err, context.Canceled) || checks < at {
					t.Fatalf("checkpoint %d: checks=%d error=%v", at, checks, err)
				}
				after, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				want := original
				if at == 0 && !dryRun {
					want = changed
					if os.SameFile(before, after) {
						t.Fatal("successful replacement did not detach the inode")
					}
				} else if !os.SameFile(before, after) {
					t.Fatal("canceled or dry-run replacement changed the inode")
				}
				if !bytes.Equal(readTestFile(t, path), want) || after.Mode() != before.Mode() {
					t.Fatal("incorrect target data or mode")
				}
				other, err := os.Stat(neighbour)
				if err != nil || !os.SameFile(before, other) || !bytes.Equal(readTestFile(t, neighbour), original) {
					t.Fatalf("source hard link changed: %v", err)
				}
				assertNoBundleStaging(t, app)
				return checks
			}
			total := run(t, 0)
			t.Logf("canceling all %d native-route checkpoints", total)
			for at := 1; at <= total; at++ {
				run(t, at)
			}
		})
	}
}
