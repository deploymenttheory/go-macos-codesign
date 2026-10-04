package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Cancel synchronously at an observable filesystem checkpoint. No sleep, race,
// monkey-patched production global or OS-specific cancellation hook is needed.
type observedCancelContext struct {
	context.Context
	cancel  context.CancelFunc
	observe func() bool
}

func (c *observedCancelContext) Err() error {
	if c.observe() {
		c.cancel()
	}
	return c.Context.Err()
}

func TestTransferCancellationFilesystem(t *testing.T) {
	for _, kind := range []string{"standalone", "bundle", "in-place", "envelope"} {
		t.Run(kind, func(t *testing.T) {
			app := testBundle(t)
			b, err := openAppBundle(app)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			path := filepath.Join(app, "Contents/MacOS/hello")
			if kind == "envelope" {
				path = filepath.Join(app, "Contents/CodeResources")
			}
			original := bytes.Repeat([]byte{0x41}, 3*transferBufferSize+17)
			changed := bytes.Repeat([]byte{0x62}, len(original))
			if err := os.WriteFile(path, original, 0755); err != nil {
				t.Fatal(err)
			}
			neighbour := filepath.Join(t.TempDir(), "neighbour")
			// Darwin restricts links FROM CodeResources; create the sibling first
			// and link TO the resource name, as the native writer corpus does.
			if err := os.WriteFile(neighbour, original, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(neighbour, path); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			reads := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observed := &observedCancelContext{Context: ctx, cancel: cancel}
			observed.observe = func() bool {
				check := path
				if kind == "standalone" || kind == "bundle" {
					matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".apfs-replacement-*", "replacement"))
					if err != nil {
						t.Fatal(err)
					}
					if len(matches) == 0 {
						return false
					}
					if len(matches) != 1 {
						t.Fatal("unexpected stages", matches)
					}
					check = matches[0]
				}
				f, err := os.Open(check)
				if err != nil {
					t.Fatal(err)
				}
				var first [1]byte
				_, err = f.ReadAt(first[:], 0)
				closeErr := f.Close()
				if closeErr != nil {
					t.Fatal(closeErr)
				}
				if err != nil {
					return false
				} // HFS+ stages initially have no data.
				if first[0] == changed[0] {
					reads++
					return true
				}
				return false
			}
			switch kind {
			case "standalone":
				err = writeFile(observed, path, changed, false)
			case "bundle":
				err = b.write(observed, b.executable, changed, false)
			case "in-place":
				err = overwriteFile(observed, path, changed)
			case "envelope":
				err = b.writeResource(observed, "Contents/CodeResources", changed)
			}
			if !errors.Is(err, context.Canceled) || reads == 0 {
				t.Fatal("transfer was not cancelled after writing", reads, err)
			}
			want := bytes.Clone(original)
			if kind == "in-place" || kind == "envelope" {
				copy(want[:transferBufferSize], changed)
			}
			for _, file := range []string{path, neighbour} {
				after, err := os.Stat(file)
				if err != nil || !os.SameFile(before, after) || !bytes.Equal(readTestFile(t, file), want) {
					t.Fatalf("incorrect cancellation effects for %s: %v", file, err)
				}
			}
			assertNoBundleStaging(t, app)
		})
	}
}

func TestReadOpenFileCancellation(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if data, err := readOpenFileContext(ctx, f, false); data != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(data, err)
	}
}
