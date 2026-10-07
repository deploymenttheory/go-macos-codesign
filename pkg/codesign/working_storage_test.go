package codesign

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
)

func TestWorkingStorageBlockedWaiters(t *testing.T) {
	for _, action := range []string{"release", "cancel", "close"} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, s, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize}))
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				_, release, err := transferBuffer(ctx, transferBufferSize)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					_, free, err := transferBuffer(ctx, 1)
					if err == nil {
						free()
					}
					done <- err
				}()
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatal("waiter bypassed exhausted budget", err)
				default:
				}
				var want error
				switch action {
				case "release":
					release()
				case "cancel":
					cancel()
					want = context.Canceled
				case "close":
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					want = os.ErrClosed
				}
				synctest.Wait()
				if err := <-done; !errors.Is(err, want) {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestWorkingStorageSections(t *testing.T) {
	for _, budget := range []int64{transferBufferSize, 2 * transferBufferSize, defaultWorkingMemory} {
		t.Run(fmtBudget(budget), func(t *testing.T) {
			dir := t.TempDir()
			var stats WorkingStorageStats
			ctx, s, err := beginWorkingStorage(WithWorkingStorage(context.Background(), WorkingStorageOptions{MemoryBytes: budget, TemporaryDirectory: dir, Observe: func(v WorkingStorageStats) { stats = v }}))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			nested, owner, err := beginWorkingStorage(ctx)
			if err != nil || owner != nil || storageFrom(nested) != s {
				t.Fatal("nested budget differs", err)
			}
			first, err := newWorkingSection(ctx, transferBufferSize)
			if err != nil {
				t.Fatal(err)
			}
			second, err := newWorkingSection(ctx, budget+17)
			if err != nil {
				t.Fatal(err)
			}
			third, err := newWorkingSection(ctx, budget+9)
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte{0xa5}, transferBufferSize)
			if err := transferOutput(ctx, first, byteOutput(payload)); err != nil {
				t.Fatal(err)
			}
			if err := transferOutput(ctx, second, first.output()); err != nil {
				t.Fatal(err)
			}
			if _, err := third.WriteAt([]byte("independent"), third.size-11); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := second.ReadAt(got, 0); err != nil || !bytes.Equal(got, payload) {
				t.Fatal("lost section data", err)
			}
			clear(got)
			got = got[:min(int64(len(got)), third.size-11)]
			if _, err := third.ReadAt(got, 0); err != nil || !bytes.Equal(got, make([]byte, len(got))) {
				t.Fatal("overlapping sections", err)
			}
			if _, err := second.WriteAt([]byte{1}, second.size); !errors.Is(err, io.ErrShortWrite) {
				t.Fatal(err)
			}
			if _, err := second.WriteAt(nil, -1); !errors.Is(err, io.ErrShortWrite) {
				t.Fatal(err)
			}
			if _, err := second.ReadAt(got, second.size-1); !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if _, err := second.ReadAt(got, -1); !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if _, err := second.ReadAt(got, second.size+1); !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if stats.MemoryBytes != 0 || stats.PeakMemoryBytes > budget || stats.SpillFiles != 1 || stats.SpillBytes < 2*budget+26 {
				t.Fatal(stats)
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 0 {
				t.Fatal("scratch leak", files, err)
			}
			if _, err := newWorkingSection(ctx, 1); !errors.Is(err, os.ErrClosed) {
				t.Fatal(err)
			}
			if _, _, err := transferBuffer(ctx, 1); !errors.Is(err, os.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

func fmtBudget(n int64) string {
	if n == transferBufferSize {
		return "one-buffer"
	}
	if n == 2*transferBufferSize {
		return "two-buffers"
	}
	return "default"
}

func TestWorkingStorageWaitAndCancel(t *testing.T) {
	ctx, s, err := beginWorkingStorage(WithWorkingStorage(context.Background(), WorkingStorageOptions{MemoryBytes: transferBufferSize}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, release, err := transferBuffer(ctx, transferBufferSize)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := transferBuffer(canceled, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := newWorkingSection(canceled, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		b, free, e := transferBuffer(ctx, 1)
		if e == nil {
			b[0] = 1
			free()
		}
		done <- e
	}()
	release()
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Multiple workers contend for one buffer, and persistent sections spill
	// without consuming the buffer needed to transfer their own bytes.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, free, e := transferBuffer(ctx, transferBufferSize)
			if e != nil {
				t.Error(e)
				return
			}
			b[0] = 1
			free()
		}()
	}
	wg.Wait()
}

type storageFaultFile struct {
	*os.File
	truncateErr, closeErr error
}

func (f storageFaultFile) Truncate(n int64) error {
	if f.truncateErr != nil {
		return f.truncateErr
	}
	return f.File.Truncate(n)
}
func (f storageFaultFile) Close() error { return errors.Join(f.File.Close(), f.closeErr) }

func TestWorkingStorageFailures(t *testing.T) {
	ctx, s, err := beginWorkingStorage(WithWorkingStorage(context.Background(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newWorkingSection(ctx, -1); err == nil {
		t.Fatal("negative size accepted")
	}
	if _, _, err := transferBuffer(ctx, -1); err == nil {
		t.Fatal("negative buffer accepted")
	}
	fault := errors.New("disk full")
	s.create = func(string, string) (scratchFile, error) { return nil, fault }
	if _, err := newWorkingSection(ctx, 1); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "fault-")
	if err != nil {
		t.Fatal(err)
	}
	s.file = storageFaultFile{File: f, truncateErr: fault, closeErr: io.ErrClosedPipe}
	if _, err := newWorkingSection(ctx, 1); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	s.stats.SpillBytes = math.MaxInt64
	if _, err := newWorkingSection(ctx, 1); err == nil {
		t.Fatal("overflow accepted")
	}
	// Restore the injected counter to the actual extent before cleanup.
	s.stats.SpillBytes = 0
	s.remove = func(string) error { return os.ErrPermission }
	if err := s.Close(); !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkingStorageOptionsAndByteHelpers(t *testing.T) {
	if err := (*workingStorage)(nil).Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := beginWorkingStorage(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := beginWorkingStorage(WithWorkingStorage(context.Background(), WorkingStorageOptions{MemoryBytes: -1})); err == nil {
		t.Fatal("invalid budget")
	}
	ctx, s, err := beginWorkingStorage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.options.MemoryBytes != defaultWorkingMemory {
		t.Fatal(s.options)
	}
	section, err := newWorkingSection(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := section.WriteAt([]byte("abc"), 0); err != nil {
		t.Fatal(err)
	}
	data, err := materializeOutput(ctx, section.output())
	if err != nil || string(data) != "abc" {
		t.Fatal(string(data), err)
	}
	b := rangeBuffer(data)
	if _, err := b.ReadAt(make([]byte, 4), 0); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if _, err := b.ReadAt(nil, -1); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	_, s, err = beginWorkingStorage(WithWorkingStorage(context.Background(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: filepath.Join(t.TempDir(), "missing")}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = newWorkingSection(context.WithValue(context.Background(), workingStorageKey{}, s), 1)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
