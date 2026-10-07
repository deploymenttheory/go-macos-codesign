package codesign

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"sync"
	"testing"
)

func TestCompressionScratchAccounting(t *testing.T) {
	var observed WorkingStorageStats
	dir := t.TempDir()
	ctx, storage, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{
		MemoryBytes: transferBufferSize, TemporaryDirectory: dir,
		Observe: func(stats WorkingStorageStats) { observed = stats },
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	section, err := newWorkingSection(ctx, 17)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := section.WriteAt([]byte("spill"), 0); err != nil {
		t.Fatal(err)
	}
	var cleanup error
	first, err := newCompressionStage(ctx, &cleanup)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newCompressionStage(ctx, &cleanup)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []int64{1024, 0, 1024} {
		if n, err := first.WriteAt([]byte("block"), at); n != 5 || err != nil {
			t.Fatal(n, err)
		}
	}
	if _, err := second.WriteAt([]byte("other"), 10); err != nil {
		t.Fatal(err)
	}
	if storage.stats.TemporaryBytes != 17+1029+15 || storage.stats.TemporaryFiles != 3 {
		t.Fatal(storage.stats)
	}
	if n, err := first.WriteAt(nil, math.MaxInt64); n != 0 || err != nil || storage.stats.TemporaryBytes != 1061 {
		t.Fatal("empty write changed extent", n, err, storage.stats)
	}
	got := make([]byte, 5)
	if _, err := first.ReadAt(got, 1024); err != nil || !bytes.Equal(got, []byte("block")) {
		t.Fatal(got, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal("close is not idempotent", err)
	}
	if storage.stats.TemporaryBytes != 32 || storage.stats.TemporaryFiles != 2 {
		t.Fatal(storage.stats)
	}
	if _, err := first.WriteAt([]byte("closed"), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	// The operation scope owns cleanup even if a stage's caller did not close.
	if err := storage.Close(); err != nil || cleanup != nil {
		t.Fatal(err, cleanup)
	}
	if observed.TemporaryBytes != 0 || observed.TemporaryFiles != 0 || observed.PeakTemporaryBytes != 1061 || observed.PeakTemporaryFiles != 3 || observed.SpillBytes != 17 {
		t.Fatal(observed)
	}
	if files, err := os.ReadDir(dir); err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
	if _, err := newCompressionStage(ctx, &cleanup); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

type partialCompressionScratch struct{ *os.File }

func (f partialCompressionScratch) WriteAt(p []byte, at int64) (int, error) {
	if at == 7 {
		n, err := f.File.WriteAt(p[:2], at)
		return n, errors.Join(err, io.ErrShortWrite)
	}
	return 0, os.ErrPermission
}

func TestCompressionScratchFailures(t *testing.T) {
	ctx, storage, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	create := storage.create
	storage.create = func(dir, pattern string) (scratchFile, error) {
		f, err := os.CreateTemp(dir, pattern)
		return partialCompressionScratch{f}, err
	}
	var cleanup error
	stage, err := newCompressionStage(ctx, &cleanup)
	if err != nil {
		t.Fatal(err)
	}
	storage.create = create
	for _, at := range []int64{-1, math.MaxInt64} {
		if _, err := stage.WriteAt([]byte("range"), at); !errors.Is(err, io.ErrShortWrite) {
			t.Fatal(at, err)
		}
	}
	if n, err := stage.WriteAt([]byte("partial"), 7); n != 2 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(n, err)
	}
	if n, err := stage.WriteAt([]byte("denied"), 100); n != 0 || !errors.Is(err, os.ErrPermission) {
		t.Fatal(n, err)
	}
	if storage.stats.TemporaryBytes != 9 || storage.stats.PeakTemporaryBytes != 9 {
		t.Fatal("counted unwritten bytes", storage.stats)
	}
	storage.stats.TemporaryBytes = math.MaxInt64
	if _, err := stage.WriteAt([]byte("overflow"), 100); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	if _, err := newWorkingSection(ctx, 1); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	storage.stats.TemporaryBytes = 9
	// A scope starts closing before it acquires each stage's lock. A writer
	// arriving at that boundary must not add data to storage being cleaned up.
	storage.closed = true
	if _, err := stage.WriteAt([]byte("closing"), 100); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	storage.closed = false
	// Failed removal must remain visible in the final observation, and scope
	// cleanup must return the error instead of pretending the file disappeared.
	storage.remove = func(string) error { return os.ErrPermission }
	if err := storage.Close(); !errors.Is(err, os.ErrPermission) || !errors.Is(cleanup, os.ErrPermission) {
		t.Fatal(err, cleanup)
	}
	if storage.stats.TemporaryBytes != 9 || storage.stats.TemporaryFiles != 1 {
		t.Fatal(storage.stats)
	}
	if err := os.Remove(stage.Name()); err != nil {
		t.Fatal(err)
	}
}

func TestCompressionScratchConcurrentExtents(t *testing.T) {
	ctx, storage, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{TemporaryDirectory: t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	var workers sync.WaitGroup
	for i := range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var cleanup error
			stage, err := newCompressionStage(ctx, &cleanup)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := stage.WriteAt([]byte("independent"), int64(i)*1024); err != nil {
				t.Error(err)
			}
			if err := stage.Close(); err != nil || cleanup != nil {
				t.Error(err, cleanup)
			}
		}()
	}
	workers.Wait()
	if storage.stats.TemporaryBytes != 0 || storage.stats.TemporaryFiles != 0 || storage.stats.PeakTemporaryFiles < 1 || storage.stats.PeakTemporaryBytes < 7*1024+11 {
		t.Fatal(storage.stats)
	}
}
