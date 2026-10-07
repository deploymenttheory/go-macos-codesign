package codesign

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
)

const defaultWorkingMemory int64 = 128 << 20

// WorkingStorageOptions controls operation-owned scratch storage. It does not
// constrain caller buffers, returned byte slices/reports or Go runtime overhead.
// Zero MemoryBytes selects 128 MiB. TemporaryDirectory defaults to os.TempDir.
// Observe runs once after cleanup; it must not mutate the operation's inputs.
type WorkingStorageOptions struct {
	MemoryBytes        int64
	TemporaryDirectory string
	Observe            func(WorkingStorageStats)
}

// WorkingStorageStats measures reservations, not process heap or resident memory.
// SpillBytes is the high-water extent of the single operation-owned spill file.
type WorkingStorageStats struct {
	PeakMemoryBytes int64
	MemoryBytes     int64
	SpillBytes      int64
	SpillFiles      int
}

type storageOptionsKey struct{}
type workingStorageKey struct{}

// WithWorkingStorage selects scratch policy for subsequent path/byte operations.
// The operation validates the options before touching the input. Nested work
// inherits the same reservation pool and spill file rather than another budget.
func WithWorkingStorage(ctx context.Context, options WorkingStorageOptions) context.Context {
	return context.WithValue(ctx, storageOptionsKey{}, options)
}

type scratchFile interface {
	io.ReaderAt
	io.WriterAt
	Truncate(int64) error
	Close() error
	Name() string
}

type workingStorage struct {
	mu      sync.Mutex
	options WorkingStorageOptions
	stats   WorkingStorageStats
	changed chan struct{}
	file    scratchFile
	closed  bool
	create  func(string, string) (scratchFile, error)
	remove  func(string) error
}

func beginWorkingStorage(ctx context.Context) (context.Context, *workingStorage, error) {
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	if _, ok := ctx.Value(workingStorageKey{}).(*workingStorage); ok {
		return ctx, nil, nil
	}
	opts, _ := ctx.Value(storageOptionsKey{}).(WorkingStorageOptions)
	if opts.MemoryBytes == 0 {
		opts.MemoryBytes = defaultWorkingMemory
	}
	if opts.MemoryBytes < transferBufferSize {
		return ctx, nil, fmt.Errorf("working memory must allow at least one %d-byte transfer buffer", transferBufferSize)
	}
	s := &workingStorage{options: opts, changed: make(chan struct{}), remove: os.Remove,
		create: func(dir, pattern string) (scratchFile, error) { return os.CreateTemp(dir, pattern) }}
	return context.WithValue(ctx, workingStorageKey{}, s), s, nil
}

func storageFrom(ctx context.Context) *workingStorage {
	s, _ := ctx.Value(workingStorageKey{}).(*workingStorage)
	return s
}

func (s *workingStorage) reserve(n int64) {
	s.stats.MemoryBytes += n
	s.stats.PeakMemoryBytes = max(s.stats.PeakMemoryBytes, s.stats.MemoryBytes)
}

func (s *workingStorage) release(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.stats.MemoryBytes -= n
	close(s.changed)
	s.changed = make(chan struct{})
}

// transferBuffer never holds the lock while waiting or doing I/O. Persistent
// sections leave one transfer buffer unreserved so spilling cannot deadlock.
func transferBuffer(ctx context.Context, size int64) ([]byte, func(), error) {
	n := min(size, transferBufferSize)
	if n < 0 {
		return nil, nil, malformed("negative transfer buffer size")
	}
	s := storageFrom(ctx)
	if s == nil {
		return make([]byte, int(n)), func() {}, ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, nil, os.ErrClosed
		}
		if n <= s.options.MemoryBytes-s.stats.MemoryBytes {
			s.reserve(n)
			s.mu.Unlock()
			var once sync.Once
			return make([]byte, int(n)), func() { once.Do(func() { s.release(n) }) }, nil
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-changed:
		}
	}
}

// workingSection is a bounded generated output range. A spill shares one held
// descriptor for the entire operation. Independent sections never overlap.
type workingSection struct {
	reader io.ReaderAt
	writer io.WriterAt
	base   int64
	size   int64
}

func (s workingSection) ReadAt(p []byte, at int64) (int, error) {
	if at < 0 || at > s.size {
		return 0, io.EOF
	}
	n, err := s.reader.ReadAt(p[:min(int64(len(p)), s.size-at)], s.base+at)
	if n != len(p) && err == nil {
		err = io.EOF
	}
	return n, err
}

func (s workingSection) WriteAt(p []byte, at int64) (int, error) {
	if at < 0 || at > s.size || int64(len(p)) > s.size-at {
		return 0, io.ErrShortWrite
	}
	return s.writer.WriteAt(p, s.base+at)
}

func (s workingSection) output() outputSource { return outputSource{reader: s, size: s.size} }

func newWorkingSection(ctx context.Context, size int64) (workingSection, error) {
	if size < 0 {
		return workingSection{}, malformed("negative working section size")
	}
	if err := ctx.Err(); err != nil {
		return workingSection{}, err
	}
	s := storageFrom(ctx)
	if s == nil {
		// Internal byte helpers retain ordinary Go-owned storage. Exported path
		// operations install a scope before reaching these builders.
		if uint64(size) > uint64(^uint(0)>>1) {
			return workingSection{}, malformed("working section exceeds host int")
		}
		b := rangeBuffer(make([]byte, int(size)))
		return workingSection{reader: b, writer: b, size: size}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return workingSection{}, os.ErrClosed
	}
	if size <= s.options.MemoryBytes-s.stats.MemoryBytes-transferBufferSize && uint64(size) <= uint64(^uint(0)>>1) {
		s.reserve(size)
		b := rangeBuffer(make([]byte, int(size)))
		return workingSection{reader: b, writer: b, size: size}, nil
	}
	if size > math.MaxInt64-s.stats.SpillBytes {
		return workingSection{}, malformed("spill extent overflow")
	}
	if s.file == nil {
		file, err := s.create(s.options.TemporaryDirectory, "macoscodesign-work-*")
		if err != nil {
			return workingSection{}, err
		}
		s.file = file
		s.stats.SpillFiles++
	}
	base := s.stats.SpillBytes
	if err := s.file.Truncate(base + size); err != nil {
		return workingSection{}, err
	}
	s.stats.SpillBytes += size
	return workingSection{reader: s.file, writer: s.file, base: base, size: size}, nil
}

func (s *workingStorage) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.changed)
	var err error
	if s.file != nil {
		err = errors.Join(s.file.Close(), s.remove(s.file.Name()))
	}
	// Closing is an operation boundary after all workers have joined. Memory
	// section references must no longer escape through an output plan.
	s.stats.MemoryBytes = 0
	stats := s.stats
	s.mu.Unlock()
	if s.options.Observe != nil {
		s.options.Observe(stats)
	}
	return err
}
