package codesign

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type preserveCompressionKey struct{}

// Capture follows metadata restoration but precedes replacement. A failed
// native compression query is deliberately nonfatal: MachOEditor::commit only
// queues recompression when queryCompressionInfo succeeds with stored bytes.
// Cancellation is an operation boundary, not a failed compression observation.
func captureCompression(ctx context.Context, source *os.File) (uint32, error) {
	return captureCompressionUsing(ctx, source, hostdata.QueryCompression)
}

func captureCompressionUsing(ctx context.Context, source *os.File, query func(context.Context, *os.File, int) (decmpfs.Info, error)) (uint32, error) {
	if preserve, _ := ctx.Value(preserveCompressionKey{}).(bool); !preserve {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	info, err := query(ctx, source, 64<<10)
	if canceled := ctx.Err(); canceled != nil {
		return 0, canceled
	}
	if err != nil || info.StoredSize == 0 {
		return 0, nil
	}
	return info.Type, nil
}

// Native codesign checks queue admission, then waits for completion without
// promoting an accepted compression failure into a signing failure. Cancellation
// and scratch cleanup remain observable Go operation errors.
func recompressCommitted(ctx context.Context, name string, kind uint32, open func(context.Context) (hostdata.CompressionInput, error)) error {
	if kind == 0 {
		return nil
	}
	var cleanup error
	result, err := hostdata.Recompress(ctx, open, hostdata.RecompressionOptions{
		Name: filepath.Base(name), Encoding: decmpfs.EncodeOptions{Type: kind},
		NewStage: func(ctx context.Context) (hostdata.CompressionStage, error) {
			return newCompressionStage(ctx, &cleanup)
		},
	})
	if !result.Accepted {
		if canceled := ctx.Err(); canceled != nil {
			return errors.Join(err, canceled, cleanup)
		}
		return errors.Join(&VerificationError{Diagnostic: "internal error in Code Signing subsystem", cause: err, omitArchitecture: true}, cleanup)
	}
	return errors.Join(ctx.Err(), cleanup)
}

type compressionStage struct {
	scratchFile
	mu      sync.Mutex
	cleanup *error
	storage *workingStorage
	extent  int64
	closed  bool
}

func newCompressionStage(ctx context.Context, cleanup *error) (*compressionStage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if storage := storageFrom(ctx); storage != nil {
		storage.mu.Lock()
		defer storage.mu.Unlock()
		if storage.closed {
			return nil, os.ErrClosed
		}
		file, err := storage.create(storage.options.TemporaryDirectory, "macoscodesign-compression-*")
		if err != nil {
			return nil, err
		}
		stage := &compressionStage{scratchFile: file, cleanup: cleanup, storage: storage}
		if storage.stages == nil {
			storage.stages = make(map[*compressionStage]struct{})
		}
		storage.stages[stage] = struct{}{}
		storage.addTemporaryFile()
		return stage, nil
	}
	file, err := os.CreateTemp("", "macoscodesign-compression-*")
	if err != nil {
		return nil, err
	}
	return &compressionStage{scratchFile: file, cleanup: cleanup}, nil
}

func (s *compressionStage) WriteAt(p []byte, at int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, os.ErrClosed
	}
	if at < 0 || at > math.MaxInt64-int64(len(p)) {
		return 0, io.ErrShortWrite
	}
	if s.storage != nil {
		s.storage.mu.Lock()
		defer s.storage.mu.Unlock()
		if s.storage.closed {
			return 0, os.ErrClosed
		}
		if len(p) > 0 && max(at+int64(len(p))-s.extent, 0) > math.MaxInt64-s.storage.stats.TemporaryBytes {
			return 0, malformed("temporary extent overflow")
		}
	}
	n, err := s.scratchFile.WriteAt(p, at)
	// Failed writes can still extend a file. Count the actual written range,
	// including holes, without claiming unwritten requested bytes were stored.
	if n > 0 && at+int64(n) > s.extent {
		end := at + int64(n)
		if s.storage != nil {
			s.storage.growTemporary(end - s.extent)
		}
		s.extent = end
	}
	return n, err
}

func (s *compressionStage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	remove := os.Remove
	if s.storage != nil {
		remove = s.storage.remove
	}
	closeErr, removeErr := s.scratchFile.Close(), remove(s.Name())
	err := errors.Join(closeErr, removeErr)
	if s.storage != nil {
		s.storage.mu.Lock()
		delete(s.storage.stages, s)
		if removeErr == nil {
			s.storage.stats.TemporaryFiles--
			s.storage.stats.TemporaryBytes -= s.extent
		}
		s.storage.mu.Unlock()
	}
	*s.cleanup = errors.Join(*s.cleanup, err)
	return err
}

func recompressNativePath(ctx context.Context, name string, kind uint32) error {
	return recompressCommitted(ctx, name, kind, func(ctx context.Context) (hostdata.CompressionInput, error) {
		return hostdata.OpenNativeCompressionInput(ctx, name)
	})
}

func recompressNativeRoot(ctx context.Context, root *os.Root, name string, kind uint32) error {
	return recompressCommitted(ctx, name, kind, func(ctx context.Context) (hostdata.CompressionInput, error) {
		file, err := root.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		input, err := hostdata.NewNativeCompressionInput(ctx, file)
		if err != nil {
			return nil, errors.Join(err, file.Close())
		}
		return input, nil
	})
}
