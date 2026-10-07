package codesign

import (
	"context"
	"errors"
	"os"
	"path/filepath"

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
	*os.File
	cleanup *error
}

func newCompressionStage(ctx context.Context, cleanup *error) (*compressionStage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir := ""
	if storage := storageFrom(ctx); storage != nil {
		dir = storage.options.TemporaryDirectory
	}
	file, err := os.CreateTemp(dir, "macoscodesign-compression-*")
	if err != nil {
		return nil, err
	}
	return &compressionStage{File: file, cleanup: cleanup}, nil
}

func (s *compressionStage) Close() error {
	err := errors.Join(s.File.Close(), os.Remove(s.Name()))
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
