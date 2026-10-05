package codesign

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
)

const transferBufferSize = 64 << 10

type operationReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r operationReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p[:min(len(p), transferBufferSize)])
	if canceled := r.ctx.Err(); canceled != nil {
		return n, errors.Join(err, canceled)
	}
	return n, err
}

// Sized random access separates transport from the current bounded byte-based
// format builders. Offsets and lengths stay int64, including above 4 GiB.
type outputSource struct {
	reader io.ReaderAt
	offset int64
	size   int64
}

func byteOutput(data []byte) outputSource {
	return outputSource{reader: bytes.NewReader(data), size: int64(len(data))}
}

// transferOutput checks cancellation between calls, never during a blocking OS
// call. In-place targets retain completed writes on failure; callers discard
// private replacement files. A reader error never permits truncation or commit.
func transferOutput(ctx context.Context, dst io.WriterAt, src outputSource) error {
	if src.offset < 0 || src.size < 0 || src.offset > math.MaxInt64-src.size {
		return malformed("output source range")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if src.size == 0 {
		return nil
	}
	buf, release, err := transferBuffer(ctx, src.size)
	if err != nil {
		return err
	}
	defer release()
	for offset := int64(0); offset < src.size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := buf[:int(min(int64(len(buf)), src.size-offset))]
		n, readErr := src.reader.ReadAt(chunk, src.offset+offset)
		if n < 0 || n > len(chunk) {
			return errors.Join(io.ErrUnexpectedEOF, readErr)
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(err, readErr)
		}
		if n > 0 {
			written, writeErr := dst.WriteAt(chunk[:n], offset)
			if written != n {
				writeErr = errors.Join(io.ErrShortWrite, writeErr)
			}
			if writeErr != nil {
				return errors.Join(writeErr, readErr, ctx.Err())
			}
		}
		if n != len(chunk) {
			return errors.Join(io.ErrUnexpectedEOF, readErr, ctx.Err())
		}
		// ReaderAt may return EOF together with a completely filled request.
		// Only bare EOF is benign: a joined error can also contain an I/O fault.
		if readErr != nil && readErr != io.EOF {
			return errors.Join(readErr, ctx.Err())
		}
		offset += int64(n)
	}
	return ctx.Err()
}

type outputFile interface {
	io.WriterAt
	Truncate(int64) error
	Sync() error
}

// populateOutput preserves the writer's order: bytes, length, representation-
// specific metadata, then sync. It neither closes handles nor commits names.
func populateOutput(ctx context.Context, dst outputFile, src outputSource, metadata func() error) error {
	if err := transferOutput(ctx, dst, src); err != nil {
		return err
	}
	if err := dst.Truncate(src.size); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if metadata != nil {
		if err := metadata(); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := dst.Sync(); err != nil {
		return err
	}
	return ctx.Err()
}

// A close failure must be reported, but must not cause a second close attempt
// on a descriptor the OS may already have released. Operation-local state also
// lets an explicit pre-rename close coexist with deferred failure cleanup.
type operationCloser struct{ close func() error }

func (c *operationCloser) Close() error {
	close := c.close
	c.close = nil
	if close == nil {
		return nil
	}
	return close()
}
