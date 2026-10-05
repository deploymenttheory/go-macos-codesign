package codesign

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
)

// Small code pages avoid allocating a transport buffer for every digest.
// Larger pages and special slots observe cancellation between bounded reads.
func digestContext(ctx context.Context, kind uint8, data []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) > transferBufferSize {
		return digestSource(ctx, kind, byteOutput(data))
	}
	sum, err := digest(kind, data)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return sum, nil
}

// Only transferOutput calls this adapter, in ascending contiguous order.
// The hash itself is sequential; it does not implement arbitrary random writes.
type hashOutput struct{ hash.Hash }

func (h hashOutput) WriteAt(p []byte, _ int64) (int, error) { return h.Write(p) }

func digestSource(ctx context.Context, kind uint8, src outputSource) ([]byte, error) {
	var h hash.Hash
	switch kind {
	case 1:
		h = sha1.New()
	case 2, 3:
		h = sha256.New()
	case 4:
		h = sha512.New384()
	default:
		return nil, unsupported(fmt.Sprintf("hash type %d", kind))
	}
	if err := transferOutput(ctx, hashOutput{h}, src); err != nil {
		return nil, err
	}
	sum := h.Sum(nil)
	if kind == 3 {
		sum = sum[:20]
	}
	return sum, nil
}

// A single transfer buffer feeds every page. Even a 1 GiB page needs only the
// hash state and the existing bounded transport buffer, not a page allocation.
type codePageOutput struct {
	hash            hash.Hash
	page, remaining int64
	sums            []byte
	writer          io.WriterAt
	offset          int64
	sum             [sha256.Size]byte
}

func (p *codePageOutput) WriteAt(data []byte, _ int64) (int, error) {
	n := len(data)
	for len(data) > 0 {
		chunk := min(int64(len(data)), p.remaining)
		_, _ = p.hash.Write(data[:chunk])
		data = data[chunk:]
		p.remaining -= chunk
		if p.remaining == 0 {
			if err := p.finish(); err != nil {
				return n - len(data), err
			}
		}
	}
	return n, nil
}

func (p *codePageOutput) finish() error {
	if p.writer == nil {
		p.hash.Sum(p.sums[:0])
		p.sums = p.sums[sha256.Size:]
	} else {
		sum := p.hash.Sum(p.sum[:0])
		n, err := p.writer.WriteAt(sum, p.offset)
		if err != nil {
			return err
		}
		if n != len(sum) {
			return io.ErrShortWrite
		}
		p.offset += int64(n)
	}
	p.hash.Reset()
	p.remaining = p.page
	return nil
}

func hashCodePages(ctx context.Context, src outputSource, page uint32, sums []byte) error {
	p := codePageOutput{hash: sha256.New(), page: int64(page), remaining: int64(page), sums: sums}
	if err := transferOutput(ctx, &p, src); err != nil {
		return err
	}
	if p.remaining != p.page {
		return p.finish()
	}
	return nil
}

func hashCodePagesTo(ctx context.Context, src outputSource, page uint32, dst io.WriterAt, offset int64) error {
	if page == 0 || src.size < 0 || src.offset < 0 || src.offset > math.MaxInt64-src.size || offset < 0 {
		return malformed("code page hash range")
	}
	pages := src.size / int64(page)
	if src.size%int64(page) != 0 {
		pages++
	}
	if pages > (math.MaxInt64-offset)/sha256.Size {
		return malformed("code page hash output overflow")
	}
	if src.size == 0 {
		return ctx.Err()
	}
	buf, release, err := transferBuffer(ctx, max(src.size, 2*sha256.Size))
	if err != nil {
		return err
	}
	defer release()
	// Both partitions share one reservation, even under the minimum budget.
	// Round the output partition down to complete SHA-256 slots.
	split := (len(buf) / 2) &^ (sha256.Size - 1)
	batch := pageHashBatch{ctx: ctx, dst: dst, buf: buf[:split], offset: offset}
	p := codePageOutput{hash: sha256.New(), page: int64(page), remaining: int64(page), writer: &batch, offset: offset}
	if err := transferOutputBuffer(ctx, &p, src, buf[split:]); err != nil {
		return err
	}
	if p.remaining != p.page {
		if err := p.finish(); err != nil {
			return err
		}
	}
	return batch.flush()
}

// Sequential digest slots are staged until a bounded batch is ready. On error
// the caller discards the generated section; no failed batch is retried.
type pageHashBatch struct {
	ctx    context.Context
	dst    io.WriterAt
	buf    []byte
	used   int
	offset int64
}

func (b *pageHashBatch) WriteAt(p []byte, at int64) (int, error) {
	if at != b.offset+int64(b.used) || len(p) > len(b.buf)-b.used {
		return 0, malformed("noncontiguous page hash batch")
	}
	b.used += copy(b.buf[b.used:], p)
	if b.used == len(b.buf) {
		return len(p), b.flush()
	}
	return len(p), nil
}

func (b *pageHashBatch) flush() error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if b.used == 0 {
		return nil
	}
	n, err := b.dst.WriteAt(b.buf[:b.used], b.offset)
	if n != b.used {
		err = errors.Join(io.ErrShortWrite, err)
	}
	if err != nil || b.ctx.Err() != nil {
		return errors.Join(err, b.ctx.Err())
	}
	b.offset += int64(b.used)
	b.used = 0
	return nil
}

// Read at most the known size plus one byte, detecting growth without following
// an indefinitely growing resource. Both seals cover the same byte stream.
func resourceDigests(ctx context.Context, r io.Reader, limit int64) ([]byte, []byte, int64, error) {
	if limit < 0 || limit == math.MaxInt64 {
		return nil, nil, 0, unsupported("resource size cannot be bounded")
	}
	h1, h2 := sha1.New(), sha256.New()
	buf, release, err := transferBuffer(ctx, limit+1)
	if err != nil {
		return nil, nil, 0, err
	}
	defer release()
	n, err := io.CopyBuffer(io.MultiWriter(h1, h2), io.LimitReader(operationReader{ctx, r}, limit+1), buf)
	if err != nil {
		return nil, nil, n, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, n, err
	}
	if n > limit {
		return nil, nil, n, invalid("resource grew during hashing")
	}
	return h1.Sum(nil), h2.Sum(nil), n, nil
}
