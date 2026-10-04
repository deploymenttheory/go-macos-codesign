package codesign

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
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

// Read to EOF rather than the initial stat size: a growing resource must still
// consume the operation budget. Both resource seals cover the same byte stream.
func resourceDigests(ctx context.Context, r io.Reader, limit int64) ([]byte, []byte, int64, error) {
	if limit < 0 || limit == math.MaxInt64 {
		return nil, nil, 0, unsupported("bundle resource data exceeds 1 GiB")
	}
	h1, h2 := sha1.New(), sha256.New()
	n, err := io.Copy(io.MultiWriter(h1, h2), io.LimitReader(operationReader{ctx, r}, limit+1))
	if err != nil {
		return nil, nil, n, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, n, err
	}
	if n > limit {
		return nil, nil, n, unsupported("bundle resource data exceeds 1 GiB")
	}
	return h1.Sum(nil), h2.Sum(nil), n, nil
}
