package codesign

import (
	"context"
	"errors"
	"io"
	"math"
	"sort"
)

// An output plan owns generated metadata and borrows payload ranges. Every byte
// belongs to one span, including zero-filled allocation/alignment gaps. Readers
// never fetch source bytes replaced by a generated header or signature.
type outputSpan struct {
	start  int64
	source outputSource
}

type outputPlan struct {
	spans []outputSpan
	size  int64
}

type zeroSource struct{}

func (zeroSource) ReadAt(p []byte, _ int64) (int, error) {
	clear(p)
	return len(p), nil
}

func (p *outputPlan) append(src outputSource) error {
	if src.offset < 0 || src.size < 0 || src.offset > math.MaxInt64-src.size || p.size > math.MaxInt64-src.size || (src.size > 0 && src.reader == nil) {
		return malformed("output plan range")
	}
	if src.size != 0 {
		p.spans = append(p.spans, outputSpan{p.size, src})
		p.size += src.size
	}
	return nil
}

func (p *outputPlan) output() outputSource { return outputSource{reader: p, size: p.size} }

func (p *outputPlan) ReadAt(b []byte, at int64) (int, error) {
	if at < 0 {
		return 0, malformed("negative output offset")
	}
	if len(b) == 0 {
		return 0, nil
	}
	if at >= p.size {
		return 0, io.EOF
	}
	written := 0
	i := sort.Search(len(p.spans), func(i int) bool { return p.spans[i].start+p.spans[i].source.size > at })
	for i < len(p.spans) && written < len(b) {
		span := p.spans[i]
		delta := at - span.start
		chunk := b[written : written+int(min(int64(len(b)-written), span.source.size-delta))]
		n, err := span.source.reader.ReadAt(chunk, span.source.offset+delta)
		if n < 0 || n > len(chunk) {
			return written, errors.Join(io.ErrUnexpectedEOF, err)
		}
		written += n
		if n != len(chunk) {
			return written, errors.Join(io.ErrUnexpectedEOF, err)
		}
		if err != nil && err != io.EOF {
			return written, err
		}
		at += int64(n)
		i++
	}
	if written != len(b) {
		return written, io.EOF
	}
	return written, nil
}

// patchedOutput retains untouched source bytes (including old signature
// padding), extends with zeros, and replaces sorted, non-overlapping ranges.
func patchedOutput(base outputSource, size int64, patches ...outputSpan) (outputSource, error) {
	if size < 0 || base.size < 0 || base.offset < 0 || base.offset > math.MaxInt64-base.size {
		return outputSource{}, malformed("patched output range")
	}
	p := new(outputPlan)
	appendBase := func(end int64) error {
		if p.size < min(end, base.size) {
			if err := p.append(outputSource{base.reader, base.offset + p.size, min(end, base.size) - p.size}); err != nil {
				return err
			}
		}
		return p.append(outputSource{reader: zeroSource{}, size: end - p.size})
	}
	for _, patch := range patches {
		if patch.start < p.size || patch.start > size || patch.source.size < 0 || patch.source.size > size-patch.start {
			return outputSource{}, malformed("overlapping or out-of-bounds output patch")
		}
		if err := appendBase(patch.start); err != nil {
			return outputSource{}, err
		}
		if err := p.append(patch.source); err != nil {
			return outputSource{}, err
		}
	}
	if err := appendBase(size); err != nil {
		return outputSource{}, err
	}
	return p.output(), nil
}

func materializeOutput(ctx context.Context, src outputSource) ([]byte, error) {
	if src.size > maxFileSize {
		return nil, unsupported("output exceeds memory limit")
	}
	if src.size < 0 {
		return nil, malformed("negative output size")
	}
	b := make([]byte, int(src.size))
	if err := transferOutput(ctx, rangeBuffer(b), src); err != nil {
		return nil, err
	}
	return b, nil
}
