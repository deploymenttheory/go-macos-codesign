package codesign

import (
	"context"
	"errors"
	"io"
	"os"
)

// codeSource borrows a stable-size ReaderAt. The operation owns its descriptor.
// Metadata is still materialized for the public Report/Signature byte fields;
// payload ranges never need a whole-file buffer on this path.
type codeSource struct {
	ctx    context.Context
	source outputSource
}

func openCodeSource(ctx context.Context, f *os.File) (codeSource, error) {
	if err := ctx.Err(); err != nil {
		return codeSource{}, err
	}
	st, err := f.Stat()
	if err != nil {
		return codeSource{}, err
	}
	if !st.Mode().IsRegular() {
		return codeSource{}, unsupported("non-regular file")
	}
	return codeSource{ctx, outputSource{reader: f, size: st.Size()}}, nil
}

type rangeBuffer []byte

func (b rangeBuffer) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 || offset > int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[int(offset):])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (b rangeBuffer) WriteAt(p []byte, offset int64) (int, error) {
	return copy(b[int(offset):], p), nil
}

func (s codeSource) read(offset, length uint64) ([]byte, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if !rangeOK(offset, length, uint64(s.source.size)) {
		return nil, malformed("source range")
	}
	// Preserve the existing metadata allocation ceiling until Report/Signature
	// ownership and spill storage are integrated. This is not a payload limit.
	if length > maxFileSize {
		return nil, unsupported("metadata exceeds memory limit")
	}
	data := make([]byte, int(length))
	err := transferOutput(s.ctx, rangeBuffer(data), outputSource{s.source.reader, s.source.offset + int64(offset), int64(length)})
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s codeSource) container() (*container, error) {
	return parseContainerRange(uint64(s.source.size), s.read, func(offset, length uint64) (*image, error) {
		im, err := parseImageRange(length, func(at, n uint64) ([]byte, error) {
			return s.read(offset+at, n)
		})
		if err == nil {
			im.source = codeSource{s.ctx, outputSource{s.source.reader, s.source.offset + int64(offset), int64(length)}}
		}
		return im, err
	})
}

func (s codeSource) isDMG() (bool, error) {
	if s.source.size < int64(dmgFooterSize) {
		return false, nil
	}
	header, err := s.read(0, 4)
	if err != nil {
		return false, err
	}
	switch be.Uint32(header) {
	case 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		return false, nil
	}
	trailer, err := s.read(uint64(s.source.size)-uint64(dmgFooterSize), 4)
	return string(trailer) == "koly", err
}

func (s codeSource) zero(offset, length uint64) (bool, error) {
	if !rangeOK(offset, length, uint64(s.source.size)) {
		return false, malformed("padding source range")
	}
	for length > 0 {
		n := min(length, transferBufferSize)
		data, err := s.read(offset, n)
		if err != nil {
			return false, err
		}
		for _, b := range data {
			if b != 0 {
				return false, nil
			}
		}
		offset += n
		length -= n
	}
	return true, s.ctx.Err()
}

func (s codeSource) digest(kind uint8, offset, length uint64) ([]byte, error) {
	if !rangeOK(offset, length, uint64(s.source.size)) {
		return nil, malformed("hash source range")
	}
	return digestSource(s.ctx, kind, outputSource{s.source.reader, s.source.offset + int64(offset), int64(length)})
}

// A held descriptor protects object identity, not a snapshot of its contents.
// Catch detectable size/mtime changes, including truncation after the last read.
func sourceUnchanged(f *os.File, before os.FileInfo) error {
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return invalid("source changed during inspection or verification")
	}
	return nil
}

func withCodeSource(ctx context.Context, path string, operation func(codeSource, *os.File) (*Report, error)) (report *Report, failure error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		failure = errors.Join(failure, f.Close())
		if failure != nil && report != nil {
			report.Valid = false
		}
	}()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	source, err := openCodeSource(ctx, f)
	if err != nil {
		return nil, err
	}
	report, err = operation(source, f)
	err = errors.Join(err, sourceUnchanged(f, before), ctx.Err())
	if err != nil && report != nil {
		report.Valid = false
	}
	if report != nil {
		report.Path = path
	}
	err = consumeReport(ctx, report, err)
	return report, err
}

// Compile-time assertion also documents the transport used by range reads.
var _ io.WriterAt = rangeBuffer(nil)

func (s codeSource) inspect() (*Report, error) {
	if _, borrowed := s.ctx.Value(reportVisitKey{}).(*reportVisit); borrowed {
		return s.inspectView()
	}
	dmg, err := s.isDMG()
	if err != nil {
		return nil, err
	}
	if dmg {
		trailer, err := s.read(uint64(s.source.size)-uint64(dmgFooterSize), uint64(dmgFooterSize))
		if err != nil {
			return nil, err
		}
		m, err := parseDMGRange(uint64(s.source.size), trailer, s.read)
		if err != nil {
			return nil, err
		}
		return inspectDMGImage(m, uint64(s.source.size)), nil
	}
	c, err := s.container()
	if err != nil {
		return nil, err
	}
	return inspectContainer(c, s.read)
}

func (s codeSource) strict(architecture string, disabled bool) error {
	dmg, err := s.isDMG()
	if err != nil {
		return err
	}
	if dmg {
		return nil
	}
	c, err := s.container()
	if err != nil {
		return err
	}
	return verifyStrictContainer(c, uint64(s.source.size), architecture, disabled, s.zero)
}
