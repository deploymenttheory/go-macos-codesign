package codesign

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// ReportVisitor consumes a report while its input and scratch storage remain
// open. operationErr is the inspection/verification result, including any
// detectable input changes. The callback is called exactly once, even when no
// report could be produced. Its error is joined with the operation and cleanup
// errors. It must not modify the input or retain the report after returning.
//
// Borrowed signatures omit Blobs and Directory.Raw. Use ReadBlob, BlobSize and
// Directory.Size when encoded data is needed. ReadBlob returns owned bytes;
// requesting a complete component necessarily allocates those returned bytes.
type ReportVisitor func(report *Report, operationErr error) error

type reportVisitKey struct{}
type reportVisit struct {
	visitor ReportVisitor
	called  bool
}

// VisitInspection inspects a path without retaining complete signature blobs or
// CodeDirectory hash tables in a public report. The visitor can use the usual
// descriptive report methods before the held input is closed. Inspect and
// InspectWithOptions retain their existing owned-byte return contracts.
func VisitInspection(ctx context.Context, path string, opts PathOptions, visitor ReportVisitor) error {
	return visitReport(ctx, visitor, func(ctx context.Context) (*Report, error) {
		return InspectWithOptions(ctx, path, opts)
	})
}

// VisitVerification performs the same validation as Verify, using held ranges
// for signature components and stored page hashes. The visitor runs before the
// input is closed; close/cleanup errors can still make the returned error nonnil.
func VisitVerification(ctx context.Context, path string, opts VerifyOptions, visitor ReportVisitor) error {
	return visitReport(ctx, visitor, func(ctx context.Context) (*Report, error) {
		return Verify(ctx, path, opts)
	})
}

func visitReport(ctx context.Context, visitor ReportVisitor, operation func(context.Context) (*Report, error)) error {
	if visitor == nil {
		return fmt.Errorf("report visitor is required")
	}
	visit := &reportVisit{visitor: visitor}
	report, err := operation(context.WithValue(ctx, reportVisitKey{}, visit))
	if !visit.called {
		err = errors.Join(err, visit.visitor(report, err))
	}
	return err
}

func consumeReport(ctx context.Context, report *Report, err error) error {
	if visit, ok := ctx.Value(reportVisitKey{}).(*reportVisit); ok && !visit.called {
		visit.called = true
		return errors.Join(err, visit.visitor(report, err))
	}
	return err
}

// Size is the complete encoded CodeDirectory length, including its header.
func (d Directory) Size() int64 {
	if d.view != nil {
		return d.view.source.source.size
	}
	return int64(len(d.Raw))
}

func (d Directory) hashAt(offset uint64) ([]byte, error) {
	if d.view != nil {
		return d.view.source.read(offset, uint64(d.HashSize))
	}
	if !rangeOK(offset, uint64(d.HashSize), uint64(len(d.Raw))) {
		return nil, malformed("CodeDirectory hash bounds")
	}
	return d.Raw[offset : offset+uint64(d.HashSize)], nil
}

// ReadBlob returns an owned copy of the complete component encoding, or nil
// when the slot is absent. Borrowed reports permit this only inside the visitor.
func (s *Signature) ReadBlob(slot uint32) ([]byte, error) {
	if s.view != nil {
		source, found, err := s.view.component(slot)
		if err != nil || !found {
			return nil, err
		}
		return source.read(0, uint64(source.source.size))
	}
	data := s.find(slot)
	if data == nil {
		return nil, nil
	}
	return append([]byte(nil), data...), nil
}

// BlobSize returns the encoded component length, or zero for an absent slot.
func (s *Signature) BlobSize(slot uint32) (int64, error) {
	if s.view != nil {
		source, _, err := s.view.component(slot)
		return source.source.size, err
	}
	return int64(len(s.find(slot))), nil
}

// BlobReader returns a bounded reader for a complete encoded component, or nil
// for an absent slot. On a borrowed report it is valid only during the visitor.
// No new file descriptor or component-sized buffer is allocated.
func (s *Signature) BlobReader(slot uint32) (*io.SectionReader, error) {
	if s.view != nil {
		source, found, err := s.view.component(slot)
		if err != nil || !found {
			return nil, err
		}
		return io.NewSectionReader(source.source.reader, source.source.offset, source.source.size), nil
	}
	data := s.find(slot)
	if data == nil {
		return nil, nil
	}
	return io.NewSectionReader(rangeBuffer(data), 0, int64(len(data))), nil
}

func (s *Signature) componentBytes(slot uint32) ([]byte, error) {
	if s.view != nil {
		return s.ReadBlob(slot)
	}
	return s.find(slot), nil
}

func (s *Signature) componentDigest(ctx context.Context, slot uint32, kind uint8) ([]byte, bool, error) {
	if s.view != nil {
		source, found, err := s.view.component(slot)
		if err != nil || !found {
			return nil, found, err
		}
		sum, err := source.digest(kind, 0, uint64(source.source.size))
		return sum, true, err
	}
	data := s.find(slot)
	if len(data) == 0 {
		return nil, false, nil
	}
	sum, err := digestContext(ctx, kind, data)
	return sum, true, err
}
