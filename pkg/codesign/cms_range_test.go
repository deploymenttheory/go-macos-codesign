package codesign

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"testing"
)

func TestCMSRangeLargeValues(t *testing.T) {
	for _, size := range []uint64{1<<30 - 1, 1 << 30, 1<<30 + 1, 2<<30 - 1, 2 << 30, 2<<30 + 1, math.MaxUint32} {
		// A source with a nonzero base and a definite OCTET STRING inside an
		// indefinite SEQUENCE. Payload reads are forbidden: this is an offset/
		// allocation control, not a native signature-acceptance assertion.
		leaf := derHeader(4, size)
		prefix := append([]byte{0x30, 0x80}, leaf...)
		length := uint64(len(prefix)) + size + 2
		const base = 37
		readBytes := 0
		reader := transferReaderFunc(func(p []byte, at int64) (int, error) {
			at -= base
			readBytes += len(p)
			if at >= 0 && uint64(at)+uint64(len(p)) <= uint64(len(prefix)) {
				return copy(p, prefix[at:]), nil
			}
			if uint64(at) == length-2 && len(p) == 2 {
				clear(p)
				return 2, io.EOF // A complete final read may also return EOF.
			}
			t.Fatalf("parser read payload at %d, bytes=%d, size=%d", at, len(p), size)
			return 0, io.ErrUnexpectedEOF
		})
		budget := 4096
		value, err := readCMSBERRange(codeSource{t.Context(), outputSource{reader, base, int64(length)}}, 0, length, 0, &budget)
		if err != nil || value.offset != 0 || value.length != length || value.content != 2 || value.contentSize != length-4 || value.tag != 0x30 {
			t.Fatal(size, value, err)
		}
		if readBytes > 16 || budget != 4094 {
			t.Fatal("unbounded header traversal", readBytes, budget)
		}
	}
}

func TestCMSRangeIOFailures(t *testing.T) {
	for _, data := range [][]byte{{0x30, 0x80, 4, 1, 42, 0, 0}, {4, 0x81, 0x80}} {
		for failAt := range len(data) {
			for _, failure := range []error{io.EOF, os.ErrPermission} {
				reader := transferReaderFunc(func(p []byte, at int64) (int, error) {
					if at <= int64(failAt) && int64(failAt) < at+int64(len(p)) {
						if errors.Is(failure, io.EOF) {
							return copy(p[:int64(failAt)-at], data[at:]), failure
						}
						copy(p, data[at:])
						return len(p), failure
					}
					return bytes.NewReader(data).ReadAt(p, at)
				})
				budget := 4096
				value, err := readCMSBERRange(codeSource{t.Context(), outputSource{reader: reader, size: int64(len(data))}}, 0, uint64(len(data)), 0, &budget)
				if err == nil && failAt != 4 { // Index 4 is deliberately unread payload.
					t.Fatal("ignored header read failure", failAt, failure, value)
				}
			}
		}
	}
	for _, bounds := range []outputSource{
		{reader: bytes.NewReader([]byte{4, 0}), offset: -1, size: 2},
		{reader: bytes.NewReader([]byte{4, 0}), size: -1},
		{reader: bytes.NewReader([]byte{4, 0}), offset: math.MaxInt64, size: 2},
		{reader: bytes.NewReader([]byte{4, 0}), size: 1},
	} {
		budget := 4096
		if _, err := readCMSBERRange(codeSource{t.Context(), bounds}, 0, 2, 0, &budget); !errors.Is(err, ErrFormat) {
			t.Fatal("accepted invalid source bounds", bounds, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	budget := 4096
	if _, err := readCMSBERRange(codeSource{ctx, byteOutput([]byte{4, 0})}, 0, 2, 0, &budget); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored initial cancellation", err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	reader := transferReaderFunc(func(p []byte, _ int64) (int, error) { cancel(); return copy(p, []byte{4, 0}), nil })
	budget = 4096
	if _, err := readCMSBERRange(codeSource{ctx, outputSource{reader: reader, size: 2}}, 0, 2, 0, &budget); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation during header read", err)
	}
}
