package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
)

func TestPageHashBatchParity(t *testing.T) {
	data := make([]byte, 3*transferBufferSize+19)
	for i := range data {
		data[i] = byte(i % 251)
	}
	for _, page := range []uint32{1, 2, 4096, 16384, 1 << 30} {
		t.Run(fmt.Sprint(page), func(t *testing.T) {
			ctx, s, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize}))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var got, want []byte
			for at := 0; at < len(data); at += int(page) {
				h := sha256.Sum256(data[at:min(at+int(page), len(data))])
				want = append(want, h[:]...)
			}
			const base int64 = 1<<32 + 17
			calls := 0
			dst := transferWriterFunc(func(p []byte, at int64) (int, error) {
				if at != base+int64(len(got)) || len(p) > transferBufferSize/2 {
					t.Fatal("wrong output range", at, len(p))
				}
				calls++
				got = append(got, p...)
				return len(p), nil
			})
			if err := hashCodePagesTo(ctx, byteOutput(data), page, dst, base); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("page hashes differ from independent SHA-256 digests")
			}
			wantCalls := (len(want) + transferBufferSize/2 - 1) / (transferBufferSize / 2)
			if calls != wantCalls {
				t.Fatalf("write calls=%d, want %d bounded batches", calls, wantCalls)
			}
			if s.stats.MemoryBytes != 0 || s.stats.PeakMemoryBytes != transferBufferSize {
				t.Fatal("reservation leak or extra buffer", s.stats)
			}
		})
	}
}

func TestPageHashBatchFailures(t *testing.T) {
	fault := errors.New("spill write failed")
	for _, tc := range []struct {
		name   string
		delta  int
		fault  error
		cancel bool
	}{
		{"short", -1, nil, false}, {"negative", -transferBufferSize, nil, false}, {"excess", 1, nil, false},
		{"full-error", 0, fault, false}, {"short-error", -1, fault, false},
		{"cancel", 0, nil, true}, {"cancel-error", -1, fault, true},
	} {
		for _, size := range []int{31, 3*transferBufferSize + 1} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, size), func(t *testing.T) {
				ctx, s, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize}))
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				calls := 0
				dst := transferWriterFunc(func(p []byte, _ int64) (int, error) {
					calls++
					if tc.cancel {
						cancel()
					}
					return len(p) + tc.delta, tc.fault
				})
				err = hashCodePagesTo(ctx, byteOutput(make([]byte, size)), 32, dst, 0)
				if err == nil || calls != 1 {
					t.Fatal("failed batch retried or error lost", calls, err)
				}
				if tc.delta != 0 && !errors.Is(err, io.ErrShortWrite) {
					t.Fatal(err)
				}
				if tc.fault != nil && !errors.Is(err, fault) {
					t.Fatal(err)
				}
				if tc.cancel && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if s.stats.MemoryBytes != 0 {
					t.Fatal("reservation leaked", s.stats)
				}
			})
		}
	}
}

func TestPageHashBatchBoundsAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		source outputSource
		page   uint32
		at     int64
	}{
		{outputSource{}, 0, 0}, {outputSource{size: -1}, 1, 0}, {outputSource{offset: -1}, 1, 0},
		{outputSource{offset: math.MaxInt64, size: 1}, 1, 0}, {outputSource{}, 1, -1},
		{outputSource{size: 1}, 1, math.MaxInt64}, {outputSource{size: math.MaxInt64}, 1, 0},
	} {
		if err := hashCodePagesTo(t.Context(), tc.source, tc.page, nil, tc.at); !errors.Is(err, ErrFormat) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, size := range []int{0, 1} {
		if err := hashCodePagesTo(ctx, byteOutput(make([]byte, size)), 1, nil, 0); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if err := hashCodePagesTo(t.Context(), outputSource{}, 1, nil, 0); err != nil {
		t.Fatal(err)
	}
	// A read error must not flush the digest bytes still queued in memory.
	readFault := errors.New("source failed after read")
	writes := 0
	src := outputSource{size: 64, reader: transferReaderFunc(func(p []byte, _ int64) (int, error) { clear(p); return len(p), readFault })}
	dst := transferWriterFunc(func(p []byte, _ int64) (int, error) { writes++; return len(p), nil })
	if err := hashCodePagesTo(t.Context(), src, 64, dst, 0); !errors.Is(err, readFault) || writes != 0 {
		t.Fatal(writes, err)
	}
	batch := pageHashBatch{ctx: t.Context(), buf: make([]byte, 32)}
	if err := batch.flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := batch.WriteAt([]byte{1}, 1); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	if _, err := batch.WriteAt(make([]byte, 33), 0); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	batch.ctx = ctx
	if err := batch.flush(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
