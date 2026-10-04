package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"testing"
)

type transferReaderFunc func([]byte, int64) (int, error)

func (f transferReaderFunc) ReadAt(p []byte, offset int64) (int, error) { return f(p, offset) }

type transferWriterFunc func([]byte, int64) (int, error)

func (f transferWriterFunc) WriteAt(p []byte, offset int64) (int, error) { return f(p, offset) }

func TestOutputTransferBounds(t *testing.T) {
	for _, size := range []int{0, 1, transferBufferSize - 1, transferBufferSize, transferBufferSize + 1, 3*transferBufferSize + 17} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{0x63}, size)
			var got []byte
			writer := transferWriterFunc(func(p []byte, offset int64) (int, error) {
				if len(p) > transferBufferSize || offset != int64(len(got)) {
					t.Fatal("unbounded or mispositioned transfer", len(p), offset)
				}
				got = append(got, p...)
				return len(p), nil
			})
			if err := transferOutput(context.Background(), writer, byteOutput(data)); err != nil || !bytes.Equal(got, data) {
				t.Fatal("incomplete transfer", err, len(got))
			}
		})
	}
	for _, offset := range []int64{1<<32 - 1, 1 << 32, 1<<32 + 1, math.MaxInt64 - 2*transferBufferSize} {
		t.Run(fmt.Sprintf("offset-%d", offset), func(t *testing.T) {
			var read, written int64
			src := outputSource{offset: offset, size: 2 * transferBufferSize}
			src.reader = transferReaderFunc(func(p []byte, at int64) (int, error) {
				if at != offset+read || len(p) > transferBufferSize {
					t.Fatal("source offset narrowed", at, read)
				}
				read += int64(len(p))
				return len(p), io.EOF // permitted with a full ReaderAt request
			})
			writer := transferWriterFunc(func(p []byte, at int64) (int, error) {
				if at != written {
					t.Fatal("incorrect destination offset", at)
				}
				written += int64(len(p))
				return len(p), nil
			})
			if err := transferOutput(context.Background(), writer, src); err != nil || written != src.size {
				t.Fatal(written, err)
			}
		})
	}
	for i, source := range []outputSource{{offset: -1}, {size: -1}, {offset: math.MaxInt64, size: 1}} {
		t.Run(fmt.Sprintf("invalid-%d", i), func(t *testing.T) {
			if err := transferOutput(context.Background(), nil, source); !errors.Is(err, ErrFormat) {
				t.Fatal(err)
			}
		})
	}
}

func TestOutputTransferLargeLength(t *testing.T) {
	// A virtual source/sink exercises every 64-bit offset without allocating or
	// pretending to have written a physical 4 GiB acceptance fixture.
	const size = int64(1<<32 + 17)
	var read, written int64
	src := outputSource{size: size, reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
		if at != read || len(p) > transferBufferSize {
			t.Fatal(at, read, len(p))
		}
		read += int64(len(p))
		return len(p), nil
	})}
	dst := transferWriterFunc(func(p []byte, at int64) (int, error) {
		if at != written {
			t.Fatal(at, written)
		}
		written += int64(len(p))
		return len(p), nil
	})
	if err := transferOutput(context.Background(), dst, src); err != nil || written != size || read != size {
		t.Fatal(read, written, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	read, written = 0, 0
	dst = transferWriterFunc(func(p []byte, at int64) (int, error) {
		written += int64(len(p))
		cancel()
		return len(p), nil
	})
	if err := transferOutput(ctx, dst, src); !errors.Is(err, context.Canceled) || written != transferBufferSize || read != written {
		t.Fatal(read, written, err)
	}
}

func TestOutputTransferFaults(t *testing.T) {
	readFailure, writeFailure := errors.New("read fault"), errors.New("write fault")
	for _, tc := range []struct {
		name              string
		read, write       int
		readErr, writeErr error
		cancel            string
		want              []error
		writes            int
	}{
		{"read-negative", -1, 8, nil, nil, "", []error{io.ErrUnexpectedEOF}, 0},
		{"read-excess", 9, 8, nil, nil, "", []error{io.ErrUnexpectedEOF}, 0},
		{"read-zero", 0, 0, nil, nil, "", []error{io.ErrUnexpectedEOF}, 0},
		{"read-short", 3, 3, nil, nil, "", []error{io.ErrUnexpectedEOF}, 1},
		{"read-eof", 3, 3, io.EOF, nil, "", []error{io.ErrUnexpectedEOF, io.EOF}, 1},
		{"read-partial-error", 3, 3, readFailure, nil, "", []error{io.ErrUnexpectedEOF, readFailure}, 1},
		{"read-full-error", 8, 8, readFailure, nil, "", []error{readFailure}, 1},
		{"read-full-joined-eof", 8, 8, errors.Join(io.EOF, readFailure), nil, "", []error{readFailure}, 1},
		{"write-zero", 8, 0, nil, nil, "", []error{io.ErrShortWrite}, 1},
		{"write-negative", 8, -1, nil, nil, "", []error{io.ErrShortWrite}, 1},
		{"write-excess", 8, 9, nil, nil, "", []error{io.ErrShortWrite}, 1},
		{"write-partial-error", 8, 3, nil, writeFailure, "", []error{io.ErrShortWrite, writeFailure}, 1},
		{"write-full-error", 8, 8, nil, writeFailure, "", []error{writeFailure}, 1},
		{"both-errors", 3, 3, readFailure, writeFailure, "", []error{readFailure, writeFailure}, 1},
		{"cancel-before", 8, 8, nil, nil, "before", []error{context.Canceled}, 0},
		{"cancel-read", 8, 8, nil, nil, "read", []error{context.Canceled}, 0},
		{"cancel-read-error", 3, 3, readFailure, nil, "read", []error{context.Canceled, readFailure}, 0},
		{"cancel-write", 8, 8, nil, nil, "write", []error{context.Canceled}, 1},
		{"cancel-write-error", 8, 3, nil, writeFailure, "write", []error{context.Canceled, io.ErrShortWrite, writeFailure}, 1},
		{"cancel-write-read-error", 3, 3, readFailure, nil, "write", []error{context.Canceled, io.ErrUnexpectedEOF, readFailure}, 1},
		{"cancel-write-full-read-error", 8, 8, readFailure, nil, "write", []error{context.Canceled, readFailure}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel == "before" {
				cancel()
			}
			reads, writes := 0, 0
			src := outputSource{size: 8, reader: transferReaderFunc(func([]byte, int64) (int, error) {
				reads++
				if tc.cancel == "read" {
					cancel()
				}
				return tc.read, tc.readErr
			})}
			dst := transferWriterFunc(func([]byte, int64) (int, error) {
				writes++
				if tc.cancel == "write" {
					cancel()
				}
				return tc.write, tc.writeErr
			})
			err := transferOutput(ctx, dst, src)
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Fatalf("lost %v: %v", want, err)
				}
			}
			if writes != tc.writes || reads > 1 || (tc.cancel == "before" && reads != 0) {
				t.Fatal("I/O after failure", reads, writes)
			}
		})
	}
}

type lifecycleOutput struct {
	write    transferWriterFunc
	truncate func(int64) error
	sync     func() error
}

func (f lifecycleOutput) WriteAt(p []byte, at int64) (int, error) { return f.write(p, at) }
func (f lifecycleOutput) Truncate(size int64) error               { return f.truncate(size) }
func (f lifecycleOutput) Sync() error                             { return f.sync() }

func TestOutputLifecycleFailures(t *testing.T) {
	steps := []string{"write", "truncate", "metadata", "sync"}
	failure := errors.New("checkpoint fault")
	for _, mode := range []string{"error", "cancel"} {
		for stop, name := range steps {
			t.Run(mode+"/"+name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var events []string
				step := func(at string) error {
					events = append(events, at)
					if name == at {
						if mode == "error" {
							return failure
						}
						cancel()
					}
					return nil
				}
				dst := lifecycleOutput{
					write: func(p []byte, _ int64) (int, error) { return len(p), step("write") },
					truncate: func(size int64) error {
						if size != 3 {
							t.Fatal(size)
						}
						return step("truncate")
					},
					sync: func() error { return step("sync") },
				}
				err := populateOutput(ctx, dst, byteOutput([]byte("abc")), func() error { return step("metadata") })
				want := failure
				if mode == "cancel" {
					want = context.Canceled
				}
				if !errors.Is(err, want) || !reflect.DeepEqual(events, steps[:stop+1]) {
					t.Fatal("later checkpoint ran or failure lost", events, err)
				}
			})
		}
	}
}

func TestOperationCloseOwnership(t *testing.T) {
	failure := errors.New("close fault")
	for _, err := range []error{nil, failure} {
		calls := 0
		closer := operationCloser{func() error { calls++; return err }}
		if got := closer.Close(); !errors.Is(got, err) {
			t.Fatal(got)
		}
		if got := closer.Close(); got != nil || calls != 1 {
			t.Fatal("retried consumed close", got, calls)
		}
	}
}

type operationReaderFunc func([]byte) (int, error)

func (f operationReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestBoundedOperationReads(t *testing.T) {
	for _, size := range []int{0, 1, transferBufferSize, transferBufferSize + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{42}, size)
			got, err := readBoundedContext(context.Background(), bytes.NewReader(data), int64(size))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatal(err, len(got))
			}
			if _, err := readBoundedContext(context.Background(), bytes.NewReader(append(data, 1)), int64(size)); !errors.Is(err, ErrUnsupported) {
				t.Fatal(err)
			}
		})
	}
	for _, limit := range []int64{-1, math.MaxInt64} {
		if _, err := readBoundedContext(context.Background(), nil, limit); !errors.Is(err, ErrFormat) {
			t.Fatal(err)
		}
	}
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprintf("cancel-before=%t", before), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if before {
				cancel()
			}
			reader := operationReaderFunc(func(p []byte) (int, error) {
				if before || len(p) > transferBufferSize {
					t.Fatal("unexpected read", len(p))
				}
				cancel()
				return 0, io.ErrUnexpectedEOF
			})
			data, err := readBoundedContext(ctx, reader, 2*transferBufferSize)
			if data != nil || !errors.Is(err, context.Canceled) || (!before && !errors.Is(err, io.ErrUnexpectedEOF)) {
				t.Fatal(data, err)
			}
		})
	}
}
