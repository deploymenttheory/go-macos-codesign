package codesign

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"testing"
)

func signatureTestStorage(t *testing.T, budget int64) (context.Context, *workingStorage, string) {
	t.Helper()
	dir := t.TempDir()
	ctx, storage, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: budget, TemporaryDirectory: dir}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := storage.Close(); err != nil {
			t.Error(err)
		}
		files, err := os.ReadDir(dir)
		if err != nil || len(files) != 0 {
			t.Error("signature scratch leaked", files, err)
		}
	})
	return ctx, storage, dir
}

func TestSignatureIndexMembershipAndNeighbors(t *testing.T) {
	for _, budget := range []int64{transferBufferSize, defaultWorkingMemory} {
		t.Run(fmtBudget(budget), func(t *testing.T) {
			ctx, storage, _ := signatureTestStorage(t, budget)
			x := signatureIndex{ctx: ctx}
			keys := []uint32{0x10, 0x18, 0, math.MaxUint32 - 1}
			for i := uint32(1); i < 2048; i++ {
				keys = append(keys, ((i*4051)&0xffff)*32+256)
			}
			model := map[uint32]uint32{}
			for _, key := range keys {
				if _, exists := model[key]; exists {
					continue
				}
				if duplicate, err := x.insert(key, key+1); err != nil || duplicate {
					t.Fatal(key, duplicate, err)
				}
				model[key] = key + 1
				if value, exists, err := x.find(key); err != nil || !exists || value != key+1 {
					t.Fatal(key, value, exists, err)
				}
				if duplicate, err := x.insert(key, 123); err != nil || !duplicate {
					t.Fatal("duplicate", key, duplicate, err)
				}
			}
			for key := uint32(1); key < 65536; key += 13 {
				value, exists, err := x.find(key)
				want, found := model[key]
				if err != nil || exists != found || found && value != want {
					t.Fatal(key, value, exists, err)
				}
				for _, width := range []uint32{1, 5, 101} {
					wantOverlap := false
					for start, end := range model {
						wantOverlap = wantOverlap || key < end && start < key+width
					}
					got, err := x.overlaps(key, key+width)
					if err != nil || got != wantOverlap {
						t.Fatal("interval mismatch", key, width, got, wantOverlap, err)
					}
				}
			}
			if x.count != uint32(len(model)*2-1) || storage.stats.PeakMemoryBytes > budget {
				t.Fatal(x.count, storage.stats)
			}
			if budget == transferBufferSize && storage.stats.SpillFiles != 1 {
				t.Fatal("index did not spill", storage.stats)
			}
		})
	}
}

type signatureIndexFaultIO struct {
	err   error
	short bool
}

func (f signatureIndexFaultIO) ReadAt(p []byte, _ int64) (int, error) {
	if f.short {
		return 0, f.err
	}
	return len(p), f.err
}
func (f signatureIndexFaultIO) WriteAt(p []byte, _ int64) (int, error) {
	if f.short {
		return 0, f.err
	}
	return len(p), f.err
}

func TestSignatureIndexFailures(t *testing.T) {
	fault := errors.New("signature index storage fault")
	for _, mode := range []string{"allocation", "read", "read-short", "read-joined-eof", "write", "write-short", "cancelled", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			ctx, storage, _ := signatureTestStorage(t, transferBufferSize)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			x := signatureIndex{ctx: ctx}
			switch mode {
			case "allocation":
				storage.create = func(string, string) (scratchFile, error) { return nil, fault }
			case "overflow":
				x.count = math.MaxUint32
			default:
				if _, err := x.insert(3, 4); err != nil {
					t.Fatal(err)
				}
			}
			want := fault
			switch mode {
			case "read", "read-short", "read-joined-eof":
				err := fault
				if mode == "read-joined-eof" {
					err = errors.Join(io.EOF, fault)
				}
				x.extents[0].reader = signatureIndexFaultIO{err: err, short: mode == "read-short"}
			case "write", "write-short":
				x.extents[0].writer = signatureIndexFaultIO{err: fault, short: mode == "write-short"}
			case "cancelled":
				cancel()
				want = context.Canceled
			case "overflow":
				want = ErrFormat
			}
			if _, err := x.insert(9, 10); !errors.Is(err, want) {
				t.Fatal(err, want)
			}
			if mode == "read" || mode == "read-short" || mode == "read-joined-eof" || mode == "cancelled" {
				if _, _, err := x.find(3); !errors.Is(err, want) {
					t.Fatal("lookup", err)
				}
				if _, err := x.overlaps(0, 12); !errors.Is(err, want) {
					t.Fatal("neighbors", err)
				}
			}
		})
	}
}

// Fault every actual index I/O, including the second descent, branch append,
// parent update and predecessor/successor descent. This catches swallowed late
// failures that a failing first lookup alone cannot exercise.
type signatureIndexCountingFile struct {
	scratchFile
	calls, fail int
	fault       error
}

func (f *signatureIndexCountingFile) ReadAt(p []byte, at int64) (int, error) {
	f.calls++
	if f.calls == f.fail {
		return 0, f.fault
	}
	return f.scratchFile.ReadAt(p, at)
}
func (f *signatureIndexCountingFile) WriteAt(p []byte, at int64) (int, error) {
	f.calls++
	if f.calls == f.fail {
		return 0, f.fault
	}
	return f.scratchFile.WriteAt(p, at)
}
func TestSignatureIndexLateFailures(t *testing.T) {
	fault := errors.New("late signature index fault")
	for _, op := range []string{"insert-left", "insert-right", "neighbors-left", "neighbors-right"} {
		run := func(fail int) int {
			ctx, s, _ := signatureTestStorage(t, transferBufferSize)
			create := s.create
			var file *signatureIndexCountingFile
			s.create = func(dir, pattern string) (scratchFile, error) {
				f, err := create(dir, pattern)
				if err != nil {
					return nil, err
				}
				file = &signatureIndexCountingFile{scratchFile: f, fault: fault}
				return file, nil
			}
			x := signatureIndex{ctx: ctx}
			for _, k := range []uint32{0x10, 0x18, 0x30, 0x38, 0x80, 0x88, 0xa0, 0xa8} {
				if _, err := x.insert(k, k+1); err != nil {
					t.Fatal(err)
				}
			}
			file.calls, file.fail = 0, fail
			var err error
			switch op {
			case "insert-left":
				_, err = x.insert(0x11, 0x12)
			case "insert-right":
				_, err = x.insert(0xa9, 0xaa)
			case "neighbors-left":
				_, err = x.overlaps(0x09, 0x0a)
			case "neighbors-right":
				_, err = x.overlaps(0xb1, 0xb2)
			}
			if fail > 0 && !errors.Is(err, fault) || fail == 0 && err != nil {
				t.Fatalf("%s I/O %d: %v", op, fail, err)
			}
			return file.calls
		}
		calls := run(0)
		for i := 1; i <= calls; i++ {
			run(i)
		}
	}
	ctx, _, _ := signatureTestStorage(t, transferBufferSize)
	ctx, cancel := context.WithCancel(ctx)
	x := signatureIndex{ctx: ctx}
	cancel()
	if err := x.put(1, signatureIndexNode{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
