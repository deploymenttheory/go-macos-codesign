package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDMGTailLifecycle(t *testing.T) {
	data := bytes.Repeat([]byte{0x57}, transferBufferSize+1)
	for _, offset := range []uint64{8, 1<<32 - 1, 1 << 32, 1<<32 + 1} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			var got []byte
			var steps []string
			out := lifecycleOutput{
				write: func(p []byte, at int64) (int, error) {
					if uint64(at) != offset+uint64(len(got)) {
						t.Fatal("payload overwrite", at)
					}
					got = append(got, p...)
					steps = append(steps, "write")
					return len(p), nil
				},
				truncate: func(size int64) error {
					if uint64(size) != offset+uint64(len(data)) {
						t.Fatal("length", size)
					}
					steps = append(steps, "truncate")
					return nil
				},
				sync: func() error { steps = append(steps, "sync"); return nil },
			}
			if err := populateDMGTail(context.Background(), out, offset, data); err != nil || !bytes.Equal(got, data) || !reflect.DeepEqual(steps, []string{"write", "write", "truncate", "sync"}) {
				t.Fatal(err, steps)
			}
		})
	}
	for _, offset := range []uint64{math.MaxInt64, math.MaxUint64} {
		if err := populateDMGTail(context.Background(), nil, offset, data); !errors.Is(err, ErrFormat) {
			t.Fatal(err)
		}
	}
	fault := errors.New("disk full")
	for _, mode := range []string{"error", "cancel", "short"} {
		for _, stop := range []string{"write", "truncate", "sync"} {
			t.Run(mode+"/"+stop, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				stopped := false
				step := func(name string) error {
					if stopped {
						t.Fatal("continued after failure", name)
					}
					if name == stop {
						stopped = true
						if mode == "cancel" {
							cancel()
							return nil
						}
						return fault
					}
					return nil
				}
				out := lifecycleOutput{write: func(p []byte, _ int64) (int, error) {
					err := step("write")
					if mode == "short" && stop == "write" {
						return 1, err
					}
					return len(p), err
				}, truncate: func(int64) error { return step("truncate") }, sync: func() error { return step("sync") }}
				err := populateDMGTail(ctx, out, 1<<32, data)
				want := fault
				if mode == "cancel" {
					want = context.Canceled
				}
				if !errors.Is(err, want) || !stopped {
					t.Fatal(err)
				}
				if mode == "short" && stop == "write" && !errors.Is(err, io.ErrShortWrite) {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDMGSourceFailurePreservation(t *testing.T) {
	ctx := context.Background()
	data := testDMG(t)
	for _, mode := range []string{"stat", "read", "parse", "options", "page", "changed", "success"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "image.dmg")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			source, err := openCodeSource(ctx, file)
			if err != nil {
				t.Fatal(err)
			}
			opts := SignOptions{Identifier: "test"}
			switch mode {
			case "stat":
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "read":
				source.source.reader = transferReaderFunc(func([]byte, int64) (int, error) { return 0, io.ErrUnexpectedEOF })
			case "parse":
				bad := bytes.Clone(data)
				bad[len(bad)-512+7] = 99
				source.source.reader = bytes.NewReader(bad)
			case "options":
				opts.Identifier = "bad\x00id"
			case "page":
				opts.PageSize = 3
			case "changed":
				source.source.reader = transferReaderFunc(func(p []byte, at int64) (int, error) {
					if err := os.Truncate(path, int64(len(data))+1); err != nil {
						t.Fatal(err)
					}
					return bytes.NewReader(data).ReadAt(p, at)
				})
			}
			err = signDMGFile(ctx, file, path, source, opts)
			if mode == "success" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted failure")
			}
			got := readTestFile(t, path)
			if mode == "changed" {
				got = got[:len(data)]
			}
			if !bytes.Equal(got, data) {
				t.Fatal("failed signing changed data")
			}
		})
	}
	t.Run("cancel-every-checkpoint", func(t *testing.T) {
		cancelEveryHashCheckpoint(t, func(ctx context.Context) error {
			path := filepath.Join(t.TempDir(), "image.dmg")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			err := Sign(ctx, path, SignOptions{Identifier: "test"})
			got := readTestFile(t, path)
			if !bytes.Equal(got[:len(data)-512], data[:len(data)-512]) {
				t.Fatal("cancellation wrote payload")
			}
			return err
		})
	})
}

func TestDMGTailTargetValidation(t *testing.T) {
	for _, mode := range []string{"missing", "directory", "other", "changed", "closed", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			before, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := path
			switch mode {
			case "missing":
				target += "missing"
			case "directory":
				target = filepath.Dir(path)
			case "other":
				target += "other"
				if err := os.WriteFile(target, []byte("other"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed":
				if err := os.Truncate(path, 9); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			if err := writeDMGTail(ctx, target, f, before, 8, []byte("new")); err == nil {
				t.Fatal("accepted stale target")
			}
			if !bytes.Equal(readTestFile(t, path)[:8], []byte("original")) {
				t.Fatal("changed source")
			}
		})
	}
}

func TestDMGBuilderLimits(t *testing.T) {
	for _, length := range []uint64{1<<32 - 1, 1 << 32, 1<<32 + 1, math.MaxInt64} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			m, err := parseDMG(testDMG(t))
			if err != nil {
				t.Fatal(err)
			}
			m.footer.CodeSignatureOffset = length
			for _, page := range []uint32{0, 2} {
				tail, err := signDMGTail(context.Background(), m, SignOptions{Identifier: "test", PageSize: page}, false, func(_ uint8, offset, size uint64) ([]byte, error) {
					if offset != 0 || size != length {
						t.Fatal(offset, size)
					}
					return make([]byte, 32), nil
				})
				if page == 2 {
					if !errors.Is(err, ErrUnsupported) {
						t.Fatal(err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				sig, err := ParseSignature(tail[:len(tail)-512])
				if err != nil {
					t.Fatal(err)
				}
				cd := sig.Directories[0]
				if cd.CodeLimit != length {
					t.Fatal(cd.CodeLimit, length)
				}
				if length > math.MaxUint32 && (cd.Version != 0x20300 || be.Uint32(cd.Raw[32:]) != math.MaxUint32 || be.Uint64(cd.Raw[56:]) != length) {
					t.Fatal("64-bit limit header")
				}
			}
		})
	}
}
