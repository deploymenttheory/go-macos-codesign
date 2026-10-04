package codesign

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMachOStreamingAllocation(t *testing.T) {
	seed := fixture(t, "unsigned-arm64")
	im, err := parseImage(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		size int64
		page uint32
	}{
		{"negative", -1, 0}, {"input32", 1 << 32, 0}, {"output32", math.MaxUint32, 0}, {"metadata", 1 << 30, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := signImageSource(context.Background(), im, outputSource{reader: zeroSource{}, size: tc.size}, SignOptions{Identifier: "large", PageSize: tc.page}); !errors.Is(err, ErrUnsupported) {
				t.Fatal(err)
			}
		})
	}
	t.Run("large-bounded-allocation", func(t *testing.T) {
		src, err := patchedOutput(byteOutput(seed), 1<<30+1)
		if err != nil {
			t.Fatal(err)
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		out, err := signImageSource(context.Background(), im, src, SignOptions{Identifier: "large"})
		runtime.ReadMemStats(&after)
		if err != nil || out.size <= 1<<30 {
			t.Fatal(out.size, err)
		}
		allocated := after.TotalAlloc - before.TotalAlloc
		if allocated > 16<<20 {
			t.Fatalf("payload-sized allocation: %d bytes", allocated)
		}
		t.Logf("1 GiB+1 payload planned and hashed using %d allocated Go bytes", allocated)
	})
	t.Run("read-fault", func(t *testing.T) {
		fault := errors.New("header read")
		_, err := signImageSource(context.Background(), im, outputSource{transferReaderFunc(func([]byte, int64) (int, error) { return 0, fault }), 0, int64(len(seed))}, SignOptions{Identifier: "fault"})
		if !errors.Is(err, fault) {
			t.Fatal(err)
		}
	})
	t.Run("header-no-room", func(t *testing.T) {
		_, err := signImageSource(context.Background(), im, outputSource{reader: zeroSource{}, size: 1}, SignOptions{Identifier: "short"})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	})
	t.Run("removal-read-fault", func(t *testing.T) {
		signed, err := SignBytes(context.Background(), seed, SignOptions{Identifier: "test"})
		if err != nil {
			t.Fatal(err)
		}
		image, err := parseImage(signed)
		if err != nil {
			t.Fatal(err)
		}
		_, err = removeImageSource(context.Background(), image, outputSource{bytes.NewReader(nil), 0, int64(len(signed))})
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	})
}

func TestMachOStreamingFAT(t *testing.T) {
	for _, fat64 := range []bool{false, true} {
		name := "fat32"
		entry := 20
		if fat64 {
			name = "fat64"
			entry = 32
		}
		t.Run(name, func(t *testing.T) {
			c := &container{fat: true, fat64: fat64, order: be, data: make([]byte, 8+2*entry), slices: []slice{{alignment: 14}, {alignment: 16}}}
			// Retain reserved header fields while replacing offsets/sizes.
			c.data[len(c.data)-1] = 0x41
			parts := []outputSource{{reader: zeroSource{}, size: 1<<32 + 17}, byteOutput([]byte("tail"))}
			src, err := c.assembleSources(parts)
			if !fat64 {
				if !errors.Is(err, ErrUnsupported) {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			header := make([]byte, len(c.data))
			if _, err := src.reader.ReadAt(header, 0); err != nil {
				t.Fatal(err)
			}
			if be.Uint64(header[16:]) != 16384 || be.Uint64(header[24:]) != 1<<32+17 || header[len(header)-1] != 0x41 {
				t.Fatal(header)
			}
			offset := int64(be.Uint64(header[48:]))
			got := make([]byte, 4)
			if _, err := src.reader.ReadAt(got, offset); err != nil || string(got) != "tail" {
				t.Fatal(got, err)
			}
			if _, err := c.assembleSources([]outputSource{{reader: zeroSource{}, size: math.MaxInt64}, byteOutput(nil)}); !errors.Is(err, ErrFormat) {
				t.Fatal(err)
			}
		})
	}
}

func TestMachOStagingFailures(t *testing.T) {
	for _, mode := range []string{"cancel-before", "cancel-transfer", "read", "short", "changed-before", "changed-transfer", "close", "missing", "directory", "different"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "code")
			data := bytes.Repeat([]byte{0x63}, 2*transferBufferSize+1)
			if err := os.WriteFile(path, data, 0755); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			closer := operationCloser{f.Close}
			defer closer.Close()
			st, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fault := errors.New("staging fault")
			src := outputSource{reader: f, size: int64(len(data))}
			mutate := func() {
				if err := os.Truncate(path, int64(len(data)-1)); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "cancel-before":
				cancel()
			case "changed-before":
				mutate()
			case "close":
				closer.close = func() error { return errors.Join(f.Close(), fault) }
			case "missing":
				path = filepath.Join(dir, "missing")
			case "directory":
				path = dir
			case "different":
				path = filepath.Join(dir, "other")
				if err := os.WriteFile(path, data, 0755); err != nil {
					t.Fatal(err)
				}
			default:
				src.reader = transferReaderFunc(func(p []byte, at int64) (int, error) {
					switch mode {
					case "read":
						return 0, fault
					case "short":
						return 0, nil
					case "cancel-transfer":
						cancel()
					case "changed-transfer":
						if at == 0 {
							mutate()
						}
						copy(p, data[int(at):])
						return len(p), nil
					}
					return f.ReadAt(p, at)
				})
			}
			err = replaceSource(ctx, path, f, &closer, st, src, false)
			if err == nil {
				t.Fatal("committed despite failure")
			}
			if mode == "read" || mode == "close" {
				if !errors.Is(err, fault) {
					t.Fatal("lost I/O error", err)
				}
			}
			if mode == "cancel-before" || mode == "cancel-transfer" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
			after, err := os.Stat(filepath.Join(dir, "code"))
			if err != nil || !os.SameFile(st, after) {
				t.Fatal("source replaced", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "code" && entry.Name() != "other" {
					t.Fatal("temporary allocation leaked", entry.Name())
				}
			}
		})
	}
}
