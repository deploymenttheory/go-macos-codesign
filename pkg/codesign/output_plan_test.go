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

func TestOutputPlanPatches(t *testing.T) {
	base := byteOutput([]byte("abcdefghi"))
	for _, tc := range []struct {
		name    string
		size    int64
		patches []outputSpan
		want    string
	}{
		{"empty", 0, nil, ""},
		{"truncate", 3, nil, "abc"},
		{"extend", 12, nil, "abcdefghi\x00\x00\x00"},
		{"replace", 9, []outputSpan{{0, byteOutput([]byte("A"))}, {3, byteOutput([]byte("DE"))}, {8, byteOutput([]byte("I"))}}, "AbcDEfghI"},
		{"extend-patch", 12, []outputSpan{{10, byteOutput([]byte("XY"))}}, "abcdefghi\x00XY"},
		{"empty-patch", 9, []outputSpan{{4, byteOutput(nil)}}, "abcdefghi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, err := patchedOutput(base, tc.size, tc.patches...)
			if err != nil {
				t.Fatal(err)
			}
			got, err := materializeOutput(context.Background(), src)
			if err != nil || string(got) != tc.want {
				t.Fatal(string(got), err)
			}
			for at := int64(0); at <= src.size; at++ {
				for n := 0; n <= len(tc.want)+1; n++ {
					b := make([]byte, n)
					read, err := src.reader.ReadAt(b, at)
					want := min(n, len(tc.want)-int(at))
					if read != want || !bytes.Equal(b[:read], []byte(tc.want)[at:int(at)+want]) || (err == io.EOF) != (want < n) {
						t.Fatal(at, n, read, err)
					}
				}
			}
			if _, err := src.reader.ReadAt(nil, -1); !errors.Is(err, ErrFormat) {
				t.Fatal(err)
			}
		})
	}
	t.Run("never-read-overwritten", func(t *testing.T) {
		src, err := patchedOutput(outputSource{transferReaderFunc(func([]byte, int64) (int, error) { t.Fatal("read replaced bytes"); return 0, nil }), 0, 8}, 8, outputSpan{0, byteOutput([]byte("replaced"))})
		if err != nil {
			t.Fatal(err)
		}
		b, err := materializeOutput(context.Background(), src)
		if err != nil || string(b) != "replaced" {
			t.Fatal(string(b), err)
		}
	})
	t.Run("above-4GiB", func(t *testing.T) {
		src, err := patchedOutput(outputSource{reader: zeroSource{}, size: 1<<32 + 3}, 1<<32+7, outputSpan{1<<32 - 1, byteOutput([]byte("TEST"))})
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 9)
		n, err := src.reader.ReadAt(b, 1<<32-2)
		if n != 9 || err != nil || !bytes.Equal(b, []byte("\x00TEST\x00\x00\x00\x00")) {
			t.Fatal(n, b, err)
		}
	})
}

func TestOutputPlanFailures(t *testing.T) {
	for i, src := range []outputSource{{size: -1}, {offset: -1}, {offset: math.MaxInt64, size: 1}, {size: 1}} {
		t.Run(fmt.Sprint("source-", i), func(t *testing.T) {
			p := new(outputPlan)
			if err := p.append(src); !errors.Is(err, ErrFormat) {
				t.Fatal(err)
			}
		})
	}
	t.Run("total-overflow", func(t *testing.T) {
		p := outputPlan{size: math.MaxInt64}
		if err := p.append(byteOutput([]byte{1})); !errors.Is(err, ErrFormat) {
			t.Fatal(err)
		}
	})
	for i, patches := range [][]outputSpan{
		{{-1, byteOutput(nil)}}, {{9, byteOutput(nil)}}, {{7, byteOutput([]byte("xx"))}}, {{2, outputSource{size: -1}}},
		{{2, byteOutput([]byte("abc"))}, {4, byteOutput([]byte("d"))}}, {{0, outputSource{size: 2}}},
	} {
		t.Run(fmt.Sprint("patch-", i), func(t *testing.T) {
			if _, err := patchedOutput(byteOutput([]byte("abcdefgh")), 8, patches...); !errors.Is(err, ErrFormat) {
				t.Fatal(err)
			}
		})
	}
	for i, src := range []outputSource{{size: -1}, {offset: -1}, {offset: math.MaxInt64, size: 1}, {size: 1}} {
		t.Run(fmt.Sprint("base-", i), func(t *testing.T) {
			if _, err := patchedOutput(src, 2); !errors.Is(err, ErrFormat) {
				t.Fatal(err)
			}
		})
	}
	t.Run("negative-size", func(t *testing.T) {
		if _, err := patchedOutput(byteOutput(nil), -1); !errors.Is(err, ErrFormat) {
			t.Fatal(err)
		}
	})
	fault := errors.New("source fault")
	for _, tc := range []struct {
		name           string
		n              int
		err, errorWant error
	}{
		{"negative", -1, fault, io.ErrUnexpectedEOF}, {"excess", 4, fault, io.ErrUnexpectedEOF}, {"short", 2, fault, io.ErrUnexpectedEOF},
		{"full-error", 3, fault, fault}, {"full-eof", 3, io.EOF, nil}, {"joined-eof", 3, errors.Join(io.EOF, fault), fault},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := new(outputPlan)
			if err := p.append(outputSource{transferReaderFunc(func(b []byte, _ int64) (int, error) { copy(b, "abc"); return tc.n, tc.err }), 0, 3}); err != nil {
				t.Fatal(err)
			}
			_, err := p.ReadAt(make([]byte, 3), 0)
			if !errors.Is(err, tc.errorWant) {
				t.Fatal(err)
			}
			if errors.Is(tc.err, fault) && !errors.Is(err, fault) {
				t.Fatal("lost source error", err)
			}
		})
	}
	for _, size := range []int64{-1, maxFileSize + 1} {
		t.Run(fmt.Sprint("materialize-", size), func(t *testing.T) {
			if _, err := materializeOutput(context.Background(), outputSource{size: size}); err == nil {
				t.Fatal("accepted invalid size")
			}
		})
	}
	t.Run("materialize-read-error", func(t *testing.T) {
		if _, err := materializeOutput(context.Background(), outputSource{bytes.NewReader(nil), 0, 1}); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	})
}

func TestStreamingCodePages(t *testing.T) {
	data := bytes.Repeat([]byte("aBCdEfGh"), 40001)
	for _, page := range []uint32{1, 16, 4096, 16384, 65536, 131072, 1 << 30} {
		for _, size := range []int{0, 1, len(data) - 1, len(data)} {
			t.Run(fmt.Sprintf("%d-%d", page, size), func(t *testing.T) {
				sums := make([]byte, ((size+int(page)-1)/int(page))*32)
				if err := hashCodePages(context.Background(), byteOutput(data[:size]), page, sums); err != nil {
					t.Fatal(err)
				}
				for at, i := 0, 0; at < size; at, i = at+int(page), i+1 {
					h := sha256.Sum256(data[at:min(at+int(page), size)])
					if !bytes.Equal(h[:], sums[i*32:(i+1)*32]) {
						t.Fatal("page", i)
					}
				}
			})
		}
	}
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := hashCodePages(ctx, byteOutput(data), 4096, make([]byte, 32)); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}
