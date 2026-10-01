package codesign

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type removalReader struct {
	read func([]byte, int64) (int, error)
}

func (r removalReader) ReadAt(p []byte, off int64) (int, error) { return r.read(p, off) }

func TestGenericRemovalClassification(t *testing.T) {
	ctx := context.Background()
	for _, order := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		for _, magic := range []uint32{0xfeedface, 0xfeedfacf} {
			for kind := uint32(0); kind <= 12; kind++ {
				b := make([]byte, 28)
				order.PutUint32(b, magic)
				order.PutUint32(b[12:], kind)
				got, err := genericRemovalReader(ctx, bytes.NewReader(b), int64(len(b)))
				want := kind != 2 && kind != 5 && kind != 6 && kind != 7 && kind != 8 && kind != 11
				if err != nil || got != want {
					t.Fatal(order, magic, kind, got, err)
				}
			}
		}
	}
	for _, name := range []string{"adhoc-arm64", "adhoc-x86_64", "adhoc-universal"} {
		b := fixture(t, name)
		got, err := genericRemovalReader(ctx, bytes.NewReader(b), int64(len(b)))
		if err != nil || got {
			t.Fatal(name, got, err)
		}
	}
	for n := 0; n < 28; n++ {
		b := fixture(t, "adhoc-arm64")[:n]
		got, err := genericRemovalReader(ctx, bytes.NewReader(b), int64(n))
		if err != nil || !got {
			t.Fatal(n, got, err)
		}
	}
	for _, magic := range []uint32{0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca} {
		b := make([]byte, 64)
		be.PutUint32(b, magic)
		be.PutUint32(b[16:], 32)
		copy(b[32:], fixture(t, "adhoc-arm64")[:28])
		got, err := genericRemovalReader(ctx, bytes.NewReader(b), 64)
		if err != nil || got {
			t.Fatal(magic, got, err)
		}
	}
	// A cyclic or out-of-range fat probe exhausts its finite budget as generic.
	for _, offset := range []uint32{0, 999} {
		b := make([]byte, 28)
		be.PutUint32(b, 0xcafebabe)
		be.PutUint32(b[16:], offset)
		got, err := genericRemovalReader(ctx, bytes.NewReader(b), 28)
		if err != nil || !got {
			t.Fatal(offset, got, err)
		}
	}
	for _, kind := range []string{"encrypted-first", "encrypted-second", "dyld", "dmg", "dmg-version", "dmg-too-short"} {
		b := make([]byte, 520)
		switch kind {
		case "encrypted-first":
			copy(b, "encr")
			be.PutUint32(b[8:], 2)
		case "encrypted-second":
			copy(b[4:], "cdsa")
			be.PutUint32(b[8:], 2)
		case "dyld":
			copy(b, "dyld_v1")
		default:
			copy(b[8:], "koly")
			be.PutUint32(b[12:], 4)
			if kind == "dmg-version" {
				be.PutUint32(b[12:], 3)
			}
			if kind == "dmg-too-short" {
				b = b[8:]
			}
		}
		got, err := genericRemovalReader(ctx, bytes.NewReader(b), int64(len(b)))
		want := kind == "dmg-version" || kind == "dmg-too-short"
		if got != want || (!want && !errors.Is(err, ErrUnsupported)) || (want && err != nil) {
			t.Fatal(kind, got, err)
		}
	}
}

func TestGenericRemovalReadFailures(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		calls := 0
		r := removalReader{func(p []byte, _ int64) (int, error) {
			calls++
			if calls == failAt {
				return 0, io.ErrClosedPipe
			}
			clear(p)
			return len(p), nil
		}}
		if _, err := genericRemovalReader(context.Background(), r, 1024); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(failAt, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := genericRemovalReader(ctx, bytes.NewReader(nil), 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	r := removalReader{func(p []byte, _ int64) (int, error) { clear(p); cancel(); return len(p), nil }}
	if _, err := genericRemovalReader(ctx, r, 1024); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := genericRemovalCandidate(context.Background(), f); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	f.Close()
	if _, err := genericRemovalCandidate(context.Background(), f); err == nil {
		t.Fatal("closed classifier")
	}
}

func TestGenericRemovalWritableIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	open := func() (*os.File, error) { return os.OpenFile(path, os.O_RDWR, 0) }
	if err := removeGenericSignature(ctx, f, open, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := removeGenericSignature(context.Background(), f, func() (*os.File, error) { return nil, io.ErrClosedPipe }, nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	other, err := os.Create(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatal(err)
	}
	if err := removeGenericSignature(context.Background(), f, func() (*os.File, error) { return other, nil }, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	closed, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if err := removeGenericSignature(context.Background(), f, func() (*os.File, error) { return closed, nil }, nil); err == nil {
		t.Fatal("closed writer")
	}
	if err := removeGenericSignature(context.Background(), closed, open, nil); err == nil {
		t.Fatal("closed source")
	}
}

func TestRemoveMetadataOptions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(path, []byte("script"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Remove(ctx, path, RemoveOptions{AppleDoubleFiles: map[string]appledouble.Value{}}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	m := &signingCarrier{Reader: sidebandCarrier(t, appledouble.File{Attrs: []appledouble.Attr{{Name: "com.apple.cs.Unknown", Value: []byte("signature")}}})}
	if err := Remove(ctx, path, RemoveOptions{AppleDouble: m}); err != nil {
		t.Fatal(err)
	}
	if string(readTestFile(t, path)) != "script" {
		t.Fatal("data changed")
	}
	app := testBundle(t)
	if err := Remove(ctx, app, RemoveOptions{AppleDouble: m}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err := Remove(ctx, app, RemoveOptions{AppleDoubleFiles: map[string]appledouble.Value{"missing": m}}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
