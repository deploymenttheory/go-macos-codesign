package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

func hashPattern(p []byte, offset int64) {
	for i := range p {
		x := uint64(offset) + uint64(i)
		p[i] = byte((x^x>>17^x>>32)*29 + 7)
	}
}

func TestIncrementalHashNativeCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/research/hash-streams.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Schema  int               `json:"schema"`
		Sources map[string]string `json:"source_sha256"`
		Cases   []struct {
			Kind   uint8  `json:"kind"`
			Offset int64  `json:"offset"`
			Length int64  `json:"length"`
			Digest string `json:"digest"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.Schema != 1 || len(capture.Cases) != 156 {
		t.Fatal("incomplete native digest corpus")
	}
	for _, path := range []string{"scripts/oracles/hash-streams.c", "scripts/probe-hash-streams.go"} {
		data, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != capture.Sources[path] {
			t.Fatal("stale oracle", path)
		}
	}
	expected := map[string]bool{}
	for kind := 1; kind <= 4; kind++ {
		for _, offset := range []int64{0, 1<<32 - 1, 1<<32 + 1} {
			for _, length := range []int{0, 1, 63, 64, 65, 4095, 4096, 4097, 65535, 65536, 65537, 131072, 131089} {
				expected[fmt.Sprintf("%d/%d/%d", kind, offset, length)] = true
			}
		}
	}
	for _, tc := range capture.Cases {
		name := fmt.Sprintf("%d/%d/%d", tc.Kind, tc.Offset, tc.Length)
		if !expected[name] {
			t.Fatal("unexpected or duplicate case", name)
		}
		delete(expected, name)
		t.Run(name, func(t *testing.T) {
			var read int64
			source := outputSource{offset: tc.Offset, size: tc.Length, reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
				if at != tc.Offset+read || len(p) > transferBufferSize {
					t.Fatal("unbounded or narrowed read", at, len(p))
				}
				hashPattern(p, at)
				read += int64(len(p))
				return len(p), nil
			})}
			got, err := digestSource(context.Background(), tc.Kind, source)
			if err != nil || hex.EncodeToString(got) != tc.Digest || read != tc.Length {
				t.Fatal("ReaderAt digest differs from CommonCrypto", err)
			}
			data := make([]byte, int(tc.Length))
			hashPattern(data, tc.Offset)
			got, err = digestContext(context.Background(), tc.Kind, data)
			if err != nil || hex.EncodeToString(got) != tc.Digest {
				t.Fatal("memory digest differs from CommonCrypto", err)
			}
		})
	}
	if len(expected) != 0 {
		t.Fatal("missing native cases")
	}
}

func TestIncrementalHashFaults(t *testing.T) {
	fault := errors.New("read fault")
	for _, tc := range []struct {
		name string
		src  outputSource
		want error
	}{
		{"negative-offset", outputSource{offset: -1}, ErrFormat},
		{"overflow", outputSource{offset: math.MaxInt64, size: 1}, ErrFormat},
		{"short", outputSource{reader: bytes.NewReader([]byte{1}), size: 2}, io.ErrUnexpectedEOF},
		{"read-error", outputSource{reader: transferReaderFunc(func(p []byte, _ int64) (int, error) { return len(p), errors.Join(io.EOF, fault) }), size: 2}, fault},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum, err := digestSource(context.Background(), 2, tc.src)
			if sum != nil || !errors.Is(err, tc.want) {
				t.Fatal(sum, err)
			}
		})
	}
	for _, size := range []int{1, transferBufferSize + 1} {
		t.Run(fmt.Sprintf("unsupported-%d", size), func(t *testing.T) {
			sum, err := digestContext(context.Background(), 255, make([]byte, size))
			if sum != nil || !errors.Is(err, ErrUnsupported) {
				t.Fatal(sum, err)
			}
		})
	}
	t.Run("cancel-read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		reads := 0
		source := outputSource{size: 2 * transferBufferSize, reader: transferReaderFunc(func(p []byte, _ int64) (int, error) { reads++; cancel(); return len(p), fault })}
		sum, err := digestSource(ctx, 2, source)
		if sum != nil || reads != 1 || !errors.Is(err, context.Canceled) || !errors.Is(err, fault) {
			t.Fatal(sum, reads, err)
		}
	})
}

type hashingReaderFunc func([]byte) (int, error)

func (f hashingReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestResourceHashStreams(t *testing.T) {
	for _, size := range []int{0, 1, transferBufferSize - 1, transferBufferSize, transferBufferSize + 1, 3*transferBufferSize + 17} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := make([]byte, size)
			hashPattern(data, 1<<32+1)
			reader := bytes.NewReader(data)
			var read int
			h1, h2, n, err := resourceDigests(context.Background(), hashingReaderFunc(func(p []byte) (int, error) {
				if len(p) > transferBufferSize {
					t.Fatal("unbounded read")
				}
				n, err := reader.Read(p)
				read += n
				return n, err
			}), int64(size))
			want1, _ := digest(1, data)
			want2, _ := digest(2, data)
			if err != nil || n != int64(size) || read != size || !bytes.Equal(h1, want1) || !bytes.Equal(h2, want2) {
				t.Fatal(n, read, err)
			}
		})
	}
	for _, limit := range []int64{-1, 0, 1, math.MaxInt64} {
		t.Run(fmt.Sprintf("budget-%d", limit), func(t *testing.T) {
			h1, h2, _, err := resourceDigests(context.Background(), bytes.NewReader([]byte{1, 2}), limit)
			want := ErrUnsupported
			if limit == 0 || limit == 1 {
				want = ErrInvalid // Growth is a changed source, not a payload-size ceiling.
			}
			if h1 != nil || h2 != nil || !errors.Is(err, want) {
				t.Fatal(h1, h2, err)
			}
		})
	}
	for _, mode := range []string{"fault", "cancel", "cancel-and-fault"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fault := errors.New("resource read fault")
			reads := 0
			h1, h2, _, err := resourceDigests(ctx, hashingReaderFunc(func(p []byte) (int, error) {
				reads++
				if mode != "fault" {
					cancel()
				}
				if mode != "cancel" {
					return 1, fault
				}
				return 1, nil
			}), 10)
			if h1 != nil || h2 != nil || reads != 1 || mode != "fault" && !errors.Is(err, context.Canceled) || mode != "cancel" && !errors.Is(err, fault) {
				t.Fatal(h1, h2, reads, err)
			}
		})
	}
}

// Exercise cancellation at every context checkpoint of a successful operation.
// No sleeps or production test hooks; Done and Err remain coherent on cancel.
func cancelEveryHashCheckpoint(t *testing.T, operation func(context.Context) error) {
	t.Helper()
	run := func(at int) (int, error) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		checks := 0
		observed := &observedCancelContext{Context: ctx, cancel: cancel, observe: func() bool { checks++; return checks == at }}
		err := operation(observed)
		return checks, err
	}
	total, err := run(0)
	if err != nil || total == 0 {
		t.Fatal("control", total, err)
	}
	for at := 1; at <= total; at++ {
		_, err = run(at)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("checkpoint %d/%d: %v", at, total, err)
		}
	}
}

func TestHashCancellationIntegration(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/removal/unsigned-arm64.macho")
	if err != nil {
		t.Fatal(err)
	}
	var dmg bytes.Buffer
	content := make([]byte, 3*transferBufferSize)
	hashPattern(content, 0)
	if err = disk.EncodeUDIF(&dmg, []disk.SourceBlock{{Name: "stream", Data: content, SectorCount: uint64(len(content) / 512)}}, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
		opts SignOptions
	}{
		{"macho", raw, SignOptions{Identifier: "stream.test", InfoPlist: content, Resources: content}},
		{"dmg-whole", dmg.Bytes(), SignOptions{Identifier: "stream.test"}},
		{"dmg-pages", dmg.Bytes(), SignOptions{Identifier: "stream.test", PageSize: 4096}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := bytes.Clone(tc.data)
			signed, err := SignBytes(context.Background(), tc.data, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Run("sign", func(t *testing.T) {
				cancelEveryHashCheckpoint(t, func(ctx context.Context) error {
					out, err := SignBytes(ctx, tc.data, tc.opts)
					if err != nil && out != nil {
						t.Fatal("failed signing exposed partial bytes")
					}
					return err
				})
			})
			t.Run("verify", func(t *testing.T) {
				cancelEveryHashCheckpoint(t, func(ctx context.Context) error {
					r, err := VerifyBytes(ctx, signed, VerifyOptions{InfoPlist: tc.opts.InfoPlist, Resources: tc.opts.Resources})
					if err != nil && r != nil && r.Valid {
						t.Fatal("cancelled verification marked valid")
					}
					return err
				})
			})
			if !bytes.Equal(tc.data, before) {
				t.Fatal("input changed")
			}
		})
	}
	t.Run("resource", func(t *testing.T) {
		cancelEveryHashCheckpoint(t, func(ctx context.Context) error {
			_, _, _, err := resourceDigests(ctx, bytes.NewReader(content), int64(len(content)))
			return err
		})
	})
	t.Run("small", func(t *testing.T) {
		cancelEveryHashCheckpoint(t, func(ctx context.Context) error { _, err := digestContext(ctx, 2, []byte{1}); return err })
	})
}

func TestBundleResourceHashCancellation(t *testing.T) {
	app := testBundle(t)
	data := make([]byte, 3*transferBufferSize+17)
	hashPattern(data, 0)
	bundleFile(t, app, "Contents/Resources/stream", data)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	cancelEveryHashCheckpoint(t, func(ctx context.Context) error { _, _, err := b.scan(ctx); return err })
	got, err := os.ReadFile(filepath.Join(app, "Contents/Resources/stream"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("cancelled scan modified resource", err)
	}
	if _, err = os.Stat(filepath.Join(app, "Contents/_CodeSignature")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("scan published a signature", err)
	}
}
