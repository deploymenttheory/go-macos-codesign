package codesign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestSourceFixtureParity(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mode := range []string{"unsigned", "adhoc", "entitlements", "requirement", "runtime"} {
			name := mode + "-" + arch
			t.Run(name, func(t *testing.T) { sourceFixtureParity(t, fixture(t, name)) })
		}
	}
	for _, name := range []string{"native-adhoc-raw.dmg", "native-adhoc-zlib.dmg", "native-adhoc-lzfse.dmg", "native-p256-zlib.dmg", "native-rsa-zlib.dmg"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../testdata/dmg", name))
			if err != nil {
				t.Fatal(err)
			}
			sourceFixtureParity(t, data)
		})
	}
}
func sourceFixtureParity(t *testing.T, data []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "code")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	want, werr := InspectBytes(data)
	got, gerr := Inspect(context.Background(), path)
	if got != nil {
		got.Path = ""
	}
	if fmt.Sprint(werr) != fmt.Sprint(gerr) || !reflect.DeepEqual(want, got) {
		t.Fatal("inspection differs", werr, gerr)
	}
	for _, opts := range []VerifyOptions{{}, {NoStrict: true}, {Architecture: "missing"}} {
		want, werr = VerifyBytes(context.Background(), data, opts)
		got, gerr = Verify(context.Background(), path, opts)
		if got != nil {
			got.Path = ""
		}
		// Error wrapping may include held-file close/status checks; its diagnostic
		// and report must preserve the byte API's verification policy.
		if fmt.Sprint(werr) != fmt.Sprint(gerr) || !reflect.DeepEqual(want, got) {
			a, _ := json.Marshal(want)
			b, _ := json.Marshal(got)
			t.Fatalf("verification differs: %v / %v\n%s\n%s", werr, gerr, a, b)
		}
	}
}

func TestSourceReadFaults(t *testing.T) {
	fault := errors.New("range read fault")
	dmg := testDMG(t)
	signed, err := SignBytes(context.Background(), dmg, SignOptions{Identifier: "range.test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{{"thin", fixture(t, "adhoc-arm64")}, {"fat", fixture(t, "adhoc-universal")}, {"dmg", signed}} {
		for _, operation := range []string{"inspect", "strict", "verify"} {
			t.Run(tc.name+"/"+operation, func(t *testing.T) {
				run := func(fail int, cancelRead bool) (int, error) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					reads := 0
					source := codeSource{ctx: ctx, source: outputSource{size: int64(len(tc.data)), reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
						reads++
						if reads == fail {
							if cancelRead {
								cancel()
							}
							return 0, fault
						}
						return bytes.NewReader(tc.data).ReadAt(p, at)
					})}}
					var err error
					switch operation {
					case "inspect":
						_, err = source.inspect()
					case "strict":
						err = source.strict("", false)
					case "verify":
						_, err = verifyInput(ctx, VerifyOptions{}, tc.name == "dmg", source.inspect, source.digest, source.strict)
					}
					return reads, err
				}
				total, err := run(0, false)
				if err != nil || total == 0 {
					t.Fatal(total, err)
				}
				for i := 1; i <= total; i++ {
					for _, cancel := range []bool{false, true} {
						_, err := run(i, cancel)
						if !errors.Is(err, fault) || cancel && !errors.Is(err, context.Canceled) {
							t.Fatalf("read %d/%d: %v", i, total, err)
						}
					}
				}
			})
		}
	}
}

func TestSourceBoundsAndCancellation(t *testing.T) {
	data := make([]byte, 2*transferBufferSize+1)
	s := codeSource{context.Background(), byteOutput(data)}
	for _, operation := range []string{"read", "digest", "zero"} {
		t.Run(operation, func(t *testing.T) {
			var err error
			switch operation {
			case "read":
				_, err = s.read(uint64(len(data)), 1)
			case "digest":
				_, err = s.digest(2, uint64(len(data)), 1)
			case "zero":
				_, err = s.zero(uint64(len(data)), 1)
			}
			if !errors.Is(err, ErrFormat) {
				t.Fatal(err)
			}
		})
	}
	s.source.size = maxFileSize + 1
	if _, err := s.read(0, maxFileSize+1); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	s.source.size = int64(len(data))
	if zero, err := s.zero(0, uint64(len(data))); err != nil || !zero {
		t.Fatal(zero, err)
	}
	data[transferBufferSize] = 1
	if zero, err := s.zero(0, uint64(len(data))); err != nil || zero {
		t.Fatal(zero, err)
	}
	s.source = outputSource{reader: bytes.NewReader(nil), size: 4}
	if _, err := s.read(0, 4); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	for _, kind := range []string{"thin", "dmg"} {
		t.Run("cancel-"+kind, func(t *testing.T) {
			bytes := fixture(t, "adhoc-arm64")
			if kind == "dmg" {
				bytes = testDMG(t)
			}
			cancelEveryHashCheckpoint(t, func(ctx context.Context) error {
				s := codeSource{ctx, byteOutput(bytes)}
				_, err := s.inspect()
				return err
			})
		})
	}
}

func TestHeldSourceLifecycle(t *testing.T) {
	data := fixture(t, "adhoc-arm64")
	path := filepath.Join(t.TempDir(), "code")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"unchanged", "size", "mtime", "closed", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var held *os.File
			r, err := withCodeSource(ctx, path, func(s codeSource, f *os.File) (*Report, error) {
				held = f
				r, e := s.inspect()
				if e != nil {
					return r, e
				}
				r.Valid = true
				switch mode {
				case "size":
					e = os.Truncate(path, int64(len(data)+1))
				case "mtime":
					e = os.Chtimes(path, time.Unix(100, 0), time.Unix(100, 0))
				case "closed":
					e = f.Close()
				case "cancel":
					cancel()
				}
				return r, e
			})
			if mode == "unchanged" {
				if err != nil || !r.Valid {
					t.Fatal(r, err)
				}
			} else if err == nil || r == nil || r.Valid {
				t.Fatal(r, err)
			}
			// Stat on a closed Windows handle reports ERROR_INVALID_HANDLE.
			// Close has the portable ErrClosed contract, as in the writer tests.
			if e := held.Close(); !errors.Is(e, os.ErrClosed) {
				t.Fatal("held source leaked", e)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		if _, err := Inspect(context.Background(), path+"missing"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		f, e := os.Open(t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		if _, e = openCodeSource(context.Background(), f); !errors.Is(e, ErrUnsupported) {
			t.Fatal(e)
		}
	})
	t.Run("closed", func(t *testing.T) {
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
		_, statErr := f.Stat()
		var want *os.PathError
		if !errors.As(statErr, &want) {
			t.Fatal("closed-file stat did not return a path error", statErr)
		}
		_, e = openCodeSource(context.Background(), f)
		var got *os.PathError
		if !errors.As(e, &got) || got.Op != want.Op || got.Path != want.Path || !errors.Is(got.Err, want.Err) {
			t.Fatalf("closed-file stat error changed: got %v, want %v", e, statErr)
		}
	})
	t.Run("cancel-before", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, e := openCodeSource(ctx, nil); !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	})
}

func TestSourceCodeLimitPrecedence(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/research/large-source.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			ContentLength uint64 `json:"content_length"`
			Signature     []byte
		}
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(fmt.Sprint(tc.ContentLength), func(t *testing.T) {
			sig, err := ParseSignature(tc.Signature)
			if err != nil {
				t.Fatal(err)
			}
			if len(sig.Directories) != 1 || sig.Directories[0].CodeLimit != tc.ContentLength {
				t.Fatal("native code limit", sig.Directories)
			}
		})
	}
	sig, err := ParseSignature(corpus.Cases[len(corpus.Cases)-1].Signature)
	if err != nil {
		t.Fatal(err)
	}
	base := sig.Directories[0].Raw
	for _, tc := range []struct {
		name  string
		short uint32
		long  uint64
		want  uint64
	}{{"prefer64", 19, 1<<32 + 7, 1<<32 + 7}, {"fallback32", 19, 0, 19}, {"bothzero", 0, 0, 0}, {"shortzero", 0, 9, 9}} {
		t.Run(tc.name, func(t *testing.T) {
			raw := bytes.Clone(base)
			be.PutUint32(raw[32:], tc.short)
			be.PutUint64(raw[56:], tc.long)
			d, e := parseDirectory(raw)
			if e != nil || d.CodeLimit != tc.want {
				t.Fatal(d.CodeLimit, e)
			}
		})
	}
}

func TestSourceMalformedAndOffsetParity(t *testing.T) {
	for _, data := range [][]byte{nil, {1, 2, 3}, make([]byte, 512), append(bytes.Repeat([]byte{1}, 8), make([]byte, 512)...)} {
		source := codeSource{context.Background(), byteOutput(data)}
		_, want := InspectBytes(data)
		_, got := source.inspect()
		if fmt.Sprint(want) != fmt.Sprint(got) {
			t.Fatal(want, got)
		}
	}
	// FAT64 maps a real small signed slice above 4 GiB without allocating the gap.
	data := fixture(t, "adhoc-arm64")
	const offset = uint64(1<<32 + 65536)
	header := make([]byte, 40)
	be.PutUint32(header, 0xcafebabf)
	be.PutUint32(header[4:], 1)
	im, err := parseImage(data)
	if err != nil {
		t.Fatal(err)
	}
	be.PutUint32(header[8:], im.cpu)
	be.PutUint32(header[12:], im.subtype)
	be.PutUint64(header[16:], offset)
	be.PutUint64(header[24:], uint64(len(data)))
	be.PutUint32(header[32:], 16)
	read := 0
	source := codeSource{context.Background(), outputSource{size: int64(offset) + int64(len(data)), reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
		read += len(p)
		if at < int64(len(header)) {
			return bytes.NewReader(header).ReadAt(p, at)
		}
		if at >= int64(offset) {
			return bytes.NewReader(data).ReadAt(p, at-int64(offset))
		}
		t.Fatal("inspection read unused gap")
		return 0, io.ErrUnexpectedEOF
	})}}
	r, err := source.inspect()
	if err != nil || r.Architectures[0].Offset != offset {
		t.Fatal(r, err)
	}
	if read > len(data) {
		t.Fatal("unexpected payload reads", read)
	}
	r, err = verifyInput(context.Background(), VerifyOptions{NoStrict: true}, false, source.inspect, source.digest, source.strict)
	if err != nil || !r.Valid {
		t.Fatal(r, err)
	}
}

func TestSourceLargeMemoryBound(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/research/large-source.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			ContentLength              int64 `json:"content_length"`
			Prefix, Signature, Trailer []byte
		}
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	tc := corpus.Cases[len(corpus.Cases)-1]
	if tc.ContentLength != 1<<32+1 {
		t.Fatal("missing largest native control")
	}
	path := filepath.Join(t.TempDir(), "large.dmg")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	total := tc.ContentLength + int64(len(tc.Signature)+len(tc.Trailer))
	if err = f.Truncate(total); err != nil {
		f.Close()
		t.Fatal(err)
	}
	for _, p := range []struct {
		at   int64
		data []byte
	}{{0, tc.Prefix}, {tc.ContentLength, tc.Signature}, {tc.ContentLength + int64(len(tc.Signature)), tc.Trailer}} {
		if _, err = f.WriteAt(p.data, p.at); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	report, err := Verify(context.Background(), path, VerifyOptions{})
	runtime.ReadMemStats(&after)
	if err != nil || !report.Valid {
		t.Fatal(report, err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	// This small-metadata control must not allocate a payload-sized byte slice.
	// TotalAlloc is deliberately stronger than a post-GC live-heap sample here;
	// this does not claim to measure RSS or enforce the planned global budget.
	if allocated > 8<<20 {
		t.Fatalf("large-source allocation regression: %d bytes", allocated)
	}
	t.Logf("verified %d-byte content; Go allocated %d bytes", tc.ContentLength, allocated)
	runtime.ReadMemStats(&before)
	err = Sign(context.Background(), path, SignOptions{Identifier: "org.example.large-source", Force: true})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	allocated = after.TotalAlloc - before.TotalAlloc
	if allocated > 8<<20 {
		t.Fatalf("large signing allocation regression: %d bytes", allocated)
	}
	t.Logf("signed %d-byte content; Go allocated %d bytes", tc.ContentLength, allocated)
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tail := make([]byte, len(tc.Signature)+len(tc.Trailer))
	if _, err = f.ReadAt(tail, tc.ContentLength); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tail, append(bytes.Clone(tc.Signature), tc.Trailer...)) {
		t.Fatal("large signed bytes differ from native")
	}
}
