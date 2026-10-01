package sideband

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func carrier(t *testing.T, f appledouble.File) *bytes.Reader {
	t.Helper()
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

func missing(string) (int, bool, error) { return 0, false, nil }

func inspect(ctx context.Context, platform string, list func() ([]string, error), size func(string) (int, bool, error), carrier appledouble.Value) (Attributes, error) {
	return inspectPolicy(ctx, platform, list, size, carrier, false)
}

func TestNativePolicy(t *testing.T) {
	ctx := context.Background()
	names := []string{appledouble.ResourceForkName, appledouble.FinderInfoName}
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, state := range []string{"missing", "empty", "fork", "finder", "both"} {
			t.Run(platform+"/"+state, func(t *testing.T) {
				var queries []string
				listed := 0
				want := Attributes{ResourceFork: state == "fork" || state == "both", FinderInfo: state == "finder" || state == "both"}
				got, err := inspect(ctx, platform, func() ([]string, error) { listed++; return names, nil }, func(name string) (int, bool, error) {
					queries = append(queries, name)
					if name == names[0] && want.ResourceFork || name == names[1] && want.FinderInfo {
						return 32, true, nil
					}
					return 0, state == "empty", nil
				}, nil)
				if err != nil || got != want || !reflect.DeepEqual(queries, names) || listed != boolInt(platform == "linux") {
					t.Fatal(got, want, queries, listed, err)
				}
			})
		}
	}
	// Native Linux inventories do not project user.* into the Darwin namespace.
	for _, names := range [][]string{nil, {"user.com.apple.ResourceFork", "user.com.apple.FinderInfo"}, {"COM.APPLE.RESOURCEFORK"}} {
		got, err := inspect(ctx, "linux", func() ([]string, error) { return names, nil }, func(name string) (int, bool, error) {
			t.Fatalf("unexpected unnamespaced query: %s", name)
			return 0, false, nil
		}, nil)
		if err != nil || got != (Attributes{}) {
			t.Fatal(got, err)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestErrorsNeverBecomeAbsence(t *testing.T) {
	names := []string{appledouble.ResourceForkName, appledouble.FinderInfoName}
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, failure := range []error{syscall.EPERM, syscall.EACCES, syscall.EIO, hostdata.ErrXattrUnsupported, hostdata.ErrXattrChanged} {
			for _, failedName := range names {
				t.Run(platform+"/"+failure.Error()+"/"+failedName, func(t *testing.T) {
					got, err := inspect(context.Background(), platform, func() ([]string, error) { return names, nil }, func(name string) (int, bool, error) {
						if name == failedName {
							return 0, false, fmtWrapped(failure)
						}
						return 4, true, nil
					}, carrier(t, appledouble.File{}))
					if platform == "darwin" && errors.Is(failure, syscall.EPERM) {
						want := Attributes{ResourceFork: failedName != names[0], FinderInfo: failedName != names[1]}
						if err != nil || got != want {
							t.Fatal(got, err)
						}
					} else if !errors.Is(err, failure) || got != (Attributes{}) || !strings.Contains(err.Error(), failedName) {
						t.Fatal("partial result or lost failure", got, err)
					}
				})
			}
		}
	}
	for _, failure := range []error{syscall.EPERM, syscall.EACCES, hostdata.ErrXattrUnsupported, hostdata.ErrXattrListMalformed} {
		got, err := inspect(context.Background(), "linux", func() ([]string, error) { return names, failure }, missing, nil)
		if !errors.Is(err, failure) || got != (Attributes{}) {
			t.Fatal("partial inventory accepted", got, err)
		}
	}
}

func fmtWrapped(err error) error { return &os.PathError{Op: "fgetxattr", Path: "held-file", Err: err} }

func TestCancellation(t *testing.T) {
	for _, stage := range []string{"before", "list", "fork", "finder", "carrier"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before" {
				cancel()
			}
			var v appledouble.Value
			if stage == "carrier" {
				v = &cancelValue{carrier(t, appledouble.File{}), cancel}
			}
			got, err := inspect(ctx, "linux", func() ([]string, error) {
				if stage == "list" {
					cancel()
				}
				return []string{appledouble.ResourceForkName, appledouble.FinderInfoName}, nil
			}, func(name string) (int, bool, error) {
				if stage == "fork" && name == appledouble.ResourceForkName || stage == "finder" && name == appledouble.FinderInfoName {
					cancel()
				}
				return 1, true, nil
			}, v)
			if !errors.Is(err, context.Canceled) || got != (Attributes{}) {
				t.Fatal(got, err)
			}
		})
	}
}

type cancelValue struct {
	*bytes.Reader
	cancel context.CancelFunc
}

func (v *cancelValue) ReadAt(p []byte, off int64) (int, error) {
	v.cancel()
	return v.Reader.ReadAt(p, off)
}

func TestCarrierComposition(t *testing.T) {
	for _, tc := range []struct {
		name string
		file appledouble.File
		want Attributes
	}{
		{"empty", appledouble.File{}, Attributes{}},
		{"fork", appledouble.File{ResourceFork: []byte("fork")}, Attributes{ResourceFork: true}},
		{"finder", appledouble.File{FinderInfo: [32]byte{'T'}}, Attributes{FinderInfo: true}},
		{"both", appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{'T'}}, Attributes{true, true}},
		{"ordinary", appledouble.File{Attrs: []appledouble.Attr{{Name: "user.test", Value: []byte("value")}}}, Attributes{}},
		{"empty-record", appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ResourceForkName}}}, Attributes{}},
		{"duplicate-forks", appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ResourceForkName, Value: []byte("present")}, {Name: appledouble.ResourceForkName}}}, Attributes{ResourceFork: true}},
		{"explicit-finder-record", appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.FinderInfoName, Value: make([]byte, 32)}}}, Attributes{FinderInfo: true}},
		{"duplicate-finder", appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.FinderInfoName, Value: bytes.Repeat([]byte{1}, 32)}, {Name: appledouble.FinderInfoName, Value: make([]byte, 32)}}}, Attributes{FinderInfo: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, native := range []Attributes{{}, {true, false}, {false, true}, {true, true}} {
				got, err := inspect(context.Background(), "darwin", nil, func(name string) (int, bool, error) {
					present := name == appledouble.ResourceForkName && native.ResourceFork || name == appledouble.FinderInfoName && native.FinderInfo
					return boolInt(present), present, nil
				}, carrier(t, tc.file))
				want := Attributes{native.ResourceFork || tc.want.ResourceFork, native.FinderInfo || tc.want.FinderInfo}
				if err != nil || got != want {
					t.Fatal(native, got, want, err)
				}
			}
		})
	}
	a := Attributes{true, true}
	names := a.Names()
	if !reflect.DeepEqual(names, []string{appledouble.ResourceForkName, appledouble.FinderInfoName}) {
		t.Fatal(names)
	}
	names[0] = "changed"
	if a.Names()[0] != appledouble.ResourceForkName || (Attributes{}).Names() != nil {
		t.Fatal("mutable or nonempty empty result")
	}
}

func TestCarrierFailures(t *testing.T) {
	good := carrier(t, appledouble.File{ResourceFork: []byte("fork")})
	raw := make([]byte, good.Size())
	if _, err := good.ReadAt(raw, 0); err != nil {
		t.Fatal(err)
	}
	outside := bytes.Clone(raw)
	binary.BigEndian.PutUint32(outside[46:], uint32(len(raw)))
	for _, v := range []appledouble.Value{bytes.NewReader(nil), bytes.NewReader([]byte("not AppleDouble")), bytes.NewReader(raw[:81]), bytes.NewReader(outside), &failedValue{good.Size()}} {
		got, err := inspect(context.Background(), "darwin", nil, func(string) (int, bool, error) { return 4, true, nil }, v)
		if err == nil || got != (Attributes{}) || !strings.Contains(err.Error(), "AppleDouble") {
			t.Fatal("carrier failure hidden by native result", got, err)
		}
	}
}

type failedValue struct{ size int64 }

func (v *failedValue) Size() int64                     { return v.size }
func (*failedValue) ReadAt([]byte, int64) (int, error) { return 0, syscall.EIO }

// A synthetic sparse source proves that the full uint32 fork boundary is
// accepted without allocating or reading the entire fork. Header accesses are bounded
// independently of its declared size; no filesystem sparse-file support needed.
type sparseValue struct {
	header []byte
	size   int64
	read   int
}

func (v *sparseValue) Size() int64 { return v.size }
func (v *sparseValue) ReadAt(p []byte, off int64) (int, error) {
	v.read += len(p)
	clear(p)
	if off < int64(len(v.header)) {
		copy(p, v.header[off:])
	}
	return len(p), nil
}

func TestLargeCarrierIsBounded(t *testing.T) {
	r := carrier(t, appledouble.File{ResourceFork: []byte{1}})
	header := make([]byte, r.Size())
	if _, err := r.ReadAt(header, 0); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(header[46:], math.MaxUint32)
	value := &sparseValue{header: header, size: int64(binary.BigEndian.Uint32(header[42:])) + math.MaxUint32}
	got, err := inspectCarrier(context.Background(), value)
	if err != nil || got != (Attributes{ResourceFork: true}) || value.read > appledouble.MaxHeader {
		t.Fatal(got, err, value.read)
	}
	value.size--
	if _, err := inspectCarrier(context.Background(), value); err == nil {
		t.Fatal("truncated fork accepted")
	}
}

func TestHeldNativeObjectAndExplicitCarrier(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "object")
	if err := os.WriteFile(path, []byte("unchanged bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"clean", "fork", "both", "empty-carrier", "carrier-only"} {
		t.Run(state, func(t *testing.T) {
			nativeFork := state == "fork" || state == "both" || state == "empty-carrier"
			nativeFinder := state == "both" || state == "empty-carrier"
			for _, attr := range []struct {
				name string
				data []byte
			}{{appledouble.ResourceForkName, []byte("fork")}, {appledouble.FinderInfoName, bytes.Repeat([]byte{1}, 32)}} {
				name := attr.name
				if runtime.GOOS == "linux" {
					name = "user." + name
				}
				present := attr.name == appledouble.ResourceForkName && nativeFork || attr.name == appledouble.FinderInfoName && nativeFinder
				if present {
					err = hostdata.SetXattr(f, name, attr.data)
				} else {
					_, err = hostdata.RemoveXattr(f, name)
				}
				if err != nil {
					t.Fatal(name, err)
				}
			}
			var source appledouble.Value
			want := Attributes{nativeFork, nativeFinder}
			if runtime.GOOS == "linux" {
				want = Attributes{} // user.* is deliberately not remapped.
			}
			switch state {
			case "empty-carrier":
				source = carrier(t, appledouble.File{})
			case "carrier-only":
				source = carrier(t, appledouble.File{ResourceFork: []byte("foreign fork"), FinderInfo: [32]byte{1}})
				want = Attributes{true, true}
			}
			before := snapshotAttributes(t, f)
			got, err := Inspect(ctx, f, source)
			if err != nil || got != want {
				t.Fatal(got, want, err)
			}
			if after := snapshotAttributes(t, f); !reflect.DeepEqual(before, after) {
				t.Fatal("native attributes changed", before, after)
			}
			if pos, err := f.Seek(0, io.SeekCurrent); err != nil || pos != 3 {
				t.Fatal("caller offset changed", pos, err)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "unchanged bytes" {
				t.Fatal(string(data), err)
			}
		})
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := Inspect(ctx, f, nil); err == nil || got != (Attributes{}) {
		t.Fatal("closed object accepted", got, err)
	}
	if got, err := Inspect(ctx, nil, nil); err == nil || got != (Attributes{}) {
		t.Fatal("nil object accepted", got, err)
	}
}
