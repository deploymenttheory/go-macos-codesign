package sideband

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestStripNativeOrderingAndFailure(t *testing.T) {
	names := []string{appledouble.ResourceForkName, appledouble.FinderInfoName}
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, state := range []string{"both", "empty", "missing", "query-denied", "remove-denied", "second-remove-denied", "cancel-after-first", "cancel-after-query", "inventory-denied"} {
			t.Run(platform+"/"+state, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var removed []string
				queries := 0
				err := stripNative(ctx, platform, func() ([]string, error) {
					if state == "inventory-denied" {
						return nil, syscall.EACCES
					}
					return names, nil
				}, func(name string) (int, bool, error) {
					queries++
					if state == "query-denied" {
						return 0, false, syscall.EPERM
					}
					if state == "cancel-after-query" {
						cancel()
					}
					if state == "empty" {
						return 0, true, nil
					}
					if state == "missing" {
						return 0, false, nil
					}
					return 32, true, nil
				}, func(name string) error {
					if state == "remove-denied" || state == "second-remove-denied" && name == names[1] {
						return syscall.EPERM
					}
					removed = append(removed, name)
					if state == "cancel-after-first" {
						cancel()
					}
					return nil
				})
				want := names
				var wantErr error
				switch state {
				case "empty", "missing":
					want = nil
				case "query-denied":
					want = nil
					if platform != "darwin" {
						wantErr = syscall.EPERM
					}
				case "remove-denied":
					want = nil
					wantErr = syscall.EPERM
				case "second-remove-denied":
					want = names[:1]
					wantErr = syscall.EPERM
				case "cancel-after-first":
					want = names[:1]
					wantErr = context.Canceled
				case "cancel-after-query":
					want = nil
					wantErr = context.Canceled
				case "inventory-denied":
					if platform == "linux" {
						want = nil
						wantErr = syscall.EACCES
					}
				}
				if !errors.Is(err, wantErr) || !reflect.DeepEqual(removed, want) {
					t.Fatal(err, wantErr, removed, want)
				}
				if state == "remove-denied" && queries != 1 {
					t.Fatal("queried FinderInfo after ResourceFork removal failure")
				}
			})
		}
	}
}

type mutableTestCarrier struct {
	*bytes.Reader
	removed []string
	fail    string
	cancel  context.CancelFunc
}

func (m *mutableTestCarrier) RemoveAttribute(ctx context.Context, name string) error {
	if name == m.fail {
		return io.ErrClosedPipe
	}
	var out bytes.Buffer
	if err := RewriteCarrier(ctx, m.Reader, &out, name); err != nil {
		return err
	}
	m.Reader = bytes.NewReader(out.Bytes())
	m.removed = append(m.removed, name)
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

func TestStripCarrierLifecycle(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "object")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	metadata := appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}, Attrs: []appledouble.Attr{{Name: "user.control", Value: []byte("keep")}}}
	for _, state := range []string{"both", "read-only", "malformed", "second-error", "cancel", "empty", "native-error"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := &mutableTestCarrier{Reader: carrier(t, metadata)}
			var input appledouble.Value = m
			file := f
			switch state {
			case "read-only":
				input = m.Reader
			case "malformed":
				input = bytes.NewReader([]byte("bad"))
			case "second-error":
				m.fail = appledouble.FinderInfoName
			case "cancel":
				m.cancel = cancel
			case "empty":
				input = carrier(t, appledouble.File{})
			case "native-error":
				file = nil
			}
			err := Strip(ctx, file, input)
			if (err == nil) != (state == "both" || state == "empty") {
				t.Fatal(err)
			}
			if state == "second-error" || state == "cancel" {
				got, e := inspectCarrier(context.Background(), m)
				if e != nil || got.ResourceFork || !got.FinderInfo {
					t.Fatal(got, e)
				}
			}
			if state == "both" {
				got, e := inspectCarrier(ctx, m)
				if e != nil || got != (Attributes{}) {
					t.Fatal(got, e)
				}
				if !reflect.DeepEqual(m.removed, []string{appledouble.ResourceForkName, appledouble.FinderInfoName}) {
					t.Fatal(m.removed)
				}
			}
		})
	}
	if err := Strip(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRewriteCarrierValues(t *testing.T) {
	metadata := appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}, Attrs: []appledouble.Attr{
		{Name: appledouble.ResourceForkName, Value: []byte("duplicate")}, {Name: appledouble.ResourceForkName},
		{Name: appledouble.FinderInfoName, Value: make([]byte, 32)}, {Name: "user.control", Value: []byte("keep")},
	}}
	for _, name := range []string{appledouble.ResourceForkName, appledouble.FinderInfoName} {
		var out bytes.Buffer
		if err := RewriteCarrier(context.Background(), carrier(t, metadata), &out, name); err != nil {
			t.Fatal(err)
		}
		got, err := appledouble.Decode(out.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if name == appledouble.ResourceForkName && (len(got.ResourceFork) != 0 || got.FinderInfo != metadata.FinderInfo) {
			t.Fatal(got)
		}
		if name == appledouble.FinderInfoName && (got.FinderInfo != [32]byte{} || !bytes.Equal(got.ResourceFork, metadata.ResourceFork)) {
			t.Fatal(got)
		}
		for _, a := range got.Attrs {
			if a.Name == name && len(a.Value) > 0 {
				t.Fatal("retained duplicate", a)
			}
		}
	}
	if err := RewriteCarrier(context.Background(), carrier(t, metadata), io.Discard, "user.control"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err := RewriteCarrier(context.Background(), bytes.NewReader(nil), io.Discard, appledouble.FinderInfoName); err == nil {
		t.Fatal("invalid input accepted")
	}
}

func TestHeldRemoval(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "object")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := hostdata.SetXattr(f, "user.codesign-test", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := removeAttribute(f, "user.codesign-test"); err != nil {
		t.Fatal(err)
	}
	if err := removeAttribute(f, "user.codesign-test"); err != nil {
		t.Fatal("disappeared attribute must be accepted", err)
	}
	if err := removeAttribute(nil, "user.codesign-test"); err == nil {
		t.Fatal("invalid held object")
	}
}
