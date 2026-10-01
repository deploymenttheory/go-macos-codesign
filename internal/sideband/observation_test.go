package sideband

import (
	"context"
	"errors"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestHeldObservation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "object")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	o := Observe(ctx, f)
	f.Close()
	// Policy consumes the held-object observation after the descriptor is closed.
	for _, metadata := range []appledouble.File{{}, {ResourceFork: []byte("fork")}, {FinderInfo: [32]byte{1}}, {ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}}} {
		got, err := o.Inspect(ctx, carrier(t, metadata))
		want := Attributes{len(metadata.ResourceFork) > 0, metadata.FinderInfo != [32]byte{}}
		if err != nil || got != want {
			t.Fatal(got, want, err)
		}
		name, err := o.First(ctx, carrier(t, metadata))
		expected := ""
		if names := want.Names(); len(names) > 0 {
			expected = names[0]
		}
		if err != nil || name != expected {
			t.Fatal(name, expected, err)
		}
	}
	closed := Observe(ctx, f)
	if _, err := closed.Inspect(ctx, nil); err == nil {
		t.Fatal("closed file accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Observe(canceled, f).Inspect(canceled, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestObservationDefersFailures(t *testing.T) {
	ctx := context.Background()
	for _, platform := range []string{"darwin", "linux", "windows"} {
		o := &Observation{platform: platform, names: []string{appledouble.ResourceForkName, appledouble.FinderInfoName}, attrs: map[string]attributeObservation{
			appledouble.ResourceForkName: {size: 1, present: true}, appledouble.FinderInfoName: {err: syscall.EACCES},
		}}
		if name, err := o.First(ctx, nil); name != appledouble.ResourceForkName || err != nil {
			t.Fatal(platform, name, err)
		}
		if _, err := o.Inspect(ctx, nil); !errors.Is(err, syscall.EACCES) {
			t.Fatal(platform, err)
		}
		o.attrs[appledouble.ResourceForkName] = attributeObservation{err: syscall.EIO}
		if _, err := o.First(ctx, nil); !errors.Is(err, syscall.EIO) {
			t.Fatal(err)
		}
	}
	o := &Observation{platform: "linux", inventory: syscall.EIO}
	if _, err := o.First(ctx, nil); !errors.Is(err, syscall.EIO) {
		t.Fatal(err)
	}
}

func TestObservationInventoryAndQueryCapture(t *testing.T) {
	ctx := context.Background()
	for _, platform := range []string{"linux", "darwin", "windows"} {
		queries := 0
		o := observe(ctx, platform, func() ([]string, error) {
			return []string{appledouble.ResourceForkName, appledouble.FinderInfoName}, nil
		}, func(name string) (int, bool, error) {
			queries++
			if name == appledouble.ResourceForkName {
				return 7, true, nil
			}
			return 0, false, syscall.EACCES
		})
		if queries != 2 {
			t.Fatal(platform, queries)
		}
		if name, err := o.First(ctx, nil); name != appledouble.ResourceForkName || err != nil {
			t.Fatal(platform, name, err)
		}
		if _, err := o.Inspect(ctx, nil); !errors.Is(err, syscall.EACCES) {
			t.Fatal(platform, err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		o = observe(canceled, platform, func() ([]string, error) { return []string{appledouble.ResourceForkName}, nil }, func(string) (int, bool, error) { t.Fatal("query after cancellation"); return 0, false, nil })
		if !errors.Is(o.attrs[appledouble.ResourceForkName].err, context.Canceled) {
			t.Fatal(platform, o)
		}
	}
	// Neither failed inventory nor an unrelated Linux name permits a size query
	// for an unlisted canonical attribute. Failed inventory is retained as failure.
	for _, inventoryErr := range []error{nil, syscall.EIO} {
		o := observe(ctx, "linux", func() ([]string, error) { return []string{"user.com.apple.ResourceFork"}, inventoryErr }, func(string) (int, bool, error) { t.Fatal("unlisted attribute queried"); return 0, false, nil })
		got, err := o.Inspect(ctx, nil)
		if got != (Attributes{}) || !errors.Is(err, inventoryErr) {
			t.Fatal(got, err)
		}
	}
}
