package sideband

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestFirstObservationOrder(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, tc := range []struct {
			name    string
			native  Attributes
			carrier appledouble.File
			queries int
			want    Attributes
		}{
			{"absent", Attributes{}, appledouble.File{}, 2, Attributes{}},
			{"native-fork", Attributes{true, true}, appledouble.File{}, 1, Attributes{ResourceFork: true}},
			{"native-finder", Attributes{FinderInfo: true}, appledouble.File{}, 2, Attributes{FinderInfo: true}},
			{"carrier-fork-before-native-finder", Attributes{FinderInfo: true}, appledouble.File{ResourceFork: []byte("fork")}, 1, Attributes{ResourceFork: true}},
			{"carrier-finder", Attributes{}, appledouble.File{FinderInfo: [32]byte{1}}, 2, Attributes{FinderInfo: true}},
			{"both-carrier", Attributes{}, appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}}, 1, Attributes{ResourceFork: true}},
		} {
			t.Run(platform+"/"+tc.name, func(t *testing.T) {
				var queried []string
				names := []string{appledouble.ResourceForkName, appledouble.FinderInfoName}
				got, err := inspectPolicy(context.Background(), platform, func() ([]string, error) { return names, nil }, func(name string) (int, bool, error) {
					queried = append(queried, name)
					present := name == names[0] && tc.native.ResourceFork || name == names[1] && tc.native.FinderInfo
					return boolInt(present), present, nil
				}, carrier(t, tc.carrier), true)
				if err != nil || got != tc.want || !reflect.DeepEqual(queried, names[:tc.queries]) {
					t.Fatal(got, tc.want, queried, err)
				}
			})
		}
	}
	// Once native ResourceFork has rejected a code object, later FinderInfo or
	// carrier failures cannot replace that first diagnostic.
	got, err := inspectPolicy(context.Background(), "darwin", nil, func(name string) (int, bool, error) {
		if name != appledouble.ResourceForkName {
			t.Fatal("queried FinderInfo after first rejection")
		}
		return 1, true, nil
	}, bytes.NewReader([]byte("malformed")), true)
	if err != nil || got != (Attributes{ResourceFork: true}) {
		t.Fatal(got, err)
	}
	for _, name := range []string{appledouble.ResourceForkName, appledouble.FinderInfoName} {
		_, err := inspectPolicy(context.Background(), "darwin", nil, func(n string) (int, bool, error) {
			if n == name {
				return 0, false, syscall.EACCES
			}
			return 0, false, nil
		}, nil, true)
		if !errors.Is(err, syscall.EACCES) {
			t.Fatal(err)
		}
	}
	if _, err := inspectPolicy(context.Background(), "darwin", nil, missing, bytes.NewReader(nil), true); err == nil {
		t.Fatal("needed malformed carrier ignored")
	}
}

func TestFirstCancellationAndHeldObject(t *testing.T) {
	for _, stage := range []string{"native", "carrier"} {
		ctx, cancel := context.WithCancel(context.Background())
		r := &cancelValue{carrier(t, appledouble.File{ResourceFork: []byte{1}}), cancel}
		got, err := inspectPolicy(ctx, "darwin", nil, func(string) (int, bool, error) {
			if stage == "native" {
				cancel()
				return 1, true, nil
			}
			return 0, false, nil
		}, r, true)
		cancel()
		if !errors.Is(err, context.Canceled) || got != (Attributes{}) {
			t.Fatal(stage, got, err)
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "first-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, tc := range []struct {
		file appledouble.File
		want string
	}{{appledouble.File{}, ""}, {appledouble.File{ResourceFork: []byte{1}}, appledouble.ResourceForkName}, {appledouble.File{FinderInfo: [32]byte{1}}, appledouble.FinderInfoName}} {
		got, err := First(context.Background(), f, carrier(t, tc.file))
		if err != nil || got != tc.want {
			t.Fatal(got, err)
		}
	}
	if _, err := First(context.Background(), nil, nil); err == nil {
		t.Fatal("invalid descriptor accepted")
	}
}
