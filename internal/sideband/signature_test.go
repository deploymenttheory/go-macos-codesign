package sideband

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestGenericSignatureProtocol(t *testing.T) {
	known := make([]string, len(signatureSlots))
	for i, n := range signatureSlots {
		known[i] = signaturePrefix + n
	}
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, failure := range []string{"success", "inventory", "known-first", "known-last", "flush", "unknown-first", "unknown-last", "cancel-before", "cancel-known", "cancel-list", "cancel-unknown"} {
			t.Run(platform+"/"+failure, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if failure == "cancel-before" {
					cancel()
				}
				names := append(slices.Clone(known), signaturePrefix+"A", signaturePrefix+"Z", "user.control", "com.apple.cs", "com.apple.csign")
				var removed []string
				lists := 0
				err := removeNativeSignature(ctx, platform, func() ([]string, error) {
					lists++
					if failure == "inventory" && lists == 1 || failure == "flush" && (platform != "linux" || lists == 2) {
						return nil, io.ErrClosedPipe
					}
					if failure == "cancel-list" && (platform != "linux" || lists == 2) {
						cancel()
					}
					return slices.Clone(names), nil
				}, func(name string) error {
					if failure == "known-first" && name == known[0] || failure == "known-last" && name == known[len(known)-1] || failure == "unknown-first" && name == signaturePrefix+"A" || failure == "unknown-last" && name == signaturePrefix+"Z" {
						return io.ErrClosedPipe
					}
					removed = append(removed, name)
					names = slices.DeleteFunc(names, func(n string) bool { return n == name })
					if failure == "cancel-known" && name == known[0] || failure == "cancel-unknown" && name == signaturePrefix+"A" {
						cancel()
					}
					return nil
				})
				want := append(slices.Clone(known), signaturePrefix+"A", signaturePrefix+"Z")
				var wantErr error
				switch failure {
				case "inventory":
					wantErr = io.ErrClosedPipe
					if platform == "linux" {
						want = nil
					} else {
						want = known
					}
				case "known-first":
					want = nil
					wantErr = io.ErrClosedPipe
				case "known-last":
					want = known[:len(known)-1]
					wantErr = io.ErrClosedPipe
				case "flush", "unknown-first":
					want = known
					wantErr = io.ErrClosedPipe
				case "unknown-last":
					want = want[:len(want)-1]
					wantErr = io.ErrClosedPipe
				case "cancel-before":
					want = nil
					wantErr = context.Canceled
				case "cancel-known":
					want = known[:1]
					wantErr = context.Canceled
				case "cancel-list":
					want = known
					wantErr = context.Canceled
				case "cancel-unknown":
					want = want[:len(want)-1]
					wantErr = context.Canceled
				}
				if !errors.Is(err, wantErr) || !slices.Equal(removed, want) {
					t.Fatalf("removed %v, err %v; want %v, %v", removed, err, want, wantErr)
				}
			})
		}
	}
}

func TestGenericSignatureNamespace(t *testing.T) {
	for _, fold := range []bool{false, true} {
		var got []string
		names := []string{"com.apple.cs.", "com.apple.cs.Unknown", "COM.APPLE.CS.UPPER", "com.apple.csign", "user.com.apple.cs.CodeDirectory"}
		err := removeSignatureAttributes(context.Background(), fold, func() ([]string, error) { return names, nil }, func(name string) error { got = append(got, name); return nil })
		want := names[:2]
		if fold {
			want = names[:3]
		}
		got = got[len(signatureSlots):]
		if err != nil || !slices.Equal(got, want) {
			t.Fatal(got, want, err)
		}
	}
	// A Linux-native user.* attribute is not a transported Apple signature.
	var calls []string
	if err := removeNativeSignature(context.Background(), "linux", func() ([]string, error) { return []string{"user.com.apple.cs.CodeDirectory"}, nil }, func(n string) error { calls = append(calls, n); return nil }); err != nil || len(calls) != 0 {
		t.Fatal(calls, err)
	}
}

func TestSignatureComponentFlushOrder(t *testing.T) {
	for _, failure := range []string{"none", "canonical", "components", "cancel-components", "list", "unknown"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var events []string
			err := removeSignatureAttributeSteps(ctx, false, func() ([]string, error) {
				events = append(events, "list")
				if failure == "list" {
					return nil, io.ErrClosedPipe
				}
				return []string{signaturePrefix + "Unknown", "user.control"}, nil
			}, func(name string) error {
				events = append(events, name)
				if failure == "canonical" || failure == "unknown" && strings.HasSuffix(name, ".Unknown") {
					return io.ErrClosedPipe
				}
				return nil
			}, func() error {
				events = append(events, "components")
				if failure == "components" {
					return io.ErrClosedPipe
				}
				if failure == "cancel-components" {
					cancel()
				}
				return nil
			})
			var want []string
			for _, slot := range signatureSlots {
				want = append(want, signaturePrefix+slot)
			}
			want = append(want, "components", "list", signaturePrefix+"Unknown")
			var expectedError error
			switch failure {
			case "canonical":
				want, expectedError = want[:1], io.ErrClosedPipe
			case "components":
				want, expectedError = want[:len(signatureSlots)+1], io.ErrClosedPipe
			case "cancel-components":
				want, expectedError = want[:len(signatureSlots)+1], context.Canceled
			case "list":
				want, expectedError = want[:len(signatureSlots)+2], io.ErrClosedPipe
			case "unknown":
				expectedError = io.ErrClosedPipe
			}
			if !slices.Equal(events, want) || !errors.Is(err, expectedError) {
				t.Fatal(events, want, err, expectedError)
			}
		})
	}
	names := SignatureComponents()
	names[0] = "caller-owned"
	if signatureSlots[0] != "CodeDirectory" {
		t.Fatal("caller changed canonical names")
	}
}

func TestSignatureCarrierComponentFlush(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "object")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m := &mutableTestCarrier{Reader: carrier(t, appledouble.File{Attrs: []appledouble.Attr{
		{Name: signaturePrefix + "CodeDirectory", Value: []byte("known")},
		{Name: signaturePrefix + "Unknown", Value: []byte("unknown")},
	}})}
	called := 0
	err = RemoveSignatureBeforeFlush(t.Context(), f, m, func() error {
		called++
		if !slices.Equal(m.removed, []string{signaturePrefix + "CodeDirectory"}) {
			t.Fatal("component removal did not occur between canonical and namespace removal", m.removed)
		}
		return io.ErrClosedPipe
	})
	if called != 1 || !errors.Is(err, io.ErrClosedPipe) || !slices.Equal(m.removed, []string{signaturePrefix + "CodeDirectory"}) {
		t.Fatal(called, err, m.removed)
	}
}

func TestGenericSignatureCarrier(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "object")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, state := range []string{"complete", "empty", "readonly", "unsigned-readonly", "invalid", "first-failure", "late-failure", "cancel"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			value := []byte("signature")
			if state == "empty" {
				value = nil
			}
			metadata := appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}, Attrs: []appledouble.Attr{{Name: "user.control", Value: []byte("keep")}}}
			if state != "unsigned-readonly" {
				for _, name := range []string{"CodeDirectory", "CodeSignature", "X", "Y"} {
					metadata.Attrs = append(metadata.Attrs, appledouble.Attr{Name: signaturePrefix + name, Value: value})
				}
			}
			m := &mutableTestCarrier{Reader: carrier(t, metadata)}
			var input appledouble.Value = m
			switch state {
			case "readonly", "unsigned-readonly":
				input = m.Reader
			case "invalid":
				input = bytes.NewReader(nil)
			case "first-failure":
				m.fail = signaturePrefix + "CodeDirectory"
			case "late-failure":
				m.fail = signaturePrefix + "Y"
			case "cancel":
				m.cancel = cancel
			}
			err := RemoveSignature(ctx, f, input)
			switch state {
			case "complete", "empty", "unsigned-readonly":
				if err != nil {
					t.Fatal(err)
				}
			case "readonly", "invalid":
				if err == nil {
					t.Fatal("accepted invalid carrier")
				}
			case "first-failure", "late-failure":
				if !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
			wire, e := io.ReadAll(io.NewSectionReader(m.Reader, 0, m.Size()))
			if e != nil {
				t.Fatal(e)
			}
			after, e := appledouble.Decode(wire)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(after.ResourceFork, metadata.ResourceFork) || after.FinderInfo != metadata.FinderInfo {
				t.Fatal("unrelated metadata changed")
			}
			expected := slices.Clone(metadata.Attrs)
			expected = slices.DeleteFunc(expected, func(a appledouble.Attr) bool { return slices.Contains(m.removed, a.Name) })
			if !slices.EqualFunc(after.Attrs, expected, func(a, b appledouble.Attr) bool { return a.Name == b.Name && bytes.Equal(a.Value, b.Value) }) {
				t.Fatalf("%#v; want %#v", after.Attrs, expected)
			}
			if state == "complete" || state == "empty" {
				for _, a := range after.Attrs {
					if strings.HasPrefix(a.Name, signaturePrefix) {
						t.Fatal("retained", a.Name)
					}
				}
			}
		})
	}
	if err := RemoveSignature(context.Background(), nil, nil); err == nil {
		t.Fatal("accepted nil object")
	}
}
