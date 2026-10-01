package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-macos-codesign/internal/sideband"
)

type signingCarrier struct {
	*bytes.Reader
	err error
}

func (m *signingCarrier) RemoveAttribute(ctx context.Context, name string) error {
	if m.err != nil {
		return m.err
	}
	var out bytes.Buffer
	if err := sideband.RewriteCarrier(ctx, m.Reader, &out, name); err != nil {
		return err
	}
	m.Reader = bytes.NewReader(out.Bytes())
	return nil
}

func TestSigningSidebandPreflight(t *testing.T) {
	ctx := context.Background()
	for _, state := range []string{"unsigned", "signed", "dryrun", "no-strict", "strip", "strip-error", "malformed-carrier", "read-only-carrier", "malformed-code"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tool")
			data := fixture(t, "unsigned-arm64")
			if state == "signed" {
				data = fixture(t, "adhoc-arm64")
			}
			if state == "malformed-code" {
				data = []byte("bad")
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			carrier := &signingCarrier{Reader: sidebandCarrier(t, appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}})}
			opts := SignOptions{AppleDouble: carrier, Identifier: "org.example.test"}
			switch state {
			case "strip", "dryrun", "strip-error", "read-only-carrier":
				opts.StripDisallowedXattrs = true
			case "no-strict":
				opts.NoStrict = true
			}
			if state == "dryrun" {
				opts.DryRun = true
			}
			if state == "strip-error" {
				carrier.err = os.ErrPermission
			}
			if state == "read-only-carrier" {
				opts.AppleDouble = carrier.Reader
			}
			if state == "malformed-carrier" {
				carrier.Reader = bytes.NewReader(nil)
			}
			err := Sign(ctx, path, opts)
			if (err == nil) != (state == "strip" || state == "dryrun" || state == "no-strict") {
				t.Fatal(err)
			}
			if state == "signed" && !errors.Is(err, ErrSigned) {
				t.Fatal(err)
			}
			if state == "unsigned" {
				var detail *VerificationError
				if !errors.As(err, &detail) || len(detail.AttachedData) != 1 {
					t.Fatal(err)
				}
			}
			got, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if (err != nil || opts.DryRun) && !bytes.Equal(got, data) {
				t.Fatal("failed or dry-run signing changed bytes")
			}
		})
	}
	if _, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), SignOptions{Identifier: "test", AppleDouble: sidebandCarrier(t, appledouble.File{})}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := SignBytes(canceled, nil, SignOptions{AppleDouble: sidebandCarrier(t, appledouble.File{})}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, fixture(t, "unsigned-arm64"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, path, SignOptions{AppleDoubleFiles: map[string]appledouble.Value{}}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestSigningBundleMetadataInputs(t *testing.T) {
	ctx := context.Background()
	for _, location := range []string{".", "Contents/MacOS/hello", "Contents/Resources/message.txt", "Contents/Info.plist"} {
		t.Run(location, func(t *testing.T) {
			app := testBundle(t)
			bundleFile(t, app, "Contents/Resources/message.txt", []byte("data"))
			carrier := &signingCarrier{Reader: sidebandCarrier(t, appledouble.File{FinderInfo: [32]byte{1}})}
			opts := SignOptions{AppleDoubleFiles: map[string]appledouble.Value{location: carrier}}
			err := Sign(ctx, app, opts)
			if (err != nil) != (location != "Contents/Info.plist") {
				t.Fatal(err)
			}
			opts.StripDisallowedXattrs, opts.Force = true, true
			if err := Sign(ctx, app, opts); err != nil {
				t.Fatal(err)
			}
		})
	}
	app := testBundle(t)
	if err := Sign(ctx, app, SignOptions{AppleDouble: sidebandCarrier(t, appledouble.File{})}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err := Sign(ctx, app, SignOptions{AppleDoubleFiles: map[string]appledouble.Value{"absent": sidebandCarrier(t, appledouble.File{})}}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if signingHasSignature([]byte("bad")) || signingHasSignature(fixture(t, "unsigned-arm64")) {
		t.Fatal("signature detection")
	}
	if err := signingNestedError("child", os.ErrPermission); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
}

func TestNestedSigningSelection(t *testing.T) {
	for _, name := range []string{"unsigned-arm64", "adhoc-arm64", "unsigned-universal", "adhoc-universal"} {
		data := fixture(t, name)
		want := name == "unsigned-arm64" || name == "unsigned-universal"
		if signingNeedsNested(data, false) != want || !signingNeedsNested(data, true) {
			t.Fatal(name)
		}
	}
	if !signingNeedsNested([]byte("bad"), false) || signingComplete(&Report{}) {
		t.Fatal("invalid input")
	}
	r, err := InspectBytes(fixture(t, "adhoc-universal"))
	if err != nil {
		t.Fatal(err)
	}
	r.Architectures[1].Signature = nil
	if signingComplete(r) {
		t.Fatal("a missing architecture must select nested signing")
	}
	r.Architectures = r.Architectures[:1]
	r.Architectures[0].Signature.Directories[0].Flags |= 0x20000
	if signingComplete(r) {
		t.Fatal("linker signatures must select nested signing")
	}
}
