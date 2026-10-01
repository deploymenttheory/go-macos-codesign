package codesign

import (
	"context"
	"errors"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBundleSidebandCarriers(t *testing.T) {
	ctx := context.Background()
	for _, location := range []string{".", "Contents/MacOS/hello", "Contents/Resources/message.txt", "Contents/Info.plist", "Contents/_CodeSignature/CodeResources"} {
		t.Run(location, func(t *testing.T) {
			app := testBundle(t)
			bundleFile(t, app, "Contents/Resources/message.txt", []byte("resource"))
			if err := Sign(ctx, app, SignOptions{}); err != nil {
				t.Fatal(err)
			}
			for _, both := range []bool{false, true} {
				metadata := appledouble.File{ResourceFork: []byte("fork")}
				if both {
					metadata.FinderInfo = [32]byte{1}
				}
				opts := VerifyOptions{StrictSideband: true, AppleDoubleFiles: map[string]appledouble.Value{location: sidebandCarrier(t, metadata)}}
				r, err := Verify(ctx, app, opts)
				checked := location != "Contents/Info.plist" && location != "Contents/_CodeSignature/CodeResources"
				if (err != nil) != checked || r == nil || r.Valid == checked {
					t.Fatal(r, err)
				}
				if checked {
					var detail *VerificationError
					if !errors.As(err, &detail) {
						t.Fatal(err)
					}
					want := 1
					if both && strings.Contains(location, "Resources/") {
						want = 2
					}
					if len(detail.AttachedData) != want {
						t.Fatal(detail.AttachedData)
					}
				}
				opts.IgnoreResources = true
				r, err = Verify(ctx, app, opts)
				checked = location == "." || strings.Contains(location, "MacOS/")
				if (err != nil) != checked || r == nil || r.Valid == checked {
					t.Fatal(r, err)
				}
			}
		})
	}
}

func TestBundleSidebandBindingValidation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "object")
	if err := os.WriteFile(path, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	value := sidebandCarrier(t, appledouble.File{ResourceFork: []byte("fork")})
	for _, bindings := range []map[string]appledouble.Value{{"": value}, {"object": nil}, {"absent": value}, {"object": value, path: value}} {
		if _, err := prepareBundleSideband(ctx, dir, VerifyOptions{StrictSideband: true, AppleDoubleFiles: bindings}); err == nil {
			t.Fatal(bindings)
		}
	}
	if _, err := prepareBundleSideband(ctx, dir, VerifyOptions{AppleDouble: value}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	tooMany := make(map[string]appledouble.Value)
	for i := 0; i <= maxBundleEntries; i++ {
		tooMany[strings.Repeat("x", i)] = value
	}
	if _, err := prepareBundleSideband(ctx, dir, VerifyOptions{StrictSideband: true, AppleDoubleFiles: tooMany}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := prepareBundleSideband(canceled, dir, VerifyOptions{StrictSideband: true, AppleDoubleFiles: map[string]appledouble.Value{"object": value}}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	inputs, err := prepareBundleSideband(ctx, dir, VerifyOptions{StrictSideband: true, AppleDoubleFiles: map[string]appledouble.Value{path: value}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	observed := inputs.observe(f)
	f.Close()
	if name, err := observed.first(ctx); name != appledouble.ResourceForkName || err != nil {
		t.Fatal(name, err)
	}
	if _, err := inputs.observe(f).first(ctx); err == nil {
		t.Fatal("closed file accepted")
	}
	if _, err := observed.first(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	data := fixture(t, "adhoc-arm64")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, path, VerifyOptions{StrictSideband: true, AppleDoubleFiles: map[string]appledouble.Value{path: value}}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestBundleSidebandDeferredErrors(t *testing.T) {
	ctx := context.Background()
	app := testBundle(t)
	bundleFile(t, app, "Contents/Resources/message.txt", []byte("resource"))
	if err := Sign(ctx, app, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	v := &sidebandIOFailure{}
	opts := VerifyOptions{StrictSideband: true, AppleDoubleFiles: map[string]appledouble.Value{"Contents/Resources/message.txt": v}}
	if _, err := Verify(ctx, app, opts); !errors.Is(err, io.ErrUnexpectedEOF) || v.reads == 0 {
		t.Fatal(v.reads, err)
	}
	v.reads = 0
	opts.IgnoreResources = true
	if _, err := Verify(ctx, app, opts); err != nil || v.reads != 0 {
		t.Fatal(v.reads, err)
	}
	opts.IgnoreResources = false
	main := filepath.Join(app, "Contents/MacOS/hello")
	data, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	data[4096] ^= 1
	if err := os.WriteFile(main, data, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, app, opts); err == nil || errors.Is(err, io.ErrUnexpectedEOF) || v.reads != 0 {
		t.Fatal(v.reads, err)
	}
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	b.startSideband(&bundleSidebandInputs{ctx: ctx})
	b.openSideband("missing")
	if _, err := b.sideband["missing"].first(ctx); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	opts.linkScope = &verificationLinkScope{bundle: b}
	if err := verifyResourceSideband(ctx, "absent", opts); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	b.sideband[b.base+"missing"] = &bundleSidebandObject{err: syscall.EACCES}
	if err := verifyResourceSideband(ctx, "missing", opts); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
}

func TestSidebandOpenErrors(t *testing.T) {
	for _, tc := range []struct {
		err     error
		message string
	}{{os.ErrNotExist, "No such file or directory"}, {syscall.ELOOP, "Too many levels of symbolic links"}, {syscall.ENOTDIR, "Not a directory"}, {os.ErrPermission, "Permission denied"}, {io.ErrUnexpectedEOF, ""}} {
		err := sidebandOpenError(tc.err)
		if !errors.Is(err, tc.err) {
			t.Fatal(err)
		}
		if tc.message != "" {
			var detail *VerificationError
			if !errors.As(err, &detail) || detail.Diagnostic != tc.message {
				t.Fatal(err)
			}
		}
	}
}

func TestBundleSidebandHardLinkBinding(t *testing.T) {
	ctx := context.Background()
	app := testBundle(t)
	bundleFile(t, app, "Contents/Resources/source", []byte("resource"))
	if err := os.Link(filepath.Join(app, "Contents/Resources/source"), filepath.Join(app, "Contents/Resources/alias")); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, app, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	opts := VerifyOptions{StrictSideband: true, AppleDoubleFiles: map[string]appledouble.Value{"Contents/Resources/source": sidebandCarrier(t, appledouble.File{ResourceFork: []byte("fork")})}}
	r, err := Verify(ctx, app, opts)
	var detail *VerificationError
	if r == nil || r.Valid || !errors.As(err, &detail) || len(detail.AttachedData) != 2 {
		t.Fatal(r, err, detail)
	}
	if !strings.Contains(detail.AttachedData[0], "alias") || !strings.Contains(detail.AttachedData[1], "source") {
		t.Fatal(detail.AttachedData)
	}
	opts.AppleDoubleFiles["Contents/Resources/alias"] = sidebandCarrier(t, appledouble.File{})
	if _, err := Verify(ctx, app, opts); !errors.Is(err, ErrUnsupported) {
		t.Fatal("ambiguous inode bindings accepted", err)
	}
}
