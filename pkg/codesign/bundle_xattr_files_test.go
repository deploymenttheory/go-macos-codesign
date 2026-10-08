package codesign

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

func TestBundleXattrFileBoundaries(t *testing.T) {
	app := testBundle(t)
	for _, name := range []string{"ordinary", "._", "._Contents"} {
		bundleFile(t, app, name, []byte("not an attribute file"))
	}
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	for _, name := range []string{"ordinary", "._", "._Contents", "Contents"} {
		st, err := b.root.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		if valid, err := b.validXattrFile(t.Context(), name, fs.FileInfoToDirEntry(st)); valid || err != nil {
			t.Fatal("ordinary filesystem must not reinterpret neighbors", name, valid, err)
		}
	}
	st, err := b.root.Lstat("._Contents")
	if err != nil {
		t.Fatal(err)
	}
	entry := fs.FileInfoToDirEntry(st)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if valid, err := b.validXattrFile(ctx, "._Contents", entry); valid || !errors.Is(err, context.Canceled) {
		t.Fatal(valid, err)
	}
	if err := b.root.Close(); err != nil {
		t.Fatal(err)
	}
	if valid, err := b.validXattrFile(t.Context(), "._Contents", entry); valid || err != nil {
		t.Fatal(valid, err)
	}
}

func TestBundleNestedGenericClassification(t *testing.T) {
	app := testBundle(t)
	const name = "Contents/plain"
	bundleFile(t, app, name, []byte("ordinary nested code"))
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	b.sidebandBase = app
	data, err := b.holdCode(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	formatErr := malformed("Mach-O magic")
	err = b.nestedFormatError(t.Context(), name, data, formatErr)
	var detail *VerificationError
	if !errors.Is(err, ErrUnsigned) || !errors.As(err, &detail) || detail.Subcomponent != filepath.Join(app, filepath.FromSlash(name)) {
		t.Fatal("unsigned generic nested code must retain its native subcomponent diagnostic", err)
	}
	executable := testBundleCode(fixture(t, "unsigned-arm64"))
	if err := b.nestedFormatError(t.Context(), name, executable, formatErr); !errors.Is(err, formatErr) {
		t.Fatal("recognized Mach-O error was replaced", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := b.nestedFormatError(ctx, name, data, formatErr); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := b.sources[name].file.Close(); err != nil {
		t.Fatal(err)
	}
	// A held-file acquisition error is not evidence of an unsigned signature.
	if err := b.nestedFormatError(t.Context(), name, testBundleCode([]byte("plain")), formatErr); err == nil || errors.Is(err, ErrUnsigned) {
		t.Fatal(err)
	}
}

func TestBundleAttributeExemptionDoesNotHideMissingResources(t *testing.T) {
	files := map[string]any{"Resources/._data": resourceSeal(make([]byte, 32), false, false)}
	envelope := encodeBundleResources(map[string]any{}, files)
	if _, err := verifyBundleResources(envelope, map[string]any{"Resources/._data": xattrResourceExemption{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBundleResources(envelope, map[string]any{}); err == nil {
		t.Fatal("missing carrier was exempted without a present companion")
	}
	if _, err := verifyBundleResources(envelope, map[string]any{"Resources/._data": resourceSeal(make([]byte, 32), false, false), "Resources/added": resourceSeal(make([]byte, 32), false, false)}); err == nil {
		t.Fatal("ordinary added resource was exempted")
	}
}
