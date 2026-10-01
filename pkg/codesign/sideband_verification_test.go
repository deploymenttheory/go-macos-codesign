package codesign

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func sidebandCarrier(t *testing.T, metadata appledouble.File) *bytes.Reader {
	t.Helper()
	encoded, err := metadata.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(encoded)
}

func TestSidebandVerificationObjects(t *testing.T) {
	ctx := context.Background()
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		path := filepath.Join(t.TempDir(), "tool")
		data := fixture(t, "adhoc-"+arch)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		for _, metadata := range []appledouble.File{{}, {ResourceFork: []byte("fork")}, {FinderInfo: [32]byte{1}}, {ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}}} {
			for _, selection := range []string{"", "arm64", "x86_64"} {
				opts := VerifyOptions{StrictSideband: true, AppleDouble: sidebandCarrier(t, metadata), Architecture: selection}
				r, err := Verify(ctx, path, opts)
				if arch != "universal" && selection != "" && selection != arch {
					if err == nil || !strings.Contains(err.Error(), "not present") {
						t.Fatal(r, err)
					}
					continue
				}
				prohibited := len(metadata.ResourceFork) != 0 || metadata.FinderInfo != [32]byte{}
				if (err != nil) != prohibited || r == nil || r.Valid == prohibited {
					t.Fatal(arch, selection, r, err)
				}
				if prohibited {
					var detail *VerificationError
					if !errors.Is(err, ErrInvalid) || !errors.As(err, &detail) || detail.Architecture != "" || len(detail.AttachedData) != 1 {
						t.Fatal(err, detail)
					}
					name := appledouble.ResourceForkName
					if len(metadata.ResourceFork) == 0 {
						name = appledouble.FinderInfoName
					}
					if !strings.Contains(detail.AttachedData[0], name) || !strings.HasSuffix(detail.AttachedData[0], r.Path) {
						t.Fatal(detail.AttachedData)
					}
				}
			}
		}
	}
}

func TestSidebandOptionsAndErrorOrder(t *testing.T) {
	ctx := context.Background()
	data := fixture(t, "adhoc-arm64")
	if _, err := VerifyBytes(ctx, data, VerifyOptions{StrictSideband: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("byte-only Mach-O claimed metadata verification", err)
	}
	if _, err := VerifyBytes(ctx, data, VerifyOptions{StrictSideband: true, NoStrict: true}); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []VerifyOptions{{AppleDouble: bytes.NewReader(nil)}, {StrictSideband: true, NoStrict: true, AppleDouble: bytes.NewReader(nil)}} {
		if _, err := VerifyBytes(ctx, data, opts); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Verify(canceled, "absent", VerifyOptions{StrictSideband: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tool")
	for _, state := range []string{"clean", "corrupt", "trailing", "unsigned"} {
		data := bytes.Clone(data)
		switch state {
		case "corrupt":
			data[4096] ^= 1
		case "trailing":
			data = append(data, 0, 0, 0, 0)
		case "unsigned":
			data = fixture(t, "unsigned-arm64")
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		v := &sidebandIOFailure{}
		r, err := Verify(ctx, path, VerifyOptions{StrictSideband: true, AppleDouble: v})
		if r == nil || r.Valid || err == nil {
			t.Fatal(state, r, err)
		}
		if state == "corrupt" || state == "unsigned" {
			if v.reads != 0 || errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal("metadata read before integrity failure", state, v.reads, err)
			}
		} else if v.reads == 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal("metadata did not precede layout validation", state, v.reads, err)
		}
	}
	app := testBundle(t)
	if err := Sign(ctx, app, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if report, err := Verify(ctx, app, VerifyOptions{StrictSideband: true}); err != nil || report == nil || !report.Valid {
		t.Fatal("clean bundle sideband verification", report, err)
	}
	if _, err := Verify(ctx, app, VerifyOptions{StrictSideband: true, NoStrict: true}); err != nil {
		t.Fatal(err)
	}
	dmg, err := os.ReadFile(filepath.Join("..", "..", "testdata", "dmg", "native-adhoc-raw.dmg"))
	if err != nil {
		t.Fatal(err)
	}
	v := &sidebandIOFailure{}
	if _, err := VerifyBytes(ctx, dmg, VerifyOptions{StrictSideband: true, AppleDouble: v}); err != nil || v.reads != 0 {
		t.Fatal("UDIF inherited Mach-O sideband restriction", v.reads, err)
	}
}

type sidebandIOFailure struct{ reads int }

func (*sidebandIOFailure) Size() int64 { return 4096 }
func (v *sidebandIOFailure) ReadAt([]byte, int64) (int, error) {
	v.reads++
	return 0, io.ErrUnexpectedEOF
}

func TestSidebandHeldIdentity(t *testing.T) {
	// The SDK read-only metadata opener supports delete-sharing on Windows.
	// After a rename, the original spelling is deliberately absent: reopening
	// File.Name would fail on every host. No OS skips or raw bindings are needed.
	dir := t.TempDir()
	path := filepath.Join(dir, "original")
	if err := os.WriteFile(path, []byte("held object"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := hostdata.OpenMetadataFileRead(root, "original")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(path, filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	opts := VerifyOptions{StrictSideband: true, sidebandFile: f, sidebandPath: path}
	if err := verifySideband(context.Background(), opts); err != nil {
		t.Fatal("held metadata inspection reopened the stale name", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifySideband(context.Background(), opts); err == nil {
		t.Fatal("closed descriptor treated as no metadata")
	}
}

func TestSidebandDoesNotBypassCertificateTrust(t *testing.T) {
	ctx := context.Background()
	id := testIdentity(t, "rsa")
	data, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), SignOptions{Identity: id, Identifier: "test.sideband"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signed")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	v := &sidebandIOFailure{}
	opts := VerifyOptions{StrictSideband: true, AppleDouble: v}
	if _, err := Verify(ctx, path, opts); !errors.Is(err, ErrUntrusted) || v.reads != 0 {
		t.Fatal("metadata examined before certificate trust", v.reads, err)
	}
	opts.TrustedCertificates = id.Certificates
	if _, err := Verify(ctx, path, opts); !errors.Is(err, io.ErrUnexpectedEOF) || v.reads == 0 {
		t.Fatal("trusted signature bypassed carrier inspection", v.reads, err)
	}
	opts.AppleDouble = sidebandCarrier(t, appledouble.File{ResourceFork: []byte{1}})
	if _, err := Verify(ctx, path, opts); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
