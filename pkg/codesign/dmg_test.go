package codesign

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

func testDMG(t testing.TB) []byte {
	t.Helper()
	var out bytes.Buffer
	data := bytes.Repeat([]byte("public image content"), 100)
	data = append(data, make([]byte, 4096-len(data))...)
	if err := disk.EncodeUDIF(&out, []disk.SourceBlock{{Name: "test", Data: data, SectorCount: 8}}, nil); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestDMGLifecycle(t *testing.T) {
	ctx := context.Background()
	data := testDMG(t)
	before := bytes.Clone(data)
	if dmgFooterSize != 512 {
		t.Fatal("APFS footer encoding changed")
	}
	if _, err := VerifyBytes(ctx, data, VerifyOptions{}); !errors.Is(err, ErrUnsigned) {
		t.Fatal(err)
	}
	for _, page := range []uint32{0, 4096, 16384} {
		out, err := SignBytes(ctx, data, SignOptions{Identifier: "test", PageSize: page})
		if err != nil {
			t.Fatal(err)
		}
		r, err := VerifyBytes(ctx, out, VerifyOptions{})
		if err != nil || !r.Valid || r.Format != "disk image" {
			t.Fatal(r, err)
		}
		if _, err := SignBytes(ctx, out, SignOptions{Identifier: "test"}); !errors.Is(err, ErrSigned) {
			t.Fatal(err)
		}
		again, err := SignBytes(ctx, out, SignOptions{Identifier: "test", PageSize: page, Force: true})
		if err != nil || !bytes.Equal(again, out) {
			t.Fatal("replacement drift", err)
		}
		if _, err := RemoveSignatureBytes(ctx, out); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
		for _, opts := range []VerifyOptions{{InfoPlist: []byte("x")}, {Resources: []byte("x")}} {
			if _, err := VerifyBytes(ctx, out, opts); !errors.Is(err, ErrUnsupported) {
				t.Fatal(err)
			}
		}
	}
	if !bytes.Equal(data, before) {
		t.Fatal("modified input")
	}
	for _, opts := range []SignOptions{{PageSize: 1}, {PageSize: 3}, {PageSize: 1 << 31}, {Requirements: []byte("bad")}, {InfoPlist: []byte("x")}, {Resources: []byte("x")}, {Entitlements: []byte("bad"), ForceLibraryEntitlements: true}} {
		opts.Identifier = "test"
		if _, err := SignBytes(ctx, data, opts); err == nil {
			t.Fatal("accepted unsupported option", opts)
		}
	}
}

func TestDMGMalformedTrailer(t *testing.T) {
	ctx := context.Background()
	data, err := SignBytes(ctx, testDMG(t), SignOptions{Identifier: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*disk.DMGFooter){
		func(h *disk.DMGFooter) { h.Version = 5 },
		func(h *disk.DMGFooter) { h.HeaderSize = 0 },
		func(h *disk.DMGFooter) { h.SegmentCount = 2 },
		func(h *disk.DMGFooter) { h.CodeSignatureOffset = 0 },
		func(h *disk.DMGFooter) { h.CodeSignatureOffset = 1 },
		func(h *disk.DMGFooter) { h.CodeSignatureOffset = ^uint64(0) },
		func(h *disk.DMGFooter) { h.CodeSignatureLength++ },
		func(h *disk.DMGFooter) { h.CodeSignatureLength = 0 },
		func(h *disk.DMGFooter) { h.PlistLength = ^uint64(0) },
		func(h *disk.DMGFooter) { h.PlistOffset = 0 },
		func(h *disk.DMGFooter) { h.PlistLength = 0 },
	} {
		bad := bytes.Clone(data)
		var h disk.DMGFooter
		_ = binary.Read(bytes.NewReader(bad[len(bad)-512:]), be, &h)
		mutate(&h)
		var trailer bytes.Buffer
		_ = binary.Write(&trailer, be, h)
		copy(bad[len(bad)-512:], trailer.Bytes())
		if _, err := InspectBytes(bad); err == nil {
			t.Fatal("inspected malformed trailer")
		}
		if _, err := SignBytes(ctx, bad, SignOptions{Identifier: "test", Force: true}); err == nil {
			t.Fatal("signed malformed trailer")
		}
		if _, err := dmgIdentifier("test.dmg", bad, true); err == nil {
			t.Fatal("identified malformed trailer")
		}
	}
	if _, err := parseDMG(make([]byte, 512)); err == nil {
		t.Fatal("short image")
	}
	m, err := parseDMG(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, len(m.content), len(m.content) + 4, len(data) - 512 + 80} {
		bad := bytes.Clone(data)
		bad[offset] ^= 1
		r, err := VerifyBytes(ctx, bad, VerifyOptions{})
		if err == nil || r != nil && r.Valid {
			t.Fatal("accepted tampering", offset, err)
		}
	}
	// A self-consistent ad-hoc directory must still bind the actual trailer.
	bad := bytes.Clone(data)
	cdOffset := int(be.Uint32(bad[len(m.content)+16:]))
	be.PutUint32(bad[len(m.content)+cdOffset+24:], 2)
	if r, err := VerifyBytes(ctx, bad, VerifyOptions{}); err == nil || r == nil || r.Valid {
		t.Fatal("missing trailer binding accepted", err)
	}
	// Mach-O allows reserved signature padding; UDIF requires an exact frame.
	bad = bytes.Clone(data)
	length := be.Uint32(bad[len(m.content)+4:])
	be.PutUint32(bad[len(m.content)+4:], length-1)
	if _, err := parseDMG(bad); err == nil {
		t.Fatal("signature length mismatch")
	}
}

func TestDMGPathsAndTimestampFailure(t *testing.T) {
	ctx := context.Background()
	data := testDMG(t)
	path := filepath.Join(t.TempDir(), "Example.dmg")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, path, SignOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("dry run changed input", err)
	}
	failure := errors.New("TSA unavailable")
	opts := SignOptions{Identity: testIdentity(t, "rsa"), Timestamp: &TimestampOptions{TrustedRoots: AppleTimestampRoots(), Provider: func(context.Context, []byte) ([]byte, error) { return nil, failure }}}
	if err := Sign(ctx, path, opts); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("TSA failure changed input", err)
	}
	if err := Sign(ctx, path, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, path, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSignature(ctx, path); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	bad := testDMG(t)
	be.PutUint32(bad[len(bad)-512+4:], 99)
	if err := os.WriteFile(path, bad, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, path, SignOptions{}); err == nil {
		t.Fatal("malformed image default identifier")
	}
}

func FuzzDMG(f *testing.F) {
	f.Add(testDMG(f))
	f.Add([]byte("koly"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = parseDMG(data)
		_, _ = VerifyBytes(context.Background(), data, VerifyOptions{})
	})
}

func TestDMGClangFacts(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-dmg.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		Version string `json:"udif_version_declaration"`
		Targets map[string]map[string]struct{ Members map[string]int }
	}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	if facts.Version != "static const int32_t udifVersion = 4;" || len(facts.Targets) != 2 {
		t.Fatal("UDIF version or Clang target facts missing")
	}
	for target, methods := range facts.Targets {
		for _, name := range []string{"readHeader", "setup", "signingLimit", "flush", "canonicalIdentifier"} {
			if _, ok := methods[name]; !ok {
				t.Fatal(target, name)
			}
		}
		for _, name := range []string{"setup", "flush"} {
			for _, member := range []string{"fUDIFCodeSignOffset", "fUDIFCodeSignLength"} {
				if methods[name].Members[member] == 0 {
					t.Fatal(target, name, member)
				}
			}
		}
	}
}
