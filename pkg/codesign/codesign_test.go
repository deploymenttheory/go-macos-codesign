package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "macho", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertAppleBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	t.Logf("Go: length=%d sha256=%x", len(got), sha256.Sum256(got))
	t.Logf("Apple: length=%d sha256=%x", len(want), sha256.Sum256(want))
	offset := 0
	for offset < min(len(got), len(want)) && got[offset] == want[offset] {
		offset++
	}
	start := max(0, offset-8)
	gotEnd, wantEnd := min(len(got), offset+16), min(len(want), offset+16)
	t.Fatalf("Apple byte parity mismatch at offset %#x (EOF if one input ends here)\nGo [%#x:%#x]: % x\nApple [%#x:%#x]: % x",
		offset, start, gotEnd, got[start:gotEnd], start, wantEnd, want[start:wantEnd])
}

func TestAppleAdhocExact(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			unsigned := fixture(t, "unsigned-"+arch)
			original := bytes.Clone(unsigned)
			out, err := SignBytes(context.Background(), unsigned, SignOptions{Identifier: "org.example.fixture"})
			if err != nil {
				t.Fatal(err)
			}
			want := fixture(t, "adhoc-"+arch)
			assertAppleBytes(t, out, want)
			if !bytes.Equal(unsigned, original) {
				t.Fatal("mutated input")
			}
			r, err := VerifyBytes(context.Background(), out, VerifyOptions{})
			if err != nil || !r.Valid {
				t.Fatalf("verify: %+v %v", r, err)
			}
			_, err = SignBytes(context.Background(), out, SignOptions{Identifier: "org.example.fixture"})
			if !errors.Is(err, ErrSigned) {
				t.Fatalf("got %v", err)
			}
			replaced, err := SignBytes(context.Background(), out, SignOptions{Identifier: "org.example.fixture", Force: true})
			if err != nil || !bytes.Equal(replaced, out) {
				t.Fatalf("force did not reproduce bytes: %v", err)
			}
			stripped, err := RemoveSignatureBytes(context.Background(), out)
			if err != nil {
				t.Fatal(err)
			}
			_, err = VerifyBytes(context.Background(), stripped, VerifyOptions{})
			if !errors.Is(err, ErrUnsigned) {
				t.Fatal(err)
			}
			_, err = SignBytes(context.Background(), stripped, SignOptions{Identifier: "org.example.fixture"})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTamperAndRequirement(t *testing.T) {
	b := fixture(t, "adhoc-arm64")
	b[0x1000] ^= 1
	if _, err := VerifyBytes(context.Background(), b, VerifyOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	b = fixture(t, "adhoc-arm64")
	for _, tc := range []struct {
		req string
		ok  bool
	}{{`identifier "org.example.fixture"`, true}, {`identifier "wrong"`, false}, {`never or (always and not false)`, true}} {
		_, err := VerifyBytes(context.Background(), b, VerifyOptions{Requirement: tc.req})
		if tc.ok && err != nil || !tc.ok && !errors.Is(err, ErrRequirement) {
			t.Fatalf("%s: %v", tc.req, err)
		}
	}
}

func TestFileOperations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hello")
	if err := os.WriteFile(path, fixture(t, "unsigned-arm64"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := Sign(ctx, path, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err := Inspect(ctx, path)
	if err != nil || r.Architectures[0].Signature.Directories[0].Identifier != "hello-555549442de53ff73d323d21af337baddce25aae" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = Verify(ctx, path, VerifyOptions{})
	if err != nil || !r.Valid {
		t.Fatalf("%+v %v", r, err)
	}
	if err := RemoveSignature(ctx, path); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSignature(ctx, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, path, VerifyOptions{}); !errors.Is(err, ErrUnsigned) {
		t.Fatal(err)
	}
}

func FuzzInspect(f *testing.F) {
	b, err := os.ReadFile("../../testdata/macho/adhoc-arm64")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, _ = InspectBytes(b)
		before := bytes.Clone(b)
		if report, err := VerifyBytes(context.Background(), b, VerifyOptions{}); err == nil {
			_ = report.CheckDesignatedRequirement("")
			_ = report.CheckRequirement("always", "")
			if !report.Valid || !bytes.Equal(before, b) {
				t.Fatal("requirement checks changed verified input or result")
			}
		}
		_, _ = SignBytes(context.Background(), b, SignOptions{Identifier: "fuzz", Force: true})
		_, _ = RemoveSignatureBytes(context.Background(), b)
	})
}
