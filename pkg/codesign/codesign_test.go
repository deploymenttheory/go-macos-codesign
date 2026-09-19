package codesign

import (
	"bytes"
	"context"
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
			if !bytes.Equal(out, want) {
				for i := 0; i < min(len(out), len(want)); i++ {
					if out[i] != want[i] {
						t.Fatalf("first byte difference at %#x: got %02x want %02x; sizes %d/%d", i, out[i], want[i], len(out), len(want))
					}
				}
				t.Fatalf("sizes %d/%d", len(out), len(want))
			}
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
	if err != nil || r.Architectures[0].Signature.Directories[0].Identifier != "hello" {
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
		_, _ = VerifyBytes(context.Background(), b, VerifyOptions{})
		_, _ = SignBytes(context.Background(), b, SignOptions{Identifier: "fuzz", Force: true})
		_, _ = RemoveSignatureBytes(context.Background(), b)
	})
}
