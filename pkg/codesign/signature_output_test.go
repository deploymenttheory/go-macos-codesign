package codesign

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedSignatureSpillParity(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			var stats []WorkingStorageStats
			ctx := WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: dir, Observe: func(s WorkingStorageStats) { stats = append(stats, s) }})
			input := fixture(t, "unsigned-"+arch)
			want := fixture(t, "adhoc-"+arch)
			signed, err := SignBytes(ctx, input, SignOptions{Identifier: "org.example.fixture"})
			if err != nil {
				t.Fatal(err)
			}
			assertAppleBytes(t, signed, want)
			path := filepath.Join(t.TempDir(), "hello")
			if err := os.WriteFile(path, input, 0755); err != nil {
				t.Fatal(err)
			}
			if err := Sign(ctx, path, SignOptions{Identifier: "org.example.fixture"}); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			assertAppleBytes(t, got, want)
			if report, err := Verify(ctx, path, VerifyOptions{}); err != nil || !report.Valid {
				t.Fatal(report, err)
			}
			if err := RemoveSignature(ctx, path); err != nil {
				t.Fatal(err)
			}
			if len(stats) != 4 {
				t.Fatalf("scope cleanup count: %d", len(stats))
			}
			for i, s := range stats {
				if s.MemoryBytes != 0 || s.PeakMemoryBytes > transferBufferSize {
					t.Fatal(s)
				}
				if i < 2 && (s.SpillFiles != 1 || s.SpillBytes == 0) {
					t.Fatal("signing did not spill", s)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("scratch leak", entries, err)
			}
		})
	}
}

type signatureFaultIO struct {
	fault error
	short bool
}

func (f signatureFaultIO) ReadAt([]byte, int64) (int, error) { return 0, f.fault }
func (f signatureFaultIO) WriteAt(b []byte, _ int64) (int, error) {
	if f.short {
		return len(b) - 1, nil
	}
	return 0, f.fault
}

func TestSignatureOutputFailures(t *testing.T) {
	ctx := t.Context()
	for _, sections := range [][]signatureSection{
		{{1, byteOutput(make([]byte, 7))}},
		{{1, outputSource{size: math.MaxUint32}}},
		{{1, outputSource{offset: -1, size: 8}}},
		{{1, outputSource{offset: math.MaxInt64 - 7, size: 8}}},
		{{1, byteOutput(make([]byte, 8))}, {1, byteOutput(make([]byte, 8))}},
	} {
		if _, err := superblobOutput(MagicSignature, sections); err == nil {
			t.Fatal("invalid signature accepted")
		}
	}
	section := workingSection{writer: signatureFaultIO{fault: io.ErrClosedPipe}, size: 100}
	if err := writeDirectoryPrefix(ctx, section, []byte("header"), "id", ""); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	section = workingSection{reader: rangeBuffer(make([]byte, 6)), writer: rangeBuffer(make([]byte, 6)), size: 6}
	if err := writeDirectoryPrefix(ctx, section, []byte("header"), "id", ""); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	for _, fault := range []signatureFaultIO{{fault: io.ErrClosedPipe}, {short: true}} {
		want := io.ErrClosedPipe
		if fault.short {
			want = io.ErrShortWrite
		}
		if err := hashCodePagesTo(ctx, byteOutput(make([]byte, 32)), 32, fault, 0); !errors.Is(err, want) {
			t.Fatal(err)
		}
		if err := hashCodePagesTo(ctx, byteOutput(make([]byte, 31)), 32, fault, 0); !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
	id := testIdentity(t, "rsa")
	if _, err := signGeneratedCMS(ctx, id, outputSource{reader: signatureFaultIO{fault: io.ErrUnexpectedEOF}, size: 1}, certificateTime, nil); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}

func TestGeneratedCMSRangeParity(t *testing.T) {
	id := testIdentity(t, "rsa")
	dirs := testDirectories(t)
	ctx, s, err := beginWorkingStorage(WithWorkingStorage(context.Background(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	section, err := newWorkingSection(ctx, int64(len(dirs[0])))
	if err != nil {
		t.Fatal(err)
	}
	if err := transferOutput(ctx, section, byteOutput(dirs[0])); err != nil {
		t.Fatal(err)
	}
	want, err := SignCMS(ctx, id, dirs, certificateTime)
	if err != nil {
		t.Fatal(err)
	}
	got, err := signGeneratedCMS(ctx, id, section.output(), certificateTime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("range CMS differs from byte API")
	}
	if _, err := VerifyCMS(got, dirs); err != nil {
		t.Fatal(err)
	}
}
