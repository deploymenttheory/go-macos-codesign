package codesign

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCMSHeldSourceVerification(t *testing.T) {
	for _, kind := range []string{"rsa", "p256"} {
		id := testIdentity(t, kind)
		dmg, err := os.ReadFile("../../testdata/dmg/native-adhoc-raw.dmg")
		if err != nil {
			t.Fatal(err)
		}
		for _, input := range [][]byte{fixture(t, "unsigned-arm64"), dmg} {
			data, err := SignBytes(t.Context(), input, SignOptions{Identifier: "held-cms", Identity: id, SigningTime: certificateTime, Force: true})
			if err != nil {
				t.Fatal(err)
			}
			opts := VerifyOptions{TrustedCertificates: id.Certificates, CurrentTime: certificateTime}
			want, err := VerifyBytes(t.Context(), data, opts)
			if err != nil {
				t.Fatal(err)
			}
			cms := want.Architectures[0].Signature.find(SlotCMS)
			at := bytes.Index(data, cms)
			if at < 0 || len(cms) <= 8 {
				t.Fatal("missing CMS component")
			}
			guard := true
			reads := 0
			componentScans := 0
			reader := transferReaderFunc(func(p []byte, offset int64) (int, error) {
				if guard && offset <= int64(at+8) && offset+int64(len(p)) >= int64(at+len(cms)) {
					// SuperBlob validation consumes every component once through
					// its bounded transfer buffer to preserve read-error ordering.
					// A second complete read would materialize CMS for decoding.
					componentScans++
					if componentScans != 1 || offset != int64(at) || len(p) != len(cms) || len(p) > transferBufferSize {
						t.Fatal("CMS decoding requested the complete component", offset, len(p))
					}
				}
				if offset >= int64(at+8) && offset < int64(at+len(cms)) {
					reads++
				}
				return bytes.NewReader(data).ReadAt(p, offset)
			})
			ctx, storage, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: t.TempDir()}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := storage.Close(); err != nil {
					t.Error(err)
				}
			})
			source := codeSource{ctx, outputSource{reader: reader, size: int64(len(data))}}
			got, err := verifyInput(ctx, opts, isDMG(data), source.inspectView, source.digest, source.strict)
			if err != nil || reads == 0 || componentScans != 1 {
				t.Fatal("held verification", reads, err)
			}
			guard = false // Explicit owned ReadBlob results may read their complete value.
			assertBorrowedReport(t, got, want)
			if err := storage.Close(); err != nil {
				t.Fatal(err)
			}
			// Exercise the public scoped path over a real held file as well as the
			// instrumented reader. Metadata returned by its callback owns its bytes.
			path := filepath.Join(t.TempDir(), "signed")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			var metadata *CertificateMetadata
			if err := VisitVerification(t.Context(), path, opts, func(report *Report, err error) error {
				if err != nil {
					return err
				}
				metadata = report.Architectures[0].Signature.CertificateMetadata
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(metadata, want.Architectures[0].Signature.CertificateMetadata) {
				t.Fatal("scoped certificate metadata differs")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal("source descriptor retained after callback", err)
			}
		}
	}
}

func TestCMSSourceReadFailures(t *testing.T) {
	encoded, directories := testCMS(t)
	bound, err := bindCMSDirectories(directories)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	reader := transferReaderFunc(func(p []byte, at int64) (int, error) {
		calls++
		return bytes.NewReader(encoded).ReadAt(p, at)
	})
	source := codeSource{t.Context(), outputSource{reader: reader, size: int64(len(encoded))}}
	want, err := VerifyCMS(encoded, directories)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifyCMSSourceBound(source, bound)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("source and byte verification differ", err)
	}
	for failAt := 1; failAt <= calls; failAt++ {
		for _, failure := range []error{os.ErrPermission, io.ErrUnexpectedEOF, context.Canceled} {
			ctx, cancel := context.WithCancel(t.Context())
			n := 0
			reader := transferReaderFunc(func(p []byte, at int64) (int, error) {
				n++
				if n == failAt {
					if errors.Is(failure, context.Canceled) {
						cancel()
					} else {
						return 0, failure
					}
				}
				return bytes.NewReader(encoded).ReadAt(p, at)
			})
			got, err := verifyCMSSourceBound(codeSource{ctx, outputSource{reader: reader, size: int64(len(encoded))}}, bound)
			cancel()
			if got != nil || !errors.Is(err, failure) {
				t.Fatal("lost CMS read failure", failAt, failure, err)
			}
		}
	}
	// The range container validates its own bounds, including callers that have
	// not yet parsed an outer envelope.
	for _, bounds := range [][2]uint64{{1, uint64(len(encoded))}, {0, uint64(len(encoded)) + 1}} {
		budget := 4096
		if _, err := cmsBERChildRanges(source, bounds[0], bounds[1], 0x30, &budget); !errors.Is(err, ErrFormat) {
			t.Fatal("invalid container bounds", err)
		}
	}
}
