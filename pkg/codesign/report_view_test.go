package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func assertBorrowedReport(t *testing.T, got, want *Report) {
	t.Helper()
	if got == nil || want == nil {
		if got != nil || want != nil {
			t.Fatal("report presence differs")
		}
		return
	}
	if got.Valid != want.Valid || got.Path != want.Path || got.Format != want.Format || !reflect.DeepEqual(got.Bundle, want.Bundle) || len(got.Architectures) != len(want.Architectures) {
		t.Fatal("report metadata differs", got, want)
	}
	for i, a := range got.Architectures {
		w := want.Architectures[i]
		gs, ws := a.Signature, w.Signature
		a.Signature, w.Signature = nil, nil
		if !reflect.DeepEqual(a, w) {
			t.Fatal("architecture metadata differs", a, w)
		}
		if gs == nil || ws == nil {
			if gs != nil || ws != nil {
				t.Fatal("signature presence differs")
			}
			continue
		}
		if gs.view == nil || gs.Blobs != nil || gs.Length != ws.Length || len(gs.Directories) != len(ws.Directories) || !reflect.DeepEqual(gs.CertificateMetadata, ws.CertificateMetadata) {
			t.Fatal("signature metadata differs")
		}
		for j, directory := range gs.Directories {
			expected := ws.Directories[j]
			if directory.Raw != nil || directory.Size() != int64(len(expected.Raw)) {
				t.Fatal("directory was materialized or has wrong length")
			}
			directory.view, expected.Raw = nil, nil
			if !reflect.DeepEqual(directory, expected) {
				t.Fatal("directory metadata differs", directory, expected)
			}
		}
		for _, b := range ws.Blobs {
			data, err := gs.ReadBlob(b.Slot)
			if err != nil || !bytes.Equal(data, b.Data) {
				t.Fatal("component bytes differ", b.Slot, err)
			}
			if size, err := gs.BlobSize(b.Slot); err != nil || size != int64(len(b.Data)) {
				t.Fatal("component size differs", b.Slot, size, err)
			}
			reader, err := gs.BlobReader(b.Slot)
			if err != nil || reader == nil {
				t.Fatal(err)
			}
			read, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(read, data) {
				t.Fatal("component reader differs", err)
			}
			clear(data)
			read, err = gs.ReadBlob(b.Slot)
			if err != nil || !bytes.Equal(read, b.Data) {
				t.Fatal("ReadBlob returned mutable source storage", err)
			}
		}
		if data, err := gs.ReadBlob(0xabcdef); data != nil || err != nil {
			t.Fatal("absent blob", data, err)
		}
		if size, err := gs.BlobSize(0xabcdef); size != 0 || err != nil {
			t.Fatal("absent blob size", size, err)
		}
		if reader, err := gs.BlobReader(0xabcdef); reader != nil || err != nil {
			t.Fatal("absent blob reader", reader, err)
		}
	}
}

func TestBorrowedReportFixtureParity(t *testing.T) {
	fixtures := map[string][]byte{}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mode := range []string{"unsigned", "adhoc", "entitlements", "requirement", "runtime"} {
			name := mode + "-" + arch
			fixtures[name] = fixture(t, name)
		}
	}
	for _, name := range []string{"native-adhoc-raw.dmg", "native-p256-zlib.dmg", "native-rsa-zlib.dmg"} {
		data, err := os.ReadFile(filepath.Join("../../testdata/dmg", name))
		if err != nil {
			t.Fatal(err)
		}
		fixtures[name] = data
	}
	for name, data := range fixtures {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "code")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"inspect", "verify", "architecture", "requirements"} {
				t.Run(operation, func(t *testing.T) {
					var stats WorkingStorageStats
					ctx := WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: t.TempDir(), Observe: func(s WorkingStorageStats) { stats = s }})
					var want *Report
					var wantErr error
					opts := VerifyOptions{}
					if operation == "architecture" {
						opts.Architecture = "missing"
					}
					if operation == "requirements" {
						opts.CheckDesignatedRequirement = true
						opts.Requirement = "always"
					}
					if operation == "inspect" {
						want, wantErr = Inspect(t.Context(), path)
					} else {
						want, wantErr = Verify(t.Context(), path, opts)
					}
					called := 0
					visitor := func(report *Report, err error) error {
						called++
						if fmt.Sprint(err) != fmt.Sprint(wantErr) {
							t.Fatal("operation error differs", err, wantErr)
						}
						assertBorrowedReport(t, report, want)
						if report != nil {
							gt, ge := report.RequirementText("")
							wt, we := want.RequirementText("")
							if !bytes.Equal(gt, wt) || fmt.Sprint(ge) != fmt.Sprint(we) {
								t.Fatal("requirement extraction differs", ge, we)
							}
							for i, a := range report.Architectures {
								ge, gerr := InspectEntitlements(a.Signature)
								we, werr := InspectEntitlements(want.Architectures[i].Signature)
								if !reflect.DeepEqual(ge, we) || fmt.Sprint(gerr) != fmt.Sprint(werr) {
									t.Fatal("entitlement extraction differs", gerr, werr)
								}
							}
						}
						return nil
					}
					var err error
					if operation == "inspect" {
						err = VisitInspection(ctx, path, PathOptions{}, visitor)
					} else {
						err = VisitVerification(ctx, path, opts, visitor)
					}
					if called != 1 || fmt.Sprint(err) != fmt.Sprint(wantErr) || stats.MemoryBytes != 0 || stats.PeakMemoryBytes > transferBufferSize {
						t.Fatal(called, err, wantErr, stats)
					}
				})
			}
		})
	}
}

func TestBorrowedReportLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "code")
	if err := os.WriteFile(path, fixture(t, "adhoc-arm64"), 0600); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("consumer failed")
	for _, verify := range []bool{false, true} {
		for _, state := range []string{"success", "missing", "cancel", "callback-error"} {
			t.Run(fmt.Sprintf("%t/%s", verify, state), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				target := path
				var want error
				switch state {
				case "missing":
					target += ".missing"
					want = os.ErrNotExist
				case "cancel":
					cancel()
					want = context.Canceled
				case "callback-error":
					want = fault
				}
				calls := 0
				visitor := func(r *Report, err error) error {
					calls++
					if state == "callback-error" {
						if err != nil || r == nil {
							t.Fatal(r, err)
						}
						return fault
					}
					if !errors.Is(err, want) {
						t.Fatal(err, want)
					}
					return nil
				}
				var err error
				if verify {
					err = VisitVerification(ctx, target, VerifyOptions{}, visitor)
				} else {
					err = VisitInspection(ctx, target, PathOptions{}, visitor)
				}
				if calls != 1 || !errors.Is(err, want) {
					t.Fatal(calls, err, want)
				}
			})
		}
	}
	if err := VisitInspection(t.Context(), path, PathOptions{}, nil); err == nil {
		t.Fatal("accepted missing consumer")
	}
	// Callback and operation failures remain independently observable.
	err := VisitVerification(t.Context(), path+".missing", VerifyOptions{}, func(*Report, error) error { return fault })
	if !errors.Is(err, fault) || !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestOwnedReportAccessors(t *testing.T) {
	sig, err := ParseSignature(signatureFixtureBytes(t, "adhoc-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range []uint32{SlotDirectory, SlotRequirements, 0xabcdef} {
		data, err := sig.ReadBlob(slot)
		if err != nil || !bytes.Equal(data, sig.find(slot)) {
			t.Fatal(err)
		}
		if size, err := sig.BlobSize(slot); err != nil || size != int64(len(data)) {
			t.Fatal(size, err)
		}
		reader, err := sig.BlobReader(slot)
		if err != nil || (reader == nil) != (data == nil) {
			t.Fatal(err)
		}
		if reader != nil {
			copy, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(copy, data) {
				t.Fatal(err)
			}
		}
		clear(data)
		if len(data) > 0 && bytes.Equal(data, sig.find(slot)) {
			t.Fatal("ReadBlob aliases owned report")
		}
	}
	if _, err := (Directory{HashSize: 32}).hashAt(0); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
}
