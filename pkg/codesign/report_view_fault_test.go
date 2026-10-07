package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
)

func TestBorrowedBundleReport(t *testing.T) {
	app := testBundle(t)
	bundleFile(t, app, "Contents/Helpers/worker", fixture(t, "unsigned-arm64"))
	if err := Sign(t.Context(), app, SignOptions{Deep: true}); err != nil {
		t.Fatal(err)
	}
	for _, inspect := range []bool{false, true} {
		for _, ignore := range []bool{false, true} {
			t.Run(fmt.Sprintf("inspect=%t/ignore=%t", inspect, ignore), func(t *testing.T) {
				opts := VerifyOptions{Deep: true, IgnoreResources: ignore}
				var want *Report
				var err error
				if inspect {
					want, err = Inspect(t.Context(), app)
				} else {
					want, err = Verify(t.Context(), app, opts)
				}
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				visitor := func(got *Report, err error) error {
					calls++
					if err != nil {
						t.Fatal(err)
					}
					assertBorrowedReport(t, got, want)
					gf, ge := got.SignatureFiles("")
					wf, we := want.SignatureFiles("")
					if !reflect.DeepEqual(gf, wf) || fmt.Sprint(ge) != fmt.Sprint(we) {
						t.Fatal(gf, wf, ge, we)
					}
					return nil
				}
				if inspect {
					err = VisitInspection(t.Context(), app, PathOptions{}, visitor)
				} else {
					err = VisitVerification(t.Context(), app, opts, visitor)
				}
				if calls != 1 || err != nil {
					t.Fatal(calls, err)
				}
			})
		}
	}
}

func TestBorrowedReportReadFailures(t *testing.T) {
	data := signatureFixtureBytes(t, "entitlements-arm64")
	fault := errors.New("held signature read failed")
	for _, operation := range []string{"report", "component", "requirements", "entitlements", "hash", "digest", "reader", "size"} {
		t.Run(operation, func(t *testing.T) {
			run := func(fail int, cancelRead bool) int {
				ctx, storage, err := beginWorkingStorage(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer storage.Close()
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				reads, armed := 0, false
				source := codeSource{ctx, outputSource{size: int64(len(data)), reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
					if armed {
						reads++
						if reads == fail {
							if cancelRead {
								cancel()
							}
							return 0, fault
						}
					}
					return bytes.NewReader(data).ReadAt(p, at)
				})}}
				view, err := parseSignatureView(source, false)
				if err != nil {
					t.Fatal(err)
				}
				sig, err := view.report()
				if err != nil {
					t.Fatal(err)
				}
				r := &Report{Architectures: []Architecture{{Name: "arm64", Signature: sig}}}
				armed = true
				switch operation {
				case "report":
					_, err = view.report()
				case "component":
					_, err = sig.ReadBlob(SlotDirectory)
				case "requirements":
					_, err = r.RequirementText("")
				case "entitlements":
					_, err = InspectEntitlements(sig)
				case "hash":
					_, err = sig.Directories[0].hashAt(uint64(sig.Directories[0].HashOffset))
				case "digest":
					_, _, err = sig.componentDigest(ctx, SlotEntitlements, 2)
				case "reader":
					_, err = sig.BlobReader(SlotDirectory)
				case "size":
					_, err = sig.BlobSize(SlotDirectory)
				}
				if fail == 0 {
					if err != nil {
						t.Fatal(err)
					}
				} else if !errors.Is(err, fault) || cancelRead && !errors.Is(err, context.Canceled) {
					t.Fatal(fail, cancelRead, err)
				}
				return reads
			}
			for i, n := 1, run(0, false); i <= n; i++ {
				run(i, false)
				run(i, true)
			}
		})
	}
}

func TestBorrowedComponentChanges(t *testing.T) {
	for _, change := range []string{"slot", "offset", "length-small", "length-large", "index-storage"} {
		t.Run(change, func(t *testing.T) {
			ctx, storage, err := beginWorkingStorage(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer storage.Close()
			data := signatureFixtureBytes(t, "adhoc-arm64")
			view, err := parseSignatureView(codeSource{ctx, byteOutput(data)}, false)
			if err != nil {
				t.Fatal(err)
			}
			offset := be.Uint32(data[16:])
			switch change {
			case "slot":
				be.PutUint32(data[12:], 999)
			case "offset":
				be.PutUint32(data[16:], ^uint32(0))
			case "length-small":
				be.PutUint32(data[offset+4:], 4)
			case "length-large":
				be.PutUint32(data[offset+4:], ^uint32(0))
			case "index-storage":
				view.slots.extents[0].reader = transferReaderFunc(func([]byte, int64) (int, error) { return 0, os.ErrClosed })
			}
			if _, _, err := view.component(SlotDirectory); err == nil {
				t.Fatal("changed component accepted")
			}
		})
	}
}

func TestBorrowedCMSBinding(t *testing.T) {
	var directories [][]byte
	for _, kind := range []uint8{1, 2, 3, 4} {
		raw := make([]byte, 64)
		be.PutUint32(raw, MagicDirectory)
		be.PutUint32(raw[4:], uint32(len(raw)))
		be.PutUint32(raw[8:], 0x20001)
		be.PutUint32(raw[16:], uint32(len(raw)))
		be.PutUint32(raw[20:], 44)
		raw[36], raw[37] = map[uint8]uint8{1: 20, 2: 32, 3: 20, 4: 48}[kind], kind
		directories = append(directories, raw)
	}
	for _, indices := range [][]int{{0}, {1}, {2}, {3}, {3, 0, 1}, {1, 2}, {0, 0, 0, 0, 0, 0}} {
		t.Run(fmt.Sprint(indices), func(t *testing.T) {
			var blobs []Blob
			var dirs [][]byte
			for i, index := range indices {
				slot := uint32(0)
				if i > 0 {
					slot = uint32(0x1000 + i - 1)
				}
				blobs = append(blobs, Blob{Slot: slot, Data: directories[index]})
				dirs = append(dirs, directories[index])
			}
			data := superblob(MagicSignature, blobs)
			// Reverse the index records; binding order must still follow slots.
			for i, j := 0, len(blobs)-1; i < j; i, j = i+1, j-1 {
				var temp [8]byte
				copy(temp[:], data[12+i*8:20+i*8])
				copy(data[12+i*8:20+i*8], data[12+j*8:20+j*8])
				copy(data[12+j*8:20+j*8], temp[:])
			}
			ctx, storage, err := beginWorkingStorage(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer storage.Close()
			view, err := parseSignatureView(codeSource{ctx, byteOutput(data)}, false)
			if err != nil {
				t.Fatal(err)
			}
			want, we := bindCMSDirectories(dirs)
			got, ge := view.cmsBinding()
			if fmt.Sprint(we) != fmt.Sprint(ge) || ge == nil && !reflect.DeepEqual(got, want) {
				t.Fatal(got, want, ge, we)
			}
		})
	}
	ctx, storage, err := beginWorkingStorage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	view, err := parseSignatureView(codeSource{ctx, byteOutput(signatureFixtureBytes(t, "adhoc-arm64"))}, false)
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("CMS range hash fault")
	for fail := 1; fail <= 2; fail++ {
		calls := 0
		dir := &view.directories[0]
		raw := testDirectories(t)[0]
		dir.source.source.reader = transferReaderFunc(func(p []byte, at int64) (int, error) {
			calls++
			if calls == fail {
				return 0, fault
			}
			return bytes.NewReader(raw).ReadAt(p, at)
		})
		dir.source.source.offset = 0
		if _, err := view.cmsBinding(); !errors.Is(err, fault) {
			t.Fatal(err)
		}
	}
	view.directories[0].source.source.size = 16<<20 + 1
	// A supported large directory must still reject a truncated held source.
	if _, err := view.cmsBinding(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if _, err := (&signatureView{}).cmsBinding(); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	// A failing source cannot turn a stored hash into an absent/zero hash.
	d := Directory{HashSize: 32, HashOffset: 32, SpecialSlots: 1, view: &directoryView{source: codeSource{ctx, outputSource{reader: transferReaderFunc(func([]byte, int64) (int, error) { return 0, io.ErrClosedPipe }), size: 32}}}}
	if _, err := d.specialSlotHash(1); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
