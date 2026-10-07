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

func signatureFixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data := fixture(t, name)
	c, err := parseContainer(data)
	if err != nil {
		t.Fatal(err)
	}
	s := c.slices[0]
	return bytes.Clone(data[s.offset+uint64(s.image.sigOffset) : s.offset+uint64(s.image.sigOffset)+uint64(s.image.sigSize)])
}
func assertSignatureViewParity(t *testing.T, data []byte, allow bool) {
	t.Helper()
	want, werr := parseSignature(data, allow)
	ctx, storage, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	got, gerr := parseSignatureView(codeSource{ctx, byteOutput(data)}, allow)
	if fmt.Sprint(werr) != fmt.Sprint(gerr) {
		t.Fatalf("owned parser %v / view %v", werr, gerr)
	}
	if werr != nil {
		return
	}
	if got.length != want.Length || got.directoryCount != len(want.Directories) || int(got.count) != len(want.Blobs) {
		t.Fatal(got, want)
	}
	for i, d := range want.Directories {
		v := got.directories[i]
		if string(data[v.source.source.offset+int64(v.identifier.offset):v.source.source.offset+int64(v.identifier.offset+v.identifier.length)]) != d.Identifier {
			t.Fatal("identifier range differs")
		}
		if v.team.length > 0 && string(data[v.source.source.offset+int64(v.team.offset):v.source.source.offset+int64(v.team.offset+v.team.length)]) != d.TeamID {
			t.Fatal("team range differs")
		}
		d.Raw = nil
		d.Identifier = ""
		d.TeamID = ""
		if !reflect.DeepEqual(v.metadata, d) {
			t.Fatalf("directory metadata differs %+v/%+v", v.metadata, d)
		}
	}
	if storage.stats.PeakMemoryBytes > transferBufferSize {
		t.Fatal(storage.stats)
	}
}

func TestSignatureViewFixtureParity(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mode := range []string{"adhoc", "entitlements", "requirement", "runtime"} {
			t.Run(mode+"/"+arch, func(t *testing.T) { assertSignatureViewParity(t, signatureFixtureBytes(t, mode+"-"+arch), false) })
		}
	}
	assertSignatureViewParity(t, superblob(MagicSignature, nil), true)
	assertSignatureViewParity(t, superblob(MagicSignature, []Blob{{Slot: 987, Data: blob(1234, []byte("opaque"))}}), true)
}

func TestSignatureViewMalformedParity(t *testing.T) {
	data := signatureFixtureBytes(t, "runtime-arm64")
	for at := 0; at < min(len(data), 256); at++ {
		b := bytes.Clone(data)
		b[at] ^= 0x80
		t.Run(fmt.Sprint(at), func(t *testing.T) { assertSignatureViewParity(t, b, false) })
	}
	for _, n := range []int{0, 4, 11, 12, len(data) - 1} {
		assertSignatureViewParity(t, data[:n], false)
	}
	// Duplicate-slot rejection precedes the later slot's invalid blob offset.
	duplicate := bytes.Clone(data)
	copy(duplicate[20:24], duplicate[12:16])
	be.PutUint32(duplicate[24:], 0)
	assertSignatureViewParity(t, duplicate, false)
	// Overlap is deferred: a later component's bad magic wins first.
	sig, err := ParseSignature(data)
	if err != nil {
		t.Fatal(err)
	}
	primary := sig.find(0)
	inner := blob(MagicCMS, []byte("payload"))
	body := append(bytes.Clone(primary), inner...)
	overlap := superblob(MagicSignature, []Blob{{Slot: 0, Data: body}, {Slot: SlotCMS, Data: inner}})
	be.PutUint32(overlap[32:], uint32(len(body)))
	primaryOffset := be.Uint32(overlap[16:])
	be.PutUint32(overlap[24:], primaryOffset+uint32(len(primary)))
	for _, badMagic := range []bool{false, true} {
		b := bytes.Clone(overlap)
		if badMagic {
			be.PutUint32(b[primaryOffset+uint32(len(primary)):], 123)
		}
		assertSignatureViewParity(t, b, false)
	}
}

func TestSignatureViewReadFailureAndCancellation(t *testing.T) {
	data := signatureFixtureBytes(t, "runtime-arm64")
	fault := errors.New("signature component read fault")
	run := func(fail int, mode string) (int, error) {
		ctx, storage, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: t.TempDir()}))
		if err != nil {
			t.Fatal(err)
		}
		defer storage.Close()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		reads := 0
		source := codeSource{ctx, outputSource{size: int64(len(data)), reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
			reads++
			if len(p) > transferBufferSize {
				t.Fatal("component-sized read", len(p))
			}
			if reads == fail {
				switch mode {
				case "cancel":
					cancel()
					return bytes.NewReader(data).ReadAt(p, at)
				case "short":
					return 0, nil
				case "joined-eof":
					return len(p), errors.Join(io.EOF, fault)
				default:
					return len(p), fault
				}
			}
			return bytes.NewReader(data).ReadAt(p, at)
		})}}
		_, err = parseSignatureView(source, false)
		return reads, err
	}
	total, err := run(0, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= total; i++ {
		for _, mode := range []string{"fault", "short", "cancel", "joined-eof"} {
			_, err := run(i, mode)
			want := fault
			if mode == "short" {
				want = io.ErrUnexpectedEOF
			}
			if mode == "cancel" {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatal(i, mode, err, want)
			}
		}
	}
	ctx, _, _ := signatureTestStorage(t, transferBufferSize)
	firstComponent := int64(be.Uint32(data[16:]))
	source := codeSource{ctx, outputSource{size: int64(len(data)), reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
		n, err := bytes.NewReader(data).ReadAt(p, at)
		if at == firstComponent && len(p) > 8 {
			p[0] ^= 1
		}
		return n, err
	})}}
	if _, err := parseSignatureView(source, false); err == nil || err.Error() != malformed("signature component changed while reading").Error() {
		t.Fatal(err)
	}
}

func TestSignatureViewUntrustedCountDoesNotPreallocate(t *testing.T) {
	ctx, storage, _ := signatureTestStorage(t, transferBufferSize)
	header := make([]byte, 20)
	be.PutUint32(header, MagicSignature)
	be.PutUint32(header[4:], 1<<30)
	be.PutUint32(header[8:], (1<<30-12)/8)
	source := codeSource{ctx, outputSource{size: 1 << 30, reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
		if at+int64(len(p)) > int64(len(header)) {
			t.Fatal("read past first invalid index", at, len(p))
		}
		return copy(p, header[at:]), nil
	})}}
	if _, err := parseSignatureView(source, false); err == nil || err.Error() != malformed("blob header bounds").Error() {
		t.Fatal(err)
	}
	if storage.stats.SpillBytes > signatureIndexFirstExtent*signatureIndexNodeSize {
		t.Fatal("allocated for declared count", storage.stats)
	}
}

func TestSignatureViewPhysicalOldLimit(t *testing.T) {
	const bodySize = int64(1<<30) + 8
	f, err := os.Create(filepath.Join(t.TempDir(), "large-signature"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := prepareCommandSparseFixture(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(20 + bodySize); err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, 28)
	be.PutUint32(prefix, MagicSignature)
	be.PutUint32(prefix[4:], uint32(20+bodySize))
	be.PutUint32(prefix[8:], 1)
	be.PutUint32(prefix[12:], 987)
	be.PutUint32(prefix[16:], 20)
	be.PutUint32(prefix[20:], 1234)
	be.PutUint32(prefix[24:], uint32(bodySize))
	if _, err := f.WriteAt(prefix, 0); err != nil {
		t.Fatal(err)
	}
	ctx, storage, _ := signatureTestStorage(t, transferBufferSize)
	largest := 0
	source := codeSource{ctx, outputSource{size: 20 + bodySize, reader: transferReaderFunc(func(p []byte, at int64) (int, error) { largest = max(largest, len(p)); return f.ReadAt(p, at) })}}
	view, err := parseSignatureView(source, true)
	if err != nil || view.directoryCount != 0 || view.count != 1 || largest > transferBufferSize {
		t.Fatal(view, largest, err)
	}
	if storage.stats.PeakMemoryBytes > transferBufferSize || storage.stats.SpillBytes > 2*signatureIndexFirstExtent*signatureIndexNodeSize {
		t.Fatal(storage.stats)
	}
	// Public owned reports deliberately retain their existing allocation policy.
	if _, err := parseSignatureRange(uint64(source.source.size), source.read, true); !errors.Is(err, ErrUnsupported) {
		t.Fatal("owned report limit changed", err)
	}
}

func TestSignatureViewDirectoryVersionsAndStrings(t *testing.T) {
	for _, version := range []uint32{0x20001, 0x20100, 0x20200, 0x20300, 0x20400, 0x20500, 0x20600} {
		for _, kind := range []byte{1, 2, 3, 4} {
			raw := make([]byte, 112)
			be.PutUint32(raw, MagicDirectory)
			be.PutUint32(raw[4:], uint32(len(raw)))
			be.PutUint32(raw[8:], version)
			be.PutUint32(raw[16:], 112)
			be.PutUint32(raw[20:], 108)
			raw[36], raw[37] = map[byte]byte{1: 20, 2: 32, 3: 20, 4: 48}[kind], kind
			copy(raw[108:], "id\x00")
			if version >= 0x20200 {
				be.PutUint32(raw[48:], 111)
			}
			if version >= 0x20300 {
				be.PutUint64(raw[56:], 1<<34)
			}
			assertSignatureViewParity(t, superblob(MagicSignature, []Blob{{Slot: 0, Data: raw}}), false)
		}
	}
	raw := make([]byte, 2*transferBufferSize+120)
	be.PutUint32(raw, MagicDirectory)
	be.PutUint32(raw[4:], uint32(len(raw)))
	be.PutUint32(raw[8:], 0x20600)
	be.PutUint32(raw[16:], uint32(len(raw)))
	be.PutUint32(raw[20:], 108)
	be.PutUint32(raw[48:], transferBufferSize+112)
	raw[36], raw[37] = 32, 2
	for i := 108; i < len(raw)-1; i++ {
		raw[i] = 'i'
	}
	raw[transferBufferSize+111] = 0
	assertSignatureViewParity(t, superblob(MagicSignature, []Blob{{Slot: 0, Data: raw}}), false)
	be.PutUint32(raw[44:], 1)
	assertSignatureViewParity(t, superblob(MagicSignature, []Blob{{Slot: 0, Data: raw}}), false)
	be.PutUint32(raw[44:], 0)
	be.PutUint32(raw[4:], 48)
	assertSignatureViewParity(t, superblob(MagicSignature, []Blob{{Slot: 0, Data: raw[:48]}}), false)
	// All six supported directory slots are fixed storage, in index order.
	sig, err := ParseSignature(signatureFixtureBytes(t, "adhoc-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	var blobs []Blob
	for _, slot := range []uint32{0, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004} {
		blobs = append(blobs, Blob{Slot: slot, Data: sig.find(0)})
	}
	assertSignatureViewParity(t, superblob(MagicSignature, blobs), false)
	assertSignatureViewParity(t, superblob(MagicSignature, blobs[1:]), true)
}

func TestSignatureViewStorageFailures(t *testing.T) {
	data := signatureFixtureBytes(t, "runtime-arm64")
	fault := errors.New("signature view scratch fault")
	run := func(fail int) int {
		ctx, s, _ := signatureTestStorage(t, transferBufferSize)
		create := s.create
		var file *signatureIndexCountingFile
		s.create = func(dir, pattern string) (scratchFile, error) {
			f, err := create(dir, pattern)
			if err != nil {
				return nil, err
			}
			file = &signatureIndexCountingFile{scratchFile: f, fault: fault, fail: fail}
			return file, nil
		}
		_, err := parseSignatureView(codeSource{ctx, byteOutput(data)}, false)
		if fail > 0 && !errors.Is(err, fault) || fail == 0 && err != nil {
			t.Fatal(fail, err)
		}
		return file.calls
	}
	for i, total := 1, run(0); i <= total; i++ {
		run(i)
	}
	if _, err := parseSignatureView(codeSource{t.Context(), byteOutput(data)}, false); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	ctx, s, _ := signatureTestStorage(t, transferBufferSize)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	source := codeSource{ctx, byteOutput(data)}
	if _, _, err := scanSignatureComponent(source, data[:8], false); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := scanViewString(source, 1); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}
