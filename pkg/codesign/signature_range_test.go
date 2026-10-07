package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
)

func TestSignatureRangeLargeReservation(t *testing.T) {
	cd := testDirectories(t)[0]
	for _, size := range []uint64{1<<30 - 1, 1 << 30, 1<<30 + 1, 1<<31 - 1, 1 << 31, 1<<31 + 1, math.MaxUint32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			header := make([]byte, 20)
			be.PutUint32(header, MagicSignature)
			be.PutUint32(header[4:], uint32(size))
			be.PutUint32(header[8:], 1)
			offset := size - uint64(len(cd))
			be.PutUint32(header[16:], uint32(offset))
			plan, err := patchedOutput(outputSource{reader: zeroSource{}, size: int64(size)}, int64(size), outputSpan{0, byteOutput(header)}, outputSpan{int64(offset), byteOutput(cd)})
			if err != nil {
				t.Fatal(err)
			}
			source := codeSource{ctx: t.Context(), source: plan}
			var bytesRead uint64
			sig, err := parseSignatureRange(size, func(off, n uint64) ([]byte, error) {
				if n > uint64(len(cd)) {
					t.Fatal("materialized signature reservation", n)
				}
				bytesRead += n
				return source.read(off, n)
			}, false)
			if err != nil {
				t.Fatal(err)
			}
			if sig.Length != uint32(size) || len(sig.Blobs) != 1 || !bytes.Equal(sig.Blobs[0].Data, cd) {
				t.Fatal("lost indexed blob")
			}
			if bytesRead != uint64(12+8+8+len(cd)) {
				t.Fatal("read unused signature bytes", bytesRead)
			}
		})
	}
	// These virtual ranges test checked offsets and allocation shape only.
	// Native acceptance of any oversized or gapped signature is a separate
	// contract; this test does not claim that such a signature is valid code.
}

func TestSignatureRangeOwnershipAndReadFailures(t *testing.T) {
	frame := superblob(MagicSignature, []Blob{{Slot: SlotDirectory, Data: testDirectories(t)[0]}, {Slot: SlotCMS, Data: blob(MagicCMS, nil)}})
	want, err := ParseSignature(frame)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	fault := errors.New("signature range read failed")
	run := func(fail int) (*Signature, error) {
		reads = 0
		return parseSignatureRange(uint64(len(frame)), func(off, n uint64) ([]byte, error) {
			reads++
			if reads == fail {
				return nil, fault
			}
			return bytes.Clone(frame[off : off+n]), nil
		}, false)
	}
	got, err := run(0)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("range parity", err)
	}
	count := reads
	for stop := 1; stop <= count; stop++ {
		if sig, err := run(stop); sig != nil || !errors.Is(err, fault) || reads != stop {
			t.Fatalf("read %d: continued or lost failure: %v", stop, err)
		}
	}
	changed := false
	_, err = parseSignatureRange(uint64(len(frame)), func(off, n uint64) ([]byte, error) {
		b := bytes.Clone(frame[off : off+n])
		if off > 20 && n > 8 {
			b[4] ^= 1
			changed = true
		}
		return b, nil
	}, false)
	if !changed || !errors.Is(err, ErrFormat) {
		t.Fatal("changed component header accepted", err)
	}
	clear(frame)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("report aliases caller input")
	}
	if _, err := parseSignatureRange(0, nil, false); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := parseSignatureRange(12, (codeSource{ctx: ctx, source: byteOutput(make([]byte, 12))}).read, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
