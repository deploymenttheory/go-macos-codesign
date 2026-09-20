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
)

func removalImage(t *testing.T, order binary.ByteOrder, is64 bool) ([]byte, int) {
	t.Helper()
	b := syntheticMachO(order, is64)
	header := 28
	if is64 {
		header = 32
	}
	p := header + int(order.Uint32(b[20:]))
	order.PutUint32(b[p:], 2)
	order.PutUint32(b[p+4:], 24)
	order.PutUint32(b[p+8:], 4096)
	order.PutUint32(b[p+12:], 3)
	order.PutUint32(b[p+16:], 4160)
	order.PutUint32(b[p+20:], 40)
	order.PutUint32(b[16:], 3)
	order.PutUint32(b[20:], order.Uint32(b[20:])+24)
	copy(b[4160:], "meaningful string pool ending in zero bytes")
	clear(b[4196:])
	return b, p
}

func TestRemovalSymbolExtent(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, be} {
		for _, is64 := range []bool{false, true} {
			original, _ := removalImage(t, order, is64)
			signed, err := SignBytes(context.Background(), original, SignOptions{Identifier: "removal"})
			if err != nil {
				t.Fatal(err)
			}
			im, err := parseImage(signed)
			if err != nil {
				t.Fatal(err)
			}
			// Preserve the signed mapping size, including sizes unlike the
			// signer's rounded default. The final four string bytes are real.
			if is64 {
				order.PutUint64(signed[im.linkedit+32:], 65536)
				order.PutUint64(original[im.linkedit+32:], 65536)
			} else {
				order.PutUint32(signed[im.linkedit+28:], 65536)
				order.PutUint32(original[im.linkedit+28:], 65536)
			}
			before := bytes.Clone(signed)
			got, err := RemoveSignatureBytes(context.Background(), signed)
			if err != nil {
				t.Fatal(err)
			}
			assertAppleBytes(t, got, original)
			if !bytes.Equal(signed, before) {
				t.Fatal("mutated signed input")
			}
			got[4096] ^= 1
			if !bytes.Equal(signed, before) {
				t.Fatal("returned alias of signed input")
			}
		}
	}
}

func TestRemovalCommandRelocation(t *testing.T) {
	b, err := SignBytes(context.Background(), syntheticMachO(binary.LittleEndian, true), SignOptions{Identifier: "relocation"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := RemoveSignatureBytes(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	im, _ := parseImage(b)
	command := bytes.Clone(b[im.sigCommand : im.sigCommand+16])
	copy(b[im.header+16:im.sigCommand+16], b[im.header:im.sigCommand])
	copy(b[im.header:], command)
	got, err := RemoveSignatureBytes(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	assertAppleBytes(t, got, want)
}

func TestRemovalRejectsUnsafeRanges(t *testing.T) {
	original, sym := removalImage(t, binary.LittleEndian, true)
	base, err := SignBytes(context.Background(), original, SignOptions{Identifier: "ranges"})
	if err != nil {
		t.Fatal(err)
	}
	im, _ := parseImage(base)
	o := binary.LittleEndian
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"filetype", func(b []byte) []byte { o.PutUint32(b[12:], 1); return b }},
		{"missing-linkedit", func(b []byte) []byte { b[im.linkedit+8] = 'X'; return b }},
		{"trailer-8", func(b []byte) []byte { return append(b, make([]byte, 8)...) }},
		{"signature-before-linkedit", func(b []byte) []byte {
			o.PutUint64(b[im.linkedit+40:], uint64(im.sigOffset)+1)
			o.PutUint64(b[im.linkedit+48:], 0)
			return b
		}},
		{"short-symbol-command", func(b []byte) []byte {
			end := 32 + int(o.Uint32(b[20:]))
			copy(b[sym+8:], b[sym+24:end])
			o.PutUint32(b[sym+4:], 8)
			o.PutUint32(b[20:], o.Uint32(b[20:])-16)
			return b
		}},
		{"duplicate-symbol-command", func(b []byte) []byte {
			end := 32 + int(o.Uint32(b[20:]))
			copy(b[end:], b[sym:sym+24])
			o.PutUint32(b[20:], o.Uint32(b[20:])+24)
			o.PutUint32(b[16:], o.Uint32(b[16:])+1)
			return b
		}},
		{"string-overflow", func(b []byte) []byte { o.PutUint32(b[sym+16:], 0xfffffff0); o.PutUint32(b[sym+20:], 32); return b }},
		{"string-in-signature", func(b []byte) []byte { o.PutUint32(b[sym+20:], 128); return b }},
		{"string-in-header", func(b []byte) []byte { o.PutUint32(b[sym+16:], 20); return b }},
		{"symbol-count-overflow", func(b []byte) []byte { o.PutUint32(b[sym+12:], 0xffffffff); return b }},
		{"symbols-before-linkedit", func(b []byte) []byte { o.PutUint32(b[sym+8:], 1024); return b }},
		{"symbols-in-padding", func(b []byte) []byte { o.PutUint32(b[sym+8:], 4192); o.PutUint32(b[sym+12:], 1); return b }},
		{"empty-strings-before-linkedit", func(b []byte) []byte {
			o.PutUint64(b[im.linkedit+40:], uint64(im.sigOffset))
			o.PutUint64(b[im.linkedit+48:], uint64(im.sigSize))
			o.PutUint32(b[sym+8:], 0)
			o.PutUint32(b[sym+12:], 0)
			o.PutUint32(b[sym+16:], im.sigOffset-8)
			o.PutUint32(b[sym+20:], 0)
			return b
		}},
		{"empty-strings-overlap-commands", func(b []byte) []byte {
			end := uint32(32) + o.Uint32(b[20:])
			o.PutUint64(b[im.linkedit+40:], 0)
			o.PutUint32(b[im.sigCommand+8:], end)
			o.PutUint32(b[im.sigCommand+12:], uint32(len(b))-end)
			o.PutUint32(b[sym+8:], 0)
			o.PutUint32(b[sym+12:], 0)
			o.PutUint32(b[sym+16:], end-4)
			o.PutUint32(b[sym+20:], 0)
			return b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.edit(bytes.Clone(base))
			before := bytes.Clone(b)
			if out, err := RemoveSignatureBytes(context.Background(), b); err == nil || out != nil {
				t.Fatal("unsafe removal accepted", len(out), err)
			}
			if !bytes.Equal(before, b) {
				t.Fatal("failed removal mutated input")
			}
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if err := RemoveSignature(context.Background(), path); err == nil {
				t.Fatal("path removal accepted")
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, before) {
				t.Fatal("failed removal changed file", err)
			}
		})
	}
}

func TestRemovalPreservesUnsignedAndNoSymbols(t *testing.T) {
	for _, signed := range []bool{false, true} {
		b := syntheticMachO(binary.LittleEndian, true)
		if signed {
			var err error
			b, err = SignBytes(context.Background(), b, SignOptions{Identifier: "no-symbols"})
			if err != nil {
				t.Fatal(err)
			}
		}
		im, _ := parseImage(b)
		end := len(b)
		if signed {
			end = int(im.sigOffset)
		}
		got, err := RemoveSignatureBytes(context.Background(), b)
		if err != nil || len(got) != end {
			t.Fatal(len(got), end, err)
		}
		if !signed && !bytes.Equal(got, b) {
			t.Fatal("unsigned bytes changed")
		}
	}
	// A failure in a later fat slice must preserve all original bytes on disk.
	b := fixture(t, "adhoc-universal")
	c, _ := parseContainer(b)
	s := c.slices[1]
	s.image.order.PutUint32(b[s.offset+12:], 1)
	path := filepath.Join(t.TempDir(), "fat")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSignature(context.Background(), path); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, b) {
		t.Fatal("later slice failure changed file", err)
	}
}

func TestRemovalAST(t *testing.T) {
	b, err := os.ReadFile("../../spec/apple-removal.json")
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Targets map[string]map[string]struct {
			Integers map[string]int `json:"integers"`
			Members  map[string]int `json:"members"`
			Kinds    map[string]int `json:"ast_kinds"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(b, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Targets) != 2 {
		t.Fatal("missing architecture AST")
	}
	for target, facts := range record.Targets {
		remove, fat := facts["remove_signature_space"], facts["code_sign_deallocate"]
		if len(facts) != 4 || remove.Integers["12"] == 0 || remove.Integers["7"] == 0 || remove.Members["strsize"] == 0 || remove.Members["vmsize"] != 0 || fat.Integers["14"] == 0 || fat.Kinds["ForStmt"] == 0 {
			t.Fatal("incomplete deallocation AST", target)
		}
	}
}
