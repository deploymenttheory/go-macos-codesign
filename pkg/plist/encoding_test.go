package plist

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func utf16Input(s string) []byte {
	b := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

// These direct conversion checks move with the implementation; public codesign
// tests still independently require the same selection and mutation effects.
func TestNativeTextPrefix(t *testing.T) {
	for _, units := range [][]byte{{0, 0xd8}, {0, 0xdc}, {0, 0xd8, 'x', 0}} {
		data := append(utf16Input("prefix"), units...)
		got, err := nativeText(data)
		if err != nil || string(got) != "prefix" {
			t.Fatal(got, err)
		}
	}
	if got, err := nativeText(utf16Input(`<?xml incomplete`)); err != nil || string(got) != `<?xml incomplete` {
		t.Fatal(got, err)
	}
}
