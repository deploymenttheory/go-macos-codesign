package codesign

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

// A BOM selects the text codec before CoreFoundation inspects XML declarations.
// Convert only for interpretation: the acquired plist and its raw URL stay intact.
func removalPlistText(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte{0xff, 0xfe, 0, 0}) || bytes.HasPrefix(data, []byte{0, 0, 0xfe, 0xff}) {
		return nil, unsupported("removal plist UTF-32 encoding")
	}
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		order = binary.LittleEndian
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		order = binary.BigEndian
	}
	if order != nil {
		var converted []byte
		// CF's UTF-16 to UTF-8 conversion retains the convertible prefix. An
		// unmatched surrogate or incomplete final code unit terminates it.
		for i := 2; i+1 < len(data); i += 2 {
			r := rune(order.Uint16(data[i:]))
			if utf16.IsSurrogate(r) {
				if r >= 0xdc00 || i+3 >= len(data) {
					break
				}
				low := rune(order.Uint16(data[i+2:]))
				if low < 0xdc00 || low > 0xdfff {
					break
				}
				r = utf16.DecodeRune(r, low)
				i += 2
			}
			if len(converted)+utf8.RuneLen(r) > maxBundlePlist {
				return nil, plistLimit("decoded text size")
			}
			converted = utf8.AppendRune(converted, r)
		}
		data = converted
		// The native parser skips the declaration after BOM-based conversion.
		// Remove it from the interpretation buffer so encoding/xml does not
		// attempt to select the declared codec for already converted UTF-8.
		if bytes.HasPrefix(data, []byte("<?xml")) {
			if end := bytes.Index(data, []byte("?>")); end >= 0 {
				data = data[end+2:]
			}
		}
	} else {
		data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, unsupported("removal plist text encoding")
	}
	return data, nil
}
