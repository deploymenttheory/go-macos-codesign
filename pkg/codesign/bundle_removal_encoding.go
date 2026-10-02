package codesign

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

// A BOM or the native unmarked heuristic selects the codec before declarations.
// Convert only for interpretation: the acquired plist and its raw URL stay intact.
func removalPlistText(data []byte) ([]byte, error) {
	var order binary.ByteOrder
	width := 2
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe, 0, 0}):
		order, width = binary.LittleEndian, 4
	case bytes.HasPrefix(data, []byte{0, 0, 0xfe, 0xff}):
		order, width = binary.BigEndian, 4
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		order = binary.LittleEndian
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		order = binary.BigEndian
	case len(data) > 2 && (data[0] == 0 || data[1] == 0):
		// Apple's unmarked heuristic skips one code unit and uses native UTF-16.
		// Both supported Mac architectures are little-endian, independent of the
		// producer host. This is deliberately not a UTF-32 or byte-order guess.
		order = binary.LittleEndian
	}
	if order != nil {
		var converted []byte
		// Both codecs ignore an incomplete final code unit. UTF-16 retains
		// the convertible prefix at an unmatched surrogate; UTF-32 instead
		// rejects the entire string if any complete scalar is invalid.
		for i := width; i+width <= len(data); i += width {
			r := rune(order.Uint16(data[i:]))
			if width == 4 {
				r = rune(order.Uint32(data[i:]))
				if !utf8.ValidRune(r) {
					return nil, nil // Native string creation fails: no executable keys.
				}
			} else if utf16.IsSurrogate(r) {
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
		// The native parser skips the declaration after wide-character conversion.
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

	if !utf8.Valid(data) {
		return nil, unsupported("removal plist text encoding")
	}
	text := bytes.TrimSpace(data)
	if bytes.IndexByte(data, 0) >= 0 && !bytes.HasPrefix(text, []byte("<")) {
		// Known invalid initial objects and tiny inputs still go through resource
		// preflight before dictionary interpretation. Other NUL contexts remain
		// explicit representation limits until separately qualified.
		if len(data) <= 2 || !removalTextStart(text) {
			return data, nil
		}
		return nil, unsupported("removal plist text encoding")
	}
	return data, nil
}
