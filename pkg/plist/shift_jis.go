package plist

import "unicode/utf8"

// Shift-JIS is stateless but the two native families have different mappings.
// Convert the complete input, including suffix bytes outside the parsed root.
// Undefined pairs and an incomplete final lead are format failures, not U+FFFD.
func shiftJISText(data []byte, family int) ([]byte, error) {
	var converted []byte
	for i := 0; i < len(data); i++ {
		b := data[i]
		r := shiftJISSingles[family][b]
		row := -1
		if b >= 0x81 && b <= 0x9f {
			row = int(b) - 0x81
		} else if b >= 0xe0 && b <= 0xfc {
			row = int(b) - 0xe0 + 31
		}
		if row >= 0 {
			i++
			if i == len(data) {
				return nil, malformed("incomplete declared Shift-JIS sequence")
			}
			r = shiftJISPairs[family][row][data[i]]
		}
		if r < 0 {
			return nil, malformed("invalid declared Shift-JIS sequence")
		}
		if len(converted)+utf8.RuneLen(r) > MaxSize {
			return nil, plistLimit("decoded text size")
		}
		converted = utf8.AppendRune(converted, r)
	}
	return converted, nil
}
