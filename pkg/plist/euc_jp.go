package plist

import "unicode/utf8"

// Native EUC-JP accepts nonstandard trails and extensions, but rejects the 0x8f
// JIS X 0212 introducer. Use captured mappings, not conventional range checks.
// Conversion includes the entire XML suffix and never replaces invalid bytes.
func eucJPText(data []byte) ([]byte, error) {
	var converted []byte
	for i := 0; i < len(data); i++ {
		b := data[i]
		r := rune(b)
		if b >= utf8.RuneSelf {
			i++
			if i == len(data) {
				return nil, malformed("incomplete declared EUC-JP sequence")
			}
			r = eucJPPairs[b-utf8.RuneSelf][data[i]]
			if r < 0 {
				return nil, malformed("invalid declared EUC-JP sequence")
			}
		}
		if len(converted)+utf8.RuneLen(r) > MaxSize {
			return nil, plistLimit("decoded text size")
		}
		converted = utf8.AppendRune(converted, r)
	}
	return converted, nil
}
