package plist

import (
	"bytes"
	"unicode/utf8"
)

// Native ISO-2022-JP recognizes escapes at character boundaries. Unknown and
// incomplete escapes remain data in the current state; EOF need not reset it.
func iso2022JPText(data []byte) ([]byte, error) {
	var converted []byte
	state, units := 0, 0
	trailingBytes, lastState := 0, 0
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b == 0x1b && len(data)-i >= 3 {
			next, size := -1, 3
			switch data[i+1] {
			case '(':
				switch data[i+2] {
				case 'B', 'H':
					next = 0
				case 'J':
					next = 1
				case 'I':
					next = 2
				}
			case ')':
				if data[i+2] == 'I' {
					next = 2
				}
			case '$':
				switch data[i+2] {
				case '@', 'B', 'D':
					next = 3
				case '(':
					if len(data)-i >= 4 && data[i+3] == 'D' {
						next, size = 4, 4
					}
				}
			}
			if next >= 0 {
				trailingBytes += size
				state = next
				i += size - 1
				continue
			}
		}
		var r rune
		if state < 3 {
			r = iso2022JPSingles[state][b]
		} else {
			i++
			if i == len(data) {
				return nil, malformed("incomplete declared ISO-2022-JP pair")
			}
			low := byte(0x21)
			if state == 4 {
				low = 0xa1
			}
			trail := data[i]
			if b < low || b-low >= 94 || trail < low || trail-low >= 94 {
				return nil, malformed("invalid declared ISO-2022-JP pair")
			}
			r = iso2022JPPairs[state-3][b-low][trail-low]
		}
		if r < 0 {
			return nil, malformed("undefined declared ISO-2022-JP character")
		}
		if len(converted)+utf8.RuneLen(r) > MaxSize {
			return nil, plistLimit("decoded text size")
		}
		converted = utf8.AppendRune(converted, r)
		units++ // Every native mapping in this qualified family is one BMP unit.
		trailingBytes, lastState = 0, state
	}
	// The native caller supplies max(504, decoded units) UTF-16 slots. Once
	// exactly full, its loop cannot consume trailing state escapes, except a
	// single ESC(B terminator consumed with the final non-ASCII-state character.
	if units >= 504 && trailingBytes > 0 && (trailingBytes != 3 || lastState == 0 || !bytes.HasSuffix(data, []byte("\x1b(B"))) {
		return nil, malformed("native ISO-2022-JP trailing escape at full conversion buffer")
	}
	return converted, nil
}
