package plist

import "unicode/utf8"

// The extension families use strict seven-bit streams, unlike the native base
// family. G2 designation survives G0 changes; a single shift consumes one scalar.
func iso2022ExtensionText(data []byte, family int) ([]byte, error) {
	var converted []byte
	state, designated, units := 0, 0, 0
	shifted, trailing := false, false
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b == 0x1b {
			if len(data)-i < 2 {
				return nil, malformed("incomplete ISO-2022 extension escape")
			}
			kind, size, next := data[i+1], 3, -1
			if kind == 'N' {
				if designated == 0 {
					return nil, malformed("ISO-2022 single shift without designation")
				}
				shifted = true
				size = 2
			} else {
				if len(data)-i < 3 {
					return nil, malformed("incomplete ISO-2022 extension escape")
				}
				end := data[i+2]
				switch kind {
				case '(':
					switch end {
					case 'B':
						next = 0
					case 'H', 'J':
						next = 1
					case 'I':
						next = 2
					}
				case '$':
					switch end {
					case '@', 'B':
						next = 3
					case 'A':
						if family == 2 {
							next = 5
						}
					case '(':
						if len(data)-i >= 4 {
							size = 4
							switch data[i+3] {
							case 'D':
								next = 4
							case 'C':
								if family == 2 {
									next = 6
								}
							}
						}
					}
				case '&':
					if end == '@' {
						next = 3
					}
				case '.':
					if family == 2 {
						switch end {
						case 'A':
							next = 7
						case 'F':
							next = 8
						}
					}
				}
				if next < 0 {
					return nil, malformed("invalid ISO-2022 extension escape")
				}
				if next >= 7 {
					designated = next
				} else {
					state = next
				}
			}
			i += size - 1
			trailing = true
			continue
		}
		if b == 0x0e || b == 0x0f {
			return nil, malformed("invalid ISO-2022 shift control")
		}
		active := state
		var r rune
		if b == '\r' || b == '\n' {
			if state != 0 && state != 1 {
				state = 0
			}
			designated, shifted = 0, false
			r = rune(b)
		} else {
			if shifted {
				active = designated
				shifted = false
			}
			switch active {
			case 0, 1:
				if b > 0x7f {
					return nil, malformed("non-seven-bit ISO-2022 character")
				}
				r = rune(b)
				if active == 1 {
					switch b {
					case '\\':
						r = 0xa5
					case '~':
						r = 0x203e
					}
				}
			case 2:
				if b < 0x21 || b > 0x5f {
					return nil, malformed("invalid ISO-2022 kana")
				}
				r = 0xff61 + rune(b-0x21)
			case 7, 8:
				if b > 0x7f {
					return nil, malformed("invalid ISO-2022 single shift")
				}
				r = rune(b) + 0x80
				if active == 8 {
					r = iso2022ExtensionGreek[b]
				}
			default:
				i++
				if i == len(data) {
					return nil, malformed("incomplete ISO-2022 extension pair")
				}
				trail := data[i]
				if b < 0x21 || b > 0x7e || trail < 0x21 || trail > 0x7e {
					return nil, malformed("invalid ISO-2022 extension pair")
				}
				r = iso2022ExtensionPairs[active-3][b-0x21][trail-0x21]
			}
		}
		if r < 0 {
			return nil, malformed("undefined ISO-2022 extension mapping")
		}
		if len(converted)+utf8.RuneLen(r) > MaxSize {
			return nil, plistLimit("decoded text size")
		}
		converted = utf8.AppendRune(converted, r)
		units++
		trailing = false
	}
	// The native ICU-backed families have no terminal-reset exception at capacity.
	if units >= 504 && trailing {
		return nil, malformed("ISO-2022 extension escape at full conversion buffer")
	}
	return converted, nil
}
