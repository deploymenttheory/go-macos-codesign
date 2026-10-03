package plist

import (
	"bytes"
	"errors"
	"strings"

	"howett.net/plist"
)

// Decode interprets the qualified native XML, binary and OpenStep profiles.
// It returns scalar and container roots without imposing an application schema.
// Syntax, unsupported representations and resource limits remain distinct errors;
// callers decide whether a syntax failure permits any operational fallback.
func Decode(data []byte) (any, error) {
	if len(data) > MaxSize {
		return nil, plistLimit("size")
	}
	if len(data) == 0 {
		return nil, malformed("empty property list")
	}
	var values any
	var err error
	if bytes.HasPrefix(data, []byte("bplist")) {
		values, err = decodeBinary(data, true)
	} else {
		data, err = nativeText(data)
		if err != nil {
			return nil, err
		}
		text := bytes.TrimSpace(data)
		if len(text) == 0 {
			return nil, malformed("property list has no root value")
		}
		if len(text) > 0 && text[0] == '<' {
			var value any
			value, err = decodeXML(text)
			values = value
		} else {
			err = boundOpenStep(text)
		}
		if err == nil && (len(text) == 0 || text[0] != '<') && nativeTextStart(text) {
			var value any
			var format int
			// The dependency has no format selector. A neutral OpenStep comment
			// with invalid XML markup forces its text parser before any user tag
			// can be mistaken for an XML document. It also prevents a second text
			// encoding guess. Only this bounded interpretation copy is prefixed.
			input := append([]byte("/*<*/"), data...)
			format, err = plist.Unmarshal(input, &value)
			if err == nil && format == plist.OpenStepFormat {
				values = value
			}
		}
	}
	if err == nil && values == nil {
		err = malformed("property list has no root value")
	}
	if err != nil && !errors.Is(err, ErrFormat) && !errors.Is(err, ErrUnsupported) {
		// Preserve classified errors; the dependency supplies ordinary syntax
		// errors which cannot carry a codesign-specific interpretation policy.
		err = malformed("%v", err)
	}
	return values, err
}

// CoreFoundation's initial XML/OpenStep object dispatch accepts these ASCII
// characters. Check after resource preflight: a malformed prefix cannot hide a
// later limit. Prevent the dependency from guessing another codec at a converted
// NUL prefix or stripping a second BOM, either of which can change selection.
func nativeTextStart(text []byte) bool {
	return len(text) == 0 || strings.ContainsRune("{(<\"'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$/:.-", rune(text[0]))
}

// OpenStep has no shared references. Count containers and scalar/key tokens
// before the dependency allocates a graph; strings/comments/data are opaque.
// The decoder still owns grammar validation, escaping and duplicate-key order.
func boundOpenStep(data []byte) error {
	depth, count := 0, 0
	word := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' && data[i] != '\r' {
				i++
			}
			word = false
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return malformed("unterminated plist comment")
			}
			i += end + 3
			word = false
		case c == '"':
			count++
			word = false
			for i++; i < len(data); i++ {
				if data[i] == '\\' {
					i++
					continue
				}
				if data[i] == '"' {
					break
				}
			}
		case c == '<':
			count++
			word = false
			for i++; i < len(data) && data[i] != '>'; i++ {
			}
		case c == '(' || c == '{':
			depth++
			count++
			word = false
		case c == ')' || c == '}':
			if depth > 0 {
				depth--
			}
			word = false
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' || c == '=' || c == ';' || c == ',':
			word = false
		default:
			if !word {
				count++
				word = true
			}
		}
		if depth > MaxDepth || count > MaxValues {
			return plistLimit("complexity")
		}
	}
	return nil
}
