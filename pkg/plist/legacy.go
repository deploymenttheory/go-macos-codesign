package plist

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// Selection follows encodingForXMLData's byte scan, before XML parsing. Only an
// exact initial '<?xml' and 'encoding=' select a charset; quotes can be either
// kind and the keyword need not be a complete attribute name. BOMs take priority.
func declaredEncoding(data []byte) (string, bool) {
	if !bytes.HasPrefix(data, []byte("<?xml")) {
		return "", false
	}
	for i := 5; i < len(data); i++ {
		if data[i] == '?' || data[i] == '>' {
			break
		}
		if !bytes.HasPrefix(data[i:], []byte("encoding=")) {
			continue
		}
		value := data[i+9:]
		if len(value) == 0 || (value[0] != '\'' && value[0] != '"') {
			break
		}
		if end := bytes.IndexByte(value[1:], value[0]); end >= 0 {
			return string(value[1 : 1+end]), true
		}
		break
	}
	return "", false
}

func declaredText(data []byte) ([]byte, error) {
	name, selected := declaredEncoding(data)
	if !selected {
		return data, nil
	}
	// Qualified IANA names are ASCII. Unicode folding would turn, for example,
	// a Kelvin sign into 'k' and silently admit an unqualified KOI8 spelling.
	for i := range len(name) {
		if name[i] >= utf8.RuneSelf {
			return nil, unsupported("removal plist text encoding: " + name)
		}
	}
	name = strings.ToLower(name)
	if name == "utf-8" || name == "utf8" {
		return data, nil
	}
	// The native property-list caller treats encoding zero as failure, including
	// the MacRoman result. This does not reject MacRoman in other CF consumers.
	switch name {
	case "macintosh", "mac", "macroman", "x-mac-roman":
		return nil, malformed("invalid declared property-list encoding")
	}
	table, ok := legacyCharsets[name]
	if !ok {
		return nil, unsupported("removal plist text encoding: " + name)
	}
	var converted []byte
	for _, b := range data {
		r := rune(b)
		if b >= 128 {
			r = table[b-128]
		}
		if r < 0 {
			return nil, malformed("invalid byte in declared property-list encoding")
		}
		if len(converted)+utf8.RuneLen(r) > MaxSize {
			return nil, plistLimit("decoded text size")
		}
		converted = utf8.AppendRune(converted, r)
	}
	return converted, nil
}

// Neutralize the initial declaration after codec selection, preserving XML
// dispatch. Removing it outright would incorrectly admit an OpenStep body.
// Prevent encoding/xml from making a second encoding decision. This buffer is
// only for interpretation; an incomplete instruction remains a parser error.
func neutralDeclaration(data []byte) []byte {
	text := bytes.TrimLeft(data, " \t\r\n\v\f")
	if bytes.HasPrefix(text, []byte("<?xml")) {
		if end := bytes.Index(text, []byte("?>")); end >= 0 {
			return append([]byte("<?xml?>"), text[end+2:]...)
		}
	}
	return data
}
