package plist

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"howett.net/plist"
)

// CoreFoundation reads string/key bytes directly, without XML 1.0 character
// filtering or newline normalization. Keep that interpretation local to removal.
// RawToken handles markup; our bounded stack owns matching across string reads.
type nativeXML struct {
	data        []byte
	decoder     *xml.Decoder
	base, count int
	stack       []xml.Name
}

func decodeXML(data []byte) (any, error) {
	if err := boundXML(data); err != nil {
		return nil, err
	}
	p := &nativeXML{data: data, decoder: xml.NewDecoder(bytes.NewReader(data))}
	for {
		token, start, err := p.token()
		if err != nil {
			return nil, err
		}
		if element, ok := token.(xml.StartElement); ok {
			return p.value(element, start)
		}
	}
}

// Check the complete first value before grammar interpretation allocates a
// graph. A dictionary with a missing key must not hide a later resource limit.
func boundXML(data []byte) error {
	p := &nativeXML{data: data, decoder: xml.NewDecoder(bytes.NewReader(data))}
	valueDepth := 0
	for {
		token, _, err := p.token()
		if err != nil {
			return err
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth := len(p.stack)
			if valueDepth == 0 && element.Name.Local != "plist" {
				valueDepth = depth
			}
			if element.Name.Local == "string" || element.Name.Local == "key" {
				if _, err := p.stringValue(); err != nil {
					return err
				}
				if depth == valueDepth {
					return nil
				}
			}
		case xml.EndElement:
			if len(p.stack)+1 == valueDepth || len(p.stack) == 0 {
				return nil
			}
		}
	}
}

func (p *nativeXML) offset() int { return p.base + int(p.decoder.InputOffset()) }

func (p *nativeXML) token() (xml.Token, int, error) {
	start := p.offset()
	token, err := p.decoder.RawToken()
	if err != nil {
		var syntax *xml.SyntaxError
		if errors.As(err, &syntax) && strings.HasPrefix(syntax.Msg, "illegal character code ") {
			return nil, start, unsupported("removal plist XML characters outside strings")
		}
		if !errors.Is(err, io.EOF) && !errors.As(err, &syntax) {
			return nil, start, unsupported("removal plist XML encoding: " + err.Error())
		}
		return nil, start, malformed("removal plist XML: %v", err)
	}
	switch t := token.(type) {
	case xml.StartElement:
		p.count++
		p.stack = append(p.stack, t.Name)
		if len(p.stack) > MaxDepth || p.count > MaxValues {
			return nil, start, plistLimit("complexity")
		}
	case xml.EndElement:
		if len(p.stack) == 0 || p.stack[len(p.stack)-1] != t.Name {
			return nil, start, malformed("removal plist XML mismatched close")
		}
		p.stack = p.stack[:len(p.stack)-1]
	}
	return token, start, nil
}

func (p *nativeXML) value(element xml.StartElement, start int) (any, error) {
	kind := element.Name.Local
	if kind == "string" || kind == "key" {
		return p.stringValue()
	}
	if kind != "plist" && kind != "dict" && kind != "array" {
		// Scalar interpretation remains with the existing plist codec. Traverse its
		// tokens first so malformed nesting and allocation budgets remain enforced.
		depth := len(p.stack)
		for len(p.stack) >= depth {
			if _, _, err := p.token(); err != nil {
				return nil, err
			}
		}
		var value any
		_, err := plist.Unmarshal(p.data[start:p.offset()], &value)
		return value, err
	}
	dict := map[string]any{}
	array := []any{}
	var key string
	haveKey := false
	for {
		token, childStart, err := p.token()
		if err != nil {
			return nil, err
		}
		switch child := token.(type) {
		case xml.StartElement:
			value, err := p.value(child, childStart)
			if err != nil {
				return nil, err
			}
			if kind == "plist" {
				return value, nil
			} // Native ignores the suffix after its first value.
			if kind == "array" {
				array = append(array, value)
				continue
			}
			if child.Name.Local == "key" {
				if haveKey {
					return nil, malformed("removal plist XML missing dictionary value")
				}
				key, haveKey = value.(string), true
			} else {
				if !haveKey {
					return nil, malformed("removal plist XML missing dictionary key")
				}
				dict[key], haveKey = value, false // Native XML duplicate keys: last value wins.
			}
		case xml.EndElement:
			if haveKey {
				return nil, malformed("removal plist XML missing dictionary value")
			}
			if kind == "dict" {
				return dict, nil
			}
			if kind == "array" {
				return array, nil
			}
			return nil, nil
		case xml.CharData:
			if len(bytes.TrimSpace(child)) != 0 {
				return nil, malformed("removal plist XML container text")
			}
		}
	}
}

func (p *nativeXML) stringValue() (string, error) {
	pos := p.offset()
	var value []byte
	// RawToken keeps the synthetic closing token for a self-closing element.
	if !bytes.HasSuffix(p.data[:pos], []byte("/>")) {
		for pos < len(p.data) {
			switch p.data[pos] {
			case '<':
				if bytes.HasPrefix(p.data[pos:], []byte("<![CDATA[")) {
					end := bytes.Index(p.data[pos+9:], []byte("]]>"))
					if end < 0 {
						return "", malformed("unterminated removal plist CDATA")
					}
					value = append(value, p.data[pos+9:pos+9+end]...)
					pos += 12 + end
					continue
				}
				// Only the matching close is permitted: comments, PIs and child elements
				// inside a native plist string are syntax errors, not discarded content.
				if !bytes.HasPrefix(p.data[pos:], []byte("</")) {
					return "", malformed("removal plist string markup")
				}
				p.base = pos
				p.decoder = xml.NewDecoder(bytes.NewReader(p.data[pos:]))
				_, _, err := p.token()
				if err != nil {
					return "", err
				}
				if !utf8.Valid(value) {
					return "", malformed("invalid UTF-8 property-list string")
				}
				return string(value), nil
			case '&':
				end := bytes.IndexByte(p.data[pos:], ';')
				if end < 0 {
					return "", malformed("unterminated removal plist entity")
				}
				r, err := nativeXMLEntity(string(p.data[pos+1 : pos+end]))
				if err != nil {
					return "", err
				}
				value = utf8.AppendRune(value, r)
				pos += end + 1
			default:
				end := bytes.IndexAny(p.data[pos:], "<&")
				if end < 0 {
					end = len(p.data) - pos
				}
				value = append(value, p.data[pos:pos+end]...)
				pos += end
			}
		}
		return "", malformed("unterminated removal plist string")
	}
	_, _, err := p.token()
	return "", err
}

func nativeXMLEntity(entity string) (rune, error) {
	switch entity {
	case "lt":
		return '<', nil
	case "gt":
		return '>', nil
	case "amp":
		return '&', nil
	case "apos":
		return '\'', nil
	case "quot":
		return '"', nil
	}
	if !strings.HasPrefix(entity, "#") {
		return 0, malformed("unknown removal plist entity")
	}
	digits, base := entity[1:], uint32(10)
	if strings.HasPrefix(digits, "x") {
		digits, base = digits[1:], 16
	}
	var value uint32
	for _, c := range digits {
		var digit uint32
		switch {
		case c >= '0' && c <= '9':
			digit = uint32(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			digit = uint32(c-'a') + 10
		case base == 16 && c >= 'A' && c <= 'F':
			digit = uint32(c-'A') + 10
		default:
			return 0, malformed("invalid removal plist numeric entity")
		}
		if value > (utf8.MaxRune-digit)/base {
			return 0, malformed("removal plist entity scalar range")
		}
		value = value*base + digit
	}
	if !utf8.ValidRune(rune(value)) {
		return 0, malformed("removal plist entity surrogate")
	}
	return rune(value), nil
}
