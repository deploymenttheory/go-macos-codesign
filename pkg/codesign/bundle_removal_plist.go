package codesign

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"

	"howett.net/plist"
)

// Resource bounds are operational limits, not evidence of an invalid native
// dictionary. Never turn their errors into a raw-plist removal decision.
type bundlePlistLimitError struct{ error }

func (e *bundlePlistLimitError) Unwrap() error { return e.error }

func plistLimit(reason string) error {
	return &bundlePlistLimitError{malformed("bundle plist %s limit", reason)}
}

// The strict parser predates permissive removal. Some of its rejections are
// representation limits rather than proof that Apple's parser returns no dict.
func plistRestriction(removal bool, reason string) error {
	if removal {
		return unsupported(reason)
	}
	return malformed("%s", reason)
}

// Removal keeps the acquired raw URL when native dictionary interpretation
// fails. It must still distinguish unsupported formats and resource limits.
func decodeRemovalPlist(data []byte) (map[string]any, error) {
	if len(data) > maxBundlePlist {
		return nil, plistLimit("size")
	}
	if len(data) == 0 {
		return nil, nil
	}
	var values map[string]any
	var err error
	if bytes.HasPrefix(data, []byte("bplist")) {
		values, err = decodeBinaryBundlePlistMode(data, true)
	} else {
		data, err = removalPlistText(data)
		if err != nil {
			return nil, err
		}
		text := bytes.TrimSpace(data)
		if len(text) > 0 && text[0] == '<' {
			err = boundRemovalXML(text)
		} else {
			err = boundRemovalOpenStep(text)
		}
		if err == nil {
			var value any
			var format int
			format, err = plist.Unmarshal(data, &value)
			if err == nil && format != plist.GNUStepFormat {
				values, _ = value.(map[string]any)
			}
		}
	}
	var limit *bundlePlistLimitError
	if errors.As(err, &limit) || errors.Is(err, ErrUnsupported) {
		return nil, err
	}
	// Syntax failures and non-dictionary roots produce no executable keys. This
	// policy applies only to removal; signing and verification retain strict parsing.
	return values, nil
}

// Bound the first XML value that CoreFoundation interprets. Its historical and
// live parsers ignore subsequent roots/trailing text, including the plist close.
func boundRemovalXML(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth, count, valueDepth := 0, 0, 0
	for {
		token, err := decoder.Token()
		if err != nil {
			var syntax *xml.SyntaxError
			if !errors.Is(err, io.EOF) && !errors.As(err, &syntax) {
				return unsupported("removal plist XML encoding: " + err.Error())
			}
			return malformed("removal plist XML: %v", err)
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			count++
			if depth > maxBundlePlistDepth || count > maxBundlePlistValues {
				return plistLimit("complexity")
			}
			if valueDepth == 0 && t.Name.Local != "plist" {
				valueDepth = depth
			}
		case xml.EndElement:
			if depth == valueDepth || depth == 1 {
				return nil
			}
			depth--
		}
	}
}

// OpenStep has no shared references. Count containers and scalar/key tokens
// before the dependency allocates a graph; strings/comments/data are opaque.
// The decoder still owns grammar validation, escaping and duplicate-key order.
func boundRemovalOpenStep(data []byte) error {
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
		if depth > maxBundlePlistDepth || count > maxBundlePlistValues {
			return plistLimit("complexity")
		}
	}
	return nil
}
