package plist

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"howett.net/plist"
)

// DecodeDictionary validates the existing bounded XML/binary dictionary profile.
// It rejects duplicate keys and requires the XML plist wrapper. Decode provides
// native interpretation; callers choose validation appropriate to their input.
func DecodeDictionary(data []byte) (map[string]any, error) {
	if len(data) == 0 || len(data) > MaxSize {
		return nil, malformed("bundle plist size")
	}
	if bytes.HasPrefix(data, []byte("bplist")) {
		return decodeBinaryDictionary(data)
	}
	// Preflight XML nesting, element count and dictionary keys before the generic
	// plist decoder allocates its object graph.
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth, count := 0, 0
	type dictionary struct {
		depth int
		keys  map[string]bool
	}
	var dicts []dictionary
	var key strings.Builder
	inKey, rootSeen := false, false
	for {
		tok, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, malformed("bundle XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if inKey || depth == 0 && (rootSeen || t.Name.Local != "plist") {
				return nil, malformed("bundle plist XML structure")
			}
			rootSeen = true
			depth++
			count++
			if depth > MaxDepth || count > MaxValues {
				return nil, malformed("bundle plist complexity limit")
			}
			if t.Name.Local == "dict" {
				dicts = append(dicts, dictionary{depth, map[string]bool{}})
			}
			if t.Name.Local == "key" {
				if len(dicts) == 0 || dicts[len(dicts)-1].depth != depth-1 {
					return nil, malformed("misplaced bundle plist key")
				}
				inKey = true
				key.Reset()
			}
		case xml.CharData:
			if inKey {
				key.Write(t)
			} else if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return nil, malformed("text outside bundle plist")
			}
		case xml.EndElement:
			depth--
			if t.Name.Local == "key" {
				keys := dicts[len(dicts)-1].keys
				if keys[key.String()] {
					return nil, malformed("duplicate bundle plist key")
				}
				keys[key.String()] = true
				inKey = false
			}
			if t.Name.Local == "dict" && len(dicts) > 0 {
				dicts = dicts[:len(dicts)-1]
			}
		}
	}
	var m map[string]any
	if _, err := plist.Unmarshal(data, &m); err != nil {
		return nil, malformed("bundle plist: %v", err)
	}
	if m == nil {
		return nil, malformed("bundle plist must be a dictionary")
	}
	return m, nil
}
