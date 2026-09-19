package codesign

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"howett.net/plist"
)

func derWrap(tag byte, data []byte) []byte {
	out := []byte{tag}
	if len(data) < 128 {
		out = append(out, byte(len(data)))
	} else {
		var buf [8]byte
		n := uint64(len(data))
		i := len(buf)
		for n > 0 {
			i--
			buf[i] = byte(n)
			n >>= 8
		}
		out = append(out, 0x80|byte(len(buf)-i))
		out = append(out, buf[i:]...)
	}
	return append(out, data...)
}

func entitlementDER(v any, depth int) ([]byte, error) {
	if depth > 128 {
		return nil, malformed("entitlement nesting limit")
	}
	switch x := v.(type) {
	case bool:
		if x {
			return []byte{1, 1, 255}, nil
		}
		return []byte{1, 1, 0}, nil
	case string:
		return derWrap(12, []byte(x)), nil
	case int64:
		return asn1.Marshal(x)
	case uint64:
		if x > 1<<63-1 {
			return nil, fmt.Errorf("entitlement integer exceeds signed 64-bit range")
		}
		return asn1.Marshal(int64(x))
	case []any:
		var data []byte
		for _, item := range x {
			b, err := entitlementDER(item, depth+1)
			if err != nil {
				return nil, err
			}
			data = append(data, b...)
		}
		return derWrap(0x30, data), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var data []byte
		for _, k := range keys {
			val, err := entitlementDER(x[k], depth+1)
			if err != nil {
				return nil, err
			}
			pair := append(derWrap(12, []byte(k)), val...)
			data = append(data, derWrap(0x30, pair)...)
		}
		return derWrap(0xb0, data), nil
	default:
		return nil, unsupported(fmt.Sprintf("entitlement value type %T", v))
	}
}

// EncodeEntitlements returns XML and Apple's versioned DER entitlement payloads.
// XML inputs retain their bytes. Binary plists are converted to XML.
func EncodeEntitlements(input []byte) ([]byte, []byte, error) {
	if len(input) > 16<<20 {
		return nil, nil, malformed("entitlements size limit")
	}
	var values map[string]any
	_, err := plist.Unmarshal(input, &values)
	if err != nil {
		return nil, nil, fmt.Errorf("entitlements: %w", err)
	}
	if values == nil {
		return nil, nil, malformed("entitlements must be a dictionary")
	}
	encoded, err := entitlementDER(values, 0)
	if err != nil {
		return nil, nil, err
	}
	var xml strings.Builder
	xml.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n")
	entitlementXML(&xml, values, 0)
	xml.WriteString("</plist>\n")
	xmlBytes := []byte(xml.String())
	if !bytes.HasPrefix(input, []byte("bplist")) {
		xmlBytes = bytes.Clone(input)
	}
	return xmlBytes, derWrap(0x70, append([]byte{2, 1, 1}, encoded...)), nil
}

var plistEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// The input has already passed EncodeEntitlements. Only boolean true sets a
// flag; an integer or a string with a truth-like value has no such meaning.
func entitlementExecFlags(xml []byte) uint64 {
	var values map[string]any
	_, _ = plist.Unmarshal(xml, &values)
	var flags uint64
	for key, bit := range map[string]uint64{
		"get-task-allow":                            0x10,
		"run-unsigned-code":                         0x10,
		"com.apple.private.cs.debugger":             0x20,
		"dynamic-codesigning":                       0x40,
		"com.apple.private.skip-library-validation": 0x80,
		"com.apple.private.amfi.can-load-cdhash":    0x100,
		"com.apple.private.amfi.can-execute-cdhash": 0x200,
	} {
		if enabled, ok := values[key].(bool); ok && enabled {
			flags |= bit
		}
	}
	return flags
}

func entitlementXML(out *strings.Builder, v any, depth int) {
	indent := strings.Repeat("\t", depth)
	element := func(tag, value string) {
		out.WriteString(indent + "<" + tag + ">" + plistEscape.Replace(value) + "</" + tag + ">\n")
	}
	switch x := v.(type) {
	case string:
		element("string", x)
	case int64:
		element("integer", strconv.FormatInt(x, 10))
	case uint64:
		element("integer", strconv.FormatUint(x, 10))
	case bool:
		if x {
			out.WriteString(indent + "<true/>\n")
		} else {
			out.WriteString(indent + "<false/>\n")
		}
	case []any:
		if len(x) == 0 {
			out.WriteString(indent + "<array/>\n")
			return
		}
		out.WriteString(indent + "<array>\n")
		for _, item := range x {
			entitlementXML(out, item, depth+1)
		}
		out.WriteString(indent + "</array>\n")
	case map[string]any:
		if len(x) == 0 {
			out.WriteString(indent + "<dict/>\n")
			return
		}
		out.WriteString(indent + "<dict>\n")
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out.WriteString(indent + "\t<key>" + plistEscape.Replace(k) + "</key>\n")
			entitlementXML(out, x[k], depth+1)
		}
		out.WriteString(indent + "</dict>\n")
	}
}
