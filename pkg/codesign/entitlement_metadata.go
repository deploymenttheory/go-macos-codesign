package codesign

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// EntitlementMetadata contains reconstructed display data, not the original XML
// slot or an authorization/trust result. TextValid is false for arrays mixing
// primitive types: native XML extraction accepts these, but its text dumper does
// not. Callers must not emit Text in that case. Nil XML with a nonnil result
// denotes bound but malformed DER: neither representation is usable.
type EntitlementMetadata struct {
	XML       []byte
	Text      []byte
	TextValid bool
}

// InspectEntitlements reads version-1 DER, preferring it over XML. XML-only
// signatures use the existing bounded plist decoder. Required special-slot hashes
// are checked against the primary CodeDirectory; executable pages and CA trust
// are not checked. Alternate directories and unknown DER versions/types are
// explicitly unsupported. Absence returns (nil, nil). The decoder limits input
// to 8 MiB, nesting to 32 and values (including dictionary keys) to 100,000.
func InspectEntitlements(signature *Signature) (*EntitlementMetadata, error) {
	if signature == nil {
		return nil, ErrUnsigned
	}
	data, slot, magic := signature.find(SlotDEREntitlements), SlotDEREntitlements, MagicDEREntitlements
	if data == nil {
		data, slot, magic = signature.find(SlotEntitlements), SlotEntitlements, MagicEntitlements
	}
	if data == nil {
		return nil, nil
	}
	if len(signature.Directories) > 1 {
		return nil, unsupported("entitlement extraction with alternate CodeDirectories")
	}
	directory, err := parseDirectory(signature.find(SlotDirectory))
	if err != nil {
		return nil, err
	}
	if len(data) < 8 || len(data)-8 > maxBundlePlist || be.Uint32(data) != magic || uint64(be.Uint32(data[4:])) != uint64(len(data)) {
		return nil, malformed("entitlements blob")
	}
	storedHash := func(slot uint32) []byte {
		if slot > directory.SpecialSlots {
			return nil
		}
		offset := directory.HashOffset - slot*uint32(directory.HashSize)
		hash := directory.Raw[offset : offset+uint32(directory.HashSize)]
		if bytes.Equal(hash, make([]byte, len(hash))) {
			return nil
		}
		return hash
	}
	stored := storedHash(slot)
	if stored == nil || slot == SlotEntitlements && storedHash(SlotDEREntitlements) != nil {
		return nil, invalid("entitlements component/hash presence")
	}
	actual, _ := digest(directory.HashType, data) // parseDirectory checked the algorithm.
	if !bytes.Equal(stored, actual) {
		return nil, invalid("entitlements slot %d hash", slot)
	}
	payload := data[8:]
	if slot == SlotEntitlements {
		values, err := decodeBundlePlist(payload)
		if err != nil {
			return nil, err
		}
		encoded, err := entitlementDER(values, 0)
		if err != nil {
			return nil, err
		}
		payload = derWrap(0x70, append([]byte{2, 1, 1}, encoded...))
	}
	metadata, err := decodeEntitlementMetadata(payload)
	if slot == SlotDEREntitlements && errors.Is(err, ErrFormat) {
		// Bound but undecodable DER reaches the native text dumper, which
		// opens its destination before returning EX_DATAERR.
		return &EntitlementMetadata{}, nil
	}
	return metadata, err
}

type entitlementValue struct {
	tag      byte
	text     string
	children []entitlementValue
}

func entitlementTLV(data []byte) (asn1.RawValue, []byte, error) {
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(data, &value)
	if err != nil {
		return value, nil, malformed("entitlement DER: %v", err)
	}
	return value, rest, nil
}

func decodeEntitlementMetadata(data []byte) (*EntitlementMetadata, error) {
	if len(data) > maxBundlePlist {
		return nil, malformed("entitlement DER size limit")
	}
	outer, rest, err := entitlementTLV(data)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || outer.Class != asn1.ClassApplication || outer.Tag != 16 || !outer.IsCompound {
		return nil, malformed("entitlement DER envelope")
	}
	version, rest, err := entitlementTLV(outer.Bytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(version.FullBytes, []byte{2, 1, 1}) {
		return nil, unsupported("entitlement DER version")
	}
	count := 0
	value, rest, err := readEntitlementValue(rest, 0, &count)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || value.tag != 0xb0 {
		return nil, malformed("entitlement DER root dictionary")
	}
	var xml, text strings.Builder
	xml.WriteString(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0">`)
	valid := value.write(&xml, &text, 0)
	xml.WriteString("</plist>\n")
	metadata := &EntitlementMetadata{XML: []byte(xml.String()), TextValid: valid}
	if valid {
		metadata.Text = []byte(text.String())
	}
	return metadata, nil
}

func readEntitlementValue(data []byte, depth int, count *int) (entitlementValue, []byte, error) {
	var value entitlementValue
	*count++
	if depth > maxBundlePlistDepth || *count > maxBundlePlistValues {
		return value, nil, malformed("entitlement DER complexity limit")
	}
	raw, rest, err := entitlementTLV(data)
	if err != nil {
		return value, nil, err
	}
	// Comparing the complete leading tag also rejects alternate classes and
	// constructed primitive encodings; asn1 handles canonical lengths.
	value.tag = raw.FullBytes[0]
	switch value.tag {
	case 1:
		var flag bool
		if err := decodeDER(raw.FullBytes, &flag); err != nil {
			return value, nil, err
		}
		value.text = strconv.FormatBool(flag)
	case 2:
		var integer int64
		if err := decodeDER(raw.FullBytes, &integer); err != nil {
			return value, nil, err
		}
		value.text = strconv.FormatInt(integer, 10)
	case 12:
		if !utf8.Valid(raw.Bytes) || bytes.IndexByte(raw.Bytes, 0) >= 0 {
			return value, nil, malformed("entitlement UTF-8 string")
		}
		value.text = string(raw.Bytes)
	case 0x30, 0xb0:
		children := raw.Bytes
		lastKey := ""
		for len(children) > 0 {
			input := children
			if value.tag == 0xb0 {
				pair, next, err := entitlementTLV(children)
				if err != nil {
					return value, nil, err
				}
				if pair.FullBytes[0] != 0x30 {
					return value, nil, malformed("entitlement dictionary entry")
				}
				key, remaining, err := readEntitlementValue(pair.Bytes, depth+1, count)
				if err != nil {
					return value, nil, err
				}
				if key.tag != 12 || len(value.children) > 0 && key.text <= lastKey {
					return value, nil, malformed("entitlement dictionary keys")
				}
				lastKey = key.text
				value.children = append(value.children, key)
				input, children = remaining, next
			}
			child, remaining, err := readEntitlementValue(input, depth+1, count)
			if err != nil {
				return value, nil, err
			}
			if value.tag == 0xb0 {
				if len(remaining) != 0 {
					return value, nil, malformed("entitlement dictionary trailing value")
				}
			} else {
				children = remaining
			}
			value.children = append(value.children, child)
		}
	default:
		return value, nil, unsupported(fmt.Sprintf("entitlement DER tag %#x", value.tag))
	}
	return value, rest, nil
}

var entitlementDisplayEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

func (v entitlementValue) write(xml, text *strings.Builder, depth int) bool {
	indent := strings.Repeat("\t", depth)
	valid := true
	switch v.tag {
	case 1, 2, 12:
		tag, label := "string", "String"
		if v.tag == 1 {
			label = "Bool"
			xml.WriteString("<" + v.text + "/>")
		} else {
			if v.tag == 2 {
				tag, label = "integer", "Int"
			}
			xml.WriteString("<" + tag + ">" + entitlementDisplayEscape.Replace(v.text) + "</" + tag + ">")
		}
		text.WriteString(indent + "[" + label + "] " + v.text + "\n")
	case 0xb0:
		xml.WriteString("<dict>")
		text.WriteString(indent + "[Dict]\n")
		for i := 0; i < len(v.children); i += 2 {
			key := v.children[i].text
			xml.WriteString("<key>" + entitlementDisplayEscape.Replace(key) + "</key>")
			text.WriteString(indent + "\t[Key] " + key + "\n" + indent + "\t[Value]\n")
			valid = v.children[i+1].write(xml, text, depth+2) && valid
		}
		xml.WriteString("</dict>")
	case 0x30:
		xml.WriteString("<array>")
		text.WriteString(indent + "[Array]\n")
		var primitive byte
		for _, child := range v.children {
			if child.tag < 0x30 {
				if primitive != 0 && primitive != child.tag {
					valid = false
				}
				primitive = child.tag
			}
			valid = child.write(xml, text, depth+1) && valid
		}
		xml.WriteString("</array>")
	}
	return valid
}
