package codesign

import (
	"bytes"
	"context"
)

// Apple emits indefinite-length BER for the four outer CMS containers. Only
// those envelopes are rewritten for encoding/asn1; certificate and signed
// attribute encodings remain untouched and must pass the strict DER decoder.
type cmsBERValue struct {
	tag          byte
	raw, content []byte
}

func readCMSBER(data []byte, depth int, budget *int) (cmsBERValue, []byte, error) {
	value, err := readCMSBERRange(codeSource{context.Background(), byteOutput(data)}, 0, uint64(len(data)), depth, budget)
	if err != nil {
		return cmsBERValue{}, nil, err
	}
	return cmsBERValue{value.tag, data[:value.length], data[value.content : value.content+value.contentSize]}, data[value.length:], nil
}

func cmsBERChildren(data []byte, tag byte, budget *int) ([]cmsBERValue, error) {
	v, rest, err := readCMSBER(data, 0, budget)
	if err != nil {
		return nil, err
	}
	if v.tag != tag || len(rest) != 0 {
		return nil, malformed("CMS BER container")
	}
	var children []cmsBERValue
	for rest = v.content; len(rest) > 0; {
		var child cmsBERValue
		child, rest, err = readCMSBER(rest, 0, budget)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	return children, nil
}

// cmsEnvelopeFields borrows the original field encodings. Verification must not
// rebuild the complete message just to remove its four BER container headers.
func cmsEnvelopeFields(data []byte) ([]byte, []cmsBERValue, error) {
	if len(data) > 16<<20 {
		return nil, nil, malformed("CMS size limit")
	}
	budget := 4096
	outer, err := cmsBERChildren(data, 0x30, &budget)
	if err != nil {
		return nil, nil, err
	}
	if len(outer) != 2 {
		return nil, nil, malformed("CMS ContentInfo fields")
	}
	wrapped, err := cmsBERChildren(outer[1].raw, 0xa0, &budget)
	if err != nil {
		return nil, nil, err
	}
	if len(wrapped) != 1 {
		return nil, nil, malformed("CMS explicit content")
	}
	fields, err := cmsBERChildren(wrapped[0].raw, 0x30, &budget)
	if err != nil {
		return nil, nil, err
	}
	if len(fields) < 4 || len(fields) > 6 || fields[2].tag != 0x30 {
		return nil, nil, malformed("CMS SignedData fields")
	}
	return outer[0].raw, fields, nil
}

// Encoding a new timestamped message still needs owned DER envelope bytes.
// Decoding instead uses cmsEnvelopeFields and preserves borrowed DER fields.
func cmsEnvelopeDER(data []byte) ([]byte, error) {
	oid, fields, err := cmsEnvelopeFields(data)
	if err != nil {
		return nil, err
	}
	var parts [][]byte
	for i, field := range fields {
		if i == 2 {
			parts = append(parts, derWrap(0x30, field.content))
		} else {
			parts = append(parts, field.raw)
		}
	}
	return derSequence(oid, derWrap(0xa0, derSequence(parts...))), nil
}

func cmsBERWrap(tag byte, parts ...[]byte) []byte {
	return append(append([]byte{tag, 0x80}, bytes.Join(parts, nil)...), 0, 0)
}
