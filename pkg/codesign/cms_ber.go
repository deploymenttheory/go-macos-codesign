package codesign

import "bytes"

// Apple emits indefinite-length BER for the four outer CMS containers. Only
// those envelopes are rewritten for encoding/asn1; certificate and signed
// attribute encodings remain untouched and must pass the strict DER decoder.
type cmsBERValue struct {
	tag          byte
	raw, content []byte
}

func readCMSBER(data []byte, depth int, budget *int) (cmsBERValue, []byte, error) {
	*budget--
	if depth > 32 || *budget < 0 || len(data) < 2 || data[0] == 0 || data[0]&31 == 31 {
		return cmsBERValue{}, nil, malformed("CMS BER tag, depth, or element limit")
	}
	header, length := 2, uint64(data[1])
	if length == 128 {
		if data[0]&0x20 == 0 {
			return cmsBERValue{}, nil, malformed("primitive indefinite CMS BER")
		}
		rest := data[2:]
		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				end := len(data) - len(rest)
				return cmsBERValue{data[0], data[:end+2], data[2:end]}, rest[2:], nil
			}
			var err error
			_, rest, err = readCMSBER(rest, depth+1, budget)
			if err != nil {
				return cmsBERValue{}, nil, err
			}
		}
	}
	if length > 128 {
		n := int(length & 127)
		if n > 4 || len(data) < 2+n || data[2] == 0 {
			return cmsBERValue{}, nil, malformed("CMS BER length")
		}
		length = 0
		for _, b := range data[2 : 2+n] {
			length = length<<8 | uint64(b)
		}
		if length < 128 {
			return cmsBERValue{}, nil, malformed("nonminimal CMS BER length")
		}
		header += n
	}
	if length > uint64(len(data)-header) {
		return cmsBERValue{}, nil, malformed("truncated CMS BER")
	}
	end := header + int(length)
	return cmsBERValue{data[0], data[:end], data[header:end]}, data[end:], nil
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

func cmsEnvelopeDER(data []byte) ([]byte, error) {
	if len(data) > 16<<20 {
		return nil, malformed("CMS size limit")
	}
	budget := 4096
	outer, err := cmsBERChildren(data, 0x30, &budget)
	if err != nil {
		return nil, err
	}
	if len(outer) != 2 {
		return nil, malformed("CMS ContentInfo fields")
	}
	wrapped, err := cmsBERChildren(outer[1].raw, 0xa0, &budget)
	if err != nil {
		return nil, err
	}
	if len(wrapped) != 1 {
		return nil, malformed("CMS explicit content")
	}
	fields, err := cmsBERChildren(wrapped[0].raw, 0x30, &budget)
	if err != nil {
		return nil, err
	}
	if len(fields) < 4 || len(fields) > 6 || fields[2].tag != 0x30 {
		return nil, malformed("CMS SignedData fields")
	}
	var parts [][]byte
	for i, field := range fields {
		if i == 2 {
			parts = append(parts, derWrap(0x30, field.content))
		} else {
			parts = append(parts, field.raw)
		}
	}
	return derSequence(outer[0].raw, derWrap(0xa0, derSequence(parts...))), nil
}

func cmsBERWrap(tag byte, parts ...[]byte) []byte {
	return append(append([]byte{tag, 0x80}, bytes.Join(parts, nil)...), 0, 0)
}
