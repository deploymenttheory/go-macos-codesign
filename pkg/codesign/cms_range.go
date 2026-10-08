package codesign

import (
	"errors"
	"io"
	"math"
)

// cmsBERRange identifies the original bytes without retaining a payload-sized
// buffer. Offsets are relative to the held CMS source, including its base.
type cmsBERRange struct {
	tag                  byte
	offset, length       uint64
	content, contentSize uint64
}

// cmsBERHeader reads at most six bytes at a time. A definite-length value is
// bounded without reading its payload; an indefinite value visits child headers
// until its own end marker. Authenticated DER bytes are never re-encoded.
func cmsBERHeader(source codeSource, at, end uint64, p []byte) error {
	if err := source.ctx.Err(); err != nil {
		return err
	}
	if source.source.offset < 0 || source.source.size < 0 || source.source.size > math.MaxInt64-source.source.offset ||
		end > uint64(source.source.size) || at > end || uint64(len(p)) > end-at {
		return malformed("CMS BER source range")
	}
	n, err := source.source.reader.ReadAt(p, source.source.offset+int64(at))
	if n != len(p) {
		return errors.Join(io.ErrUnexpectedEOF, err, source.ctx.Err())
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.Join(err, source.ctx.Err())
	}
	return source.ctx.Err()
}

func readCMSBERRange(source codeSource, at, end uint64, depth int, budget *int) (cmsBERRange, error) {
	*budget--
	if depth > 32 || *budget < 0 || at > end || end-at < 2 {
		return cmsBERRange{}, malformed("CMS BER tag, depth, or element limit")
	}
	var header [6]byte
	if err := cmsBERHeader(source, at, end, header[:2]); err != nil {
		return cmsBERRange{}, err
	}
	if header[0] == 0 || header[0]&31 == 31 {
		return cmsBERRange{}, malformed("CMS BER tag, depth, or element limit")
	}
	value := cmsBERRange{tag: header[0], offset: at, content: at + 2}
	length := uint64(header[1])
	if length == 128 {
		if value.tag&0x20 == 0 {
			return cmsBERRange{}, malformed("primitive indefinite CMS BER")
		}
		for next := value.content; ; {
			if err := cmsBERHeader(source, next, end, header[:2]); err != nil {
				return cmsBERRange{}, err
			}
			if header[0] == 0 && header[1] == 0 {
				value.length, value.contentSize = next+2-at, next-value.content
				return value, nil
			}
			child, err := readCMSBERRange(source, next, end, depth+1, budget)
			if err != nil {
				return cmsBERRange{}, err
			}
			next += child.length
		}
	}
	if length > 128 {
		n := int(length & 127)
		if n > 4 {
			return cmsBERRange{}, malformed("CMS BER length")
		}
		if err := cmsBERHeader(source, value.content, end, header[2:2+n]); err != nil {
			return cmsBERRange{}, err
		}
		if header[2] == 0 {
			return cmsBERRange{}, malformed("CMS BER length")
		}
		length = 0
		for _, b := range header[2 : 2+n] {
			length = length<<8 | uint64(b)
		}
		if length < 128 {
			return cmsBERRange{}, malformed("nonminimal CMS BER length")
		}
		value.content += uint64(n)
	}
	if length > end-value.content {
		return cmsBERRange{}, malformed("truncated CMS BER")
	}
	value.contentSize, value.length = length, value.content-at+length
	return value, nil
}

func cmsBERChildRanges(source codeSource, at, length uint64, tag byte, budget *int) ([]cmsBERRange, error) {
	if source.source.size < 0 || !rangeOK(at, length, uint64(source.source.size)) {
		return nil, malformed("CMS BER container range")
	}
	v, err := readCMSBERRange(source, at, at+length, 0, budget)
	if err != nil {
		return nil, err
	}
	if v.tag != tag || v.length != length {
		return nil, malformed("CMS BER container")
	}
	var children []cmsBERRange
	end := v.content + v.contentSize
	for next := v.content; next < end; {
		child, err := readCMSBERRange(source, next, end, 0, budget)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		next += child.length
	}
	return children, nil
}

// Locate fields in the held component without reading definite-length payloads.
// The message ceiling remains until individual certificate and signer fields
// also have bounded decoders; locating them alone does not remove that limit.
func cmsEnvelopeRanges(source codeSource) (cmsBERRange, []cmsBERRange, error) {
	if source.source.size > 16<<20 {
		return cmsBERRange{}, nil, malformed("CMS size limit")
	}
	budget := 4096
	outer, err := cmsBERChildRanges(source, 0, uint64(source.source.size), 0x30, &budget)
	if err != nil {
		return cmsBERRange{}, nil, err
	}
	if len(outer) != 2 {
		return cmsBERRange{}, nil, malformed("CMS ContentInfo fields")
	}
	wrapped, err := cmsBERChildRanges(source, outer[1].offset, outer[1].length, 0xa0, &budget)
	if err != nil {
		return cmsBERRange{}, nil, err
	}
	if len(wrapped) != 1 {
		return cmsBERRange{}, nil, malformed("CMS explicit content")
	}
	fields, err := cmsBERChildRanges(source, wrapped[0].offset, wrapped[0].length, 0x30, &budget)
	if err != nil {
		return cmsBERRange{}, nil, err
	}
	if len(fields) < 4 || len(fields) > 6 || fields[2].tag != 0x30 {
		return cmsBERRange{}, nil, malformed("CMS SignedData fields")
	}
	return outer[0], fields, nil
}
