package codesign

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
)

// The summaries retain only the command fields consumed by signing and
// verification. Their size does not depend on ncmds, sizeofcmds or section count.
// Diagnostic-only details stay deferred until the corresponding operation.
type symbolSummary struct {
	present, duplicate                  bool
	size                                uint32
	symbols, count, strings, stringSize uint64
}
type image struct {
	data                                    []byte     // borrowed only by the byte API; never populated for path readers
	source                                  codeSource // borrows the operation's reader and shared scratch budget
	order                                   binary.ByteOrder
	header                                  int
	headerBytes                             [32]byte
	cpu, subtype, filetype                  uint32
	commandCount, commandBytes              uint32
	sigOffset, sigSize                      uint32
	sigCommand, linkedit                    int
	linkeditKind                            uint32
	linkStart                               uint64
	textBase, textSize, firstSection        uint64
	uuidOffset                              int
	uuidSize                                uint32
	uuid                                    [16]byte
	versionPlatform, versionMin, versionSDK uint32
	buildVersionSeen, minVersionSeen        bool
	execPlatform, legacyPlatform            uint32
	strictCandidate, strictValid            bool
	symbols                                 symbolSummary
}
type slice struct {
	offset, size            uint64
	cpu, subtype, alignment uint32
	image                   *image
}
type container struct {
	data   []byte
	fat    bool
	fat64  bool
	order  binary.ByteOrder
	slices []slice
}

type rangeReader func(offset, length uint64) ([]byte, error)

func memoryRange(data []byte) rangeReader {
	return func(offset, length uint64) ([]byte, error) { return data[offset : offset+length], nil }
}

func ownedMemoryRange(data []byte) rangeReader {
	return func(offset, length uint64) ([]byte, error) {
		return bytes.Clone(data[offset : offset+length]), nil
	}
}

func parseImage(data []byte) (*image, error) {
	im, err := parseImageRange(uint64(len(data)), memoryRange(data))
	if err == nil {
		im.data = data
		im.source = codeSource{context.Background(), byteOutput(data)}
	}
	return im, err
}

func parseImageRange(length uint64, read rangeReader) (*image, error) {
	if length < 28 {
		return nil, malformed("Mach-O header")
	}
	data, err := read(0, min(length, 32))
	if err != nil {
		return nil, err
	}
	im := &image{header: 28, sigCommand: -1, linkedit: -1, uuidOffset: -1, firstSection: length}
	switch be.Uint32(data) {
	case 0xfeedface:
		im.order = be
	case 0xcefaedfe:
		im.order = binary.LittleEndian
	case 0xfeedfacf:
		im.order = be
		im.header = 32
	case 0xcffaedfe:
		im.order = binary.LittleEndian
		im.header = 32
	default:
		return nil, malformed("Mach-O magic")
	}
	if length < uint64(im.header) {
		return nil, malformed("64-bit Mach-O header")
	}
	copy(im.headerBytes[:], data)
	o := im.order
	im.cpu, im.subtype, im.filetype = o.Uint32(data[4:]), o.Uint32(data[8:]), o.Uint32(data[12:])
	im.commandCount, im.commandBytes = o.Uint32(data[16:]), o.Uint32(data[20:])
	if !rangeOK(uint64(im.header), uint64(im.commandBytes), length) || uint64(im.commandCount)*8 > uint64(im.commandBytes) {
		return nil, malformed("load command bounds")
	}
	end := uint64(im.header) + uint64(im.commandBytes)
	p := uint64(im.header)
	for i := uint32(0); i < im.commandCount; i++ {
		if p+8 > end {
			return nil, malformed("truncated load command")
		}
		command, e := read(p, 8)
		if e != nil {
			return nil, e
		}
		kind, size := o.Uint32(command), o.Uint32(command[4:])
		if size < 8 || size%4 != 0 || uint64(size) > end-p {
			return nil, malformed("load command size")
		}
		switch kind {
		case 0x1d:
			if size != 16 || im.sigCommand >= 0 {
				return nil, malformed("code signature command")
			}
			b, e := read(p+8, 8)
			if e != nil {
				return nil, e
			}
			im.sigCommand, im.sigOffset, im.sigSize = int(p), o.Uint32(b), o.Uint32(b[4:])
			if uint64(im.sigOffset) < end || !rangeOK(uint64(im.sigOffset), uint64(im.sigSize), length) {
				return nil, malformed("code signature range")
			}
		case 1, 0x19:
			base, sectionSize, field := uint64(56), uint64(68), uint64(40)
			if kind == 0x19 {
				base, sectionSize, field = 72, 80, 48
			}
			if uint64(size) < base {
				return nil, malformed("segment header")
			}
			b, e := read(p, base)
			if e != nil {
				return nil, e
			}
			name := string(bytes.TrimRight(b[8:24], "\x00"))
			var offset, segmentLength uint64
			var count uint32
			if kind == 0x19 {
				offset, segmentLength, count = o.Uint64(b[40:]), o.Uint64(b[48:]), o.Uint32(b[64:])
			} else {
				offset, segmentLength, count = uint64(o.Uint32(b[32:])), uint64(o.Uint32(b[36:])), o.Uint32(b[48:])
			}
			if !rangeOK(offset, segmentLength, length) || uint64(count)*sectionSize > uint64(size)-base {
				return nil, malformed("segment bounds")
			}
			if name == "__LINKEDIT" {
				if im.linkedit >= 0 {
					return nil, malformed("duplicate LINKEDIT")
				}
				im.linkedit, im.linkeditKind, im.linkStart = int(p), kind, offset
				if !im.strictCandidate {
					im.strictCandidate, im.strictValid = true, segmentLength == length-offset
				}
			}
			if name == "__TEXT" {
				im.textBase, im.textSize = offset, segmentLength
			}
			for j := uint32(0); j < count; j++ {
				b, e := read(p+base+uint64(j)*sectionSize+field, 4)
				if e != nil {
					return nil, e
				}
				off := uint64(o.Uint32(b))
				if off != 0 && off < im.firstSection {
					im.firstSection = off
				}
			}
		case 0x1b:
			if im.uuidOffset < 0 {
				im.uuidOffset, im.uuidSize = int(p), size
				if size == 24 {
					b, e := read(p+8, 16)
					if e != nil {
						return nil, e
					}
					copy(im.uuid[:], b)
				}
			}
		case 0x32:
			if size >= 24 {
				b, e := read(p+8, 12)
				if e != nil {
					return nil, e
				}
				im.versionPlatform, im.versionMin, im.versionSDK = o.Uint32(b), o.Uint32(b[4:]), o.Uint32(b[8:])
				if !im.buildVersionSeen {
					im.execPlatform = o.Uint32(b)
				}
			}
			im.buildVersionSeen = true
		case 0x24, 0x25, 0x2f, 0x30:
			if !im.minVersionSeen && size >= 16 {
				switch kind {
				case 0x24:
					im.legacyPlatform = 1
				case 0x25:
					im.legacyPlatform = 2
				case 0x2f:
					im.legacyPlatform = 3
				case 0x30:
					im.legacyPlatform = 4
				}
			}
			im.minVersionSeen = true
		case 2:
			var symbols, count, strings, stringSize uint64
			if size >= 24 {
				b, e := read(p+8, 16)
				if e != nil {
					return nil, e
				}
				symbols, count, strings, stringSize = uint64(o.Uint32(b)), uint64(o.Uint32(b[4:])), uint64(o.Uint32(b[8:])), uint64(o.Uint32(b[12:]))
			}
			if !im.symbols.present {
				im.symbols = symbolSummary{present: true, size: size, symbols: symbols, count: count, strings: strings, stringSize: stringSize}
			} else {
				im.symbols.duplicate = true
			}
			if !im.strictCandidate {
				im.strictCandidate, im.strictValid = true, size >= 24 && strings+stringSize == length
			}
		}
		p += uint64(size)
	}
	if p != end || im.firstSection < end {
		return nil, malformed("load commands overlap content")
	}
	if !im.buildVersionSeen {
		im.execPlatform = im.legacyPlatform
	}
	return im, nil
}

func parseContainer(data []byte) (*container, error) {
	c, err := parseContainerRange(uint64(len(data)), memoryRange(data), func(offset, length uint64) (*image, error) { return parseImage(data[offset : offset+length]) })
	if err == nil {
		c.data = data
	}
	return c, err
}

func parseContainerRange(length uint64, read rangeReader, readImage func(uint64, uint64) (*image, error)) (*container, error) {
	c := &container{order: be}
	if length < 4 {
		return nil, malformed("empty or truncated file")
	}
	data, err := read(0, min(length, 8))
	if err != nil {
		return nil, err
	}
	magic := be.Uint32(data)
	if magic != 0xcafebabe && magic != 0xbebafeca && magic != 0xcafebabf && magic != 0xbfbafeca {
		im, err := readImage(0, length)
		if err != nil {
			return nil, err
		}
		c.slices = []slice{{0, length, im.cpu, im.subtype, 0, im}}
		return c, nil
	}
	c.fat = true
	c.fat64 = magic == 0xcafebabf || magic == 0xbfbafeca
	if magic == 0xbebafeca || magic == 0xbfbafeca {
		c.order = binary.LittleEndian
	}
	if length < 8 {
		return nil, malformed("universal header")
	}
	n := c.order.Uint32(data[4:])
	entry := 20
	if c.fat64 {
		entry = 32
	}
	if n == 0 || n > 128 || uint64(n)*uint64(entry)+8 > length {
		return nil, malformed("universal index bounds")
	}
	data, err = read(0, 8+uint64(n)*uint64(entry))
	if err != nil {
		return nil, err
	}
	c.data = data
	for i := uint32(0); i < n; i++ {
		p := 8 + int(i)*entry
		s := slice{cpu: c.order.Uint32(data[p:]), subtype: c.order.Uint32(data[p+4:])}
		if c.fat64 {
			s.offset = c.order.Uint64(data[p+8:])
			s.size = c.order.Uint64(data[p+16:])
			s.alignment = c.order.Uint32(data[p+24:])
		} else {
			s.offset = uint64(c.order.Uint32(data[p+8:]))
			s.size = uint64(c.order.Uint32(data[p+12:]))
			s.alignment = c.order.Uint32(data[p+16:])
		}
		if s.alignment > 30 || s.offset%(uint64(1)<<s.alignment) != 0 || s.offset < uint64(8+int(n)*entry) || !rangeOK(s.offset, s.size, length) {
			return nil, malformed("universal slice bounds")
		}
		for _, old := range c.slices {
			if old.cpu == s.cpu && old.subtype == s.subtype {
				return nil, malformed("duplicate architecture")
			}
			if s.offset < old.offset+old.size && old.offset < s.offset+s.size {
				return nil, malformed("overlapping architectures")
			}
		}
		im, err := readImage(s.offset, s.size)
		if err != nil {
			return nil, err
		}
		if im.cpu != s.cpu || im.subtype != s.subtype {
			return nil, malformed("universal architecture mismatch")
		}
		s.image = im
		c.slices = append(c.slices, s)
	}
	return c, nil
}

func archName(cpu, sub uint32) string {
	switch cpu {
	case 0x100000c:
		if sub&0xffffff == 2 {
			return "arm64e"
		}
		return "arm64"
	case 0x1000007:
		if sub&0xffffff == 8 {
			return "x86_64h"
		}
		return "x86_64"
	case 7:
		return "i386"
	case 12:
		return "arm"
	case 18:
		return "ppc"
	case 0x1000012:
		return "ppc64"
	default:
		return fmt.Sprintf("cpu-%x-%x", cpu, sub)
	}
}
