package codesign

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type loadCommand struct {
	kind         uint32
	offset, size int
}
type image struct {
	data                   []byte
	order                  binary.ByteOrder
	header                 int
	cpu, subtype, filetype uint32
	commands               []loadCommand
	sigOffset, sigSize     uint32
	sigCommand             int
	linkedit               int
	textBase, textSize     uint64
	firstSection           uint64
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

func parseImage(data []byte) (*image, error) {
	im, err := parseImageRange(uint64(len(data)), memoryRange(data))
	if err == nil {
		im.data = data
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
	im := &image{header: 28, sigCommand: -1, linkedit: -1, firstSection: length}
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
	o := im.order
	im.cpu = o.Uint32(data[4:])
	im.subtype = o.Uint32(data[8:])
	im.filetype = o.Uint32(data[12:])
	n, sz := o.Uint32(data[16:]), o.Uint32(data[20:])
	if !rangeOK(uint64(im.header), uint64(sz), length) || uint64(n)*8 > uint64(sz) {
		return nil, malformed("load command bounds")
	}
	data, err = read(0, uint64(im.header)+uint64(sz))
	if err != nil {
		return nil, err
	}
	im.data = data
	end := im.header + int(sz)
	p := im.header
	for i := uint32(0); i < n; i++ {
		if p+8 > end {
			return nil, malformed("truncated load command")
		}
		kind, size := o.Uint32(data[p:]), o.Uint32(data[p+4:])
		if size < 8 || size%4 != 0 || uint64(size) > uint64(end-p) {
			return nil, malformed("load command size")
		}
		im.commands = append(im.commands, loadCommand{kind, p, int(size)})
		if kind == 0x1d {
			if size != 16 || im.sigCommand >= 0 {
				return nil, malformed("code signature command")
			}
			im.sigCommand = p
			im.sigOffset = o.Uint32(data[p+8:])
			im.sigSize = o.Uint32(data[p+12:])
			if im.sigOffset < uint32(end) || !rangeOK(uint64(im.sigOffset), uint64(im.sigSize), length) {
				return nil, malformed("code signature range")
			}
		}
		if kind == 0x19 || kind == 1 {
			base, sectionSize := 56, 68
			if kind == 0x19 {
				base, sectionSize = 72, 80
			}
			if int(size) < base {
				return nil, malformed("segment header")
			}
			name := string(bytes.TrimRight(data[p+8:p+24], "\x00"))
			var offset, segmentLength uint64
			var count uint32
			if kind == 0x19 {
				offset = o.Uint64(data[p+40:])
				segmentLength = o.Uint64(data[p+48:])
				count = o.Uint32(data[p+64:])
			} else {
				offset = uint64(o.Uint32(data[p+32:]))
				segmentLength = uint64(o.Uint32(data[p+36:]))
				count = o.Uint32(data[p+48:])
			}
			if !rangeOK(offset, segmentLength, length) || uint64(count)*uint64(sectionSize) > uint64(size)-uint64(base) {
				return nil, malformed("segment bounds")
			}
			if name == "__LINKEDIT" {
				if im.linkedit >= 0 {
					return nil, malformed("duplicate LINKEDIT")
				}
				im.linkedit = p
			}
			if name == "__TEXT" {
				im.textBase = offset
				im.textSize = segmentLength
			}
			for j := uint32(0); j < count; j++ {
				pos := p + base + int(j)*sectionSize
				idx := 40
				if kind == 0x19 {
					idx = 48
				}
				off := uint64(o.Uint32(data[pos+idx:]))
				if off != 0 && off < im.firstSection {
					im.firstSection = off
				}
			}
		}
		p += int(size)
	}
	if p != end || im.firstSection < uint64(end) {
		return nil, malformed("load commands overlap content")
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
