package codesign

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
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

func parseImage(data []byte) (*image, error) {
	if len(data) < 28 {
		return nil, malformed("Mach-O header")
	}
	im := &image{data: data, header: 28, sigCommand: -1, linkedit: -1, firstSection: uint64(len(data))}
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
	if len(data) < im.header {
		return nil, malformed("64-bit Mach-O header")
	}
	o := im.order
	im.cpu = o.Uint32(data[4:])
	im.subtype = o.Uint32(data[8:])
	im.filetype = o.Uint32(data[12:])
	n, sz := o.Uint32(data[16:]), o.Uint32(data[20:])
	if !rangeOK(uint64(im.header), uint64(sz), uint64(len(data))) || uint64(n)*8 > uint64(sz) {
		return nil, malformed("load command bounds")
	}
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
			if im.sigOffset < uint32(end) || !rangeOK(uint64(im.sigOffset), uint64(im.sigSize), uint64(len(data))) {
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
			var offset, length uint64
			var count uint32
			if kind == 0x19 {
				offset = o.Uint64(data[p+40:])
				length = o.Uint64(data[p+48:])
				count = o.Uint32(data[p+64:])
			} else {
				offset = uint64(o.Uint32(data[p+32:]))
				length = uint64(o.Uint32(data[p+36:]))
				count = o.Uint32(data[p+48:])
			}
			if !rangeOK(offset, length, uint64(len(data))) || uint64(count)*uint64(sectionSize) > uint64(size)-uint64(base) {
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
				im.textSize = length
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
	c := &container{data: data, order: be}
	if len(data) < 4 {
		return nil, malformed("empty or truncated file")
	}
	magic := be.Uint32(data)
	if magic != 0xcafebabe && magic != 0xbebafeca && magic != 0xcafebabf && magic != 0xbfbafeca {
		im, err := parseImage(data)
		if err != nil {
			return nil, err
		}
		c.slices = []slice{{0, uint64(len(data)), im.cpu, im.subtype, 0, im}}
		return c, nil
	}
	c.fat = true
	c.fat64 = magic == 0xcafebabf || magic == 0xbfbafeca
	if magic == 0xbebafeca || magic == 0xbfbafeca {
		c.order = binary.LittleEndian
	}
	if len(data) < 8 {
		return nil, malformed("universal header")
	}
	n := c.order.Uint32(data[4:])
	entry := 20
	if c.fat64 {
		entry = 32
	}
	if n == 0 || n > 128 || uint64(n)*uint64(entry)+8 > uint64(len(data)) {
		return nil, malformed("universal index bounds")
	}
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
		if s.alignment > 30 || s.offset%(uint64(1)<<s.alignment) != 0 || s.offset < uint64(8+int(n)*entry) || !rangeOK(s.offset, s.size, uint64(len(data))) {
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
		im, err := parseImage(data[s.offset : s.offset+s.size])
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

func (c *container) assemble(parts [][]byte) ([]byte, error) {
	if !c.fat {
		return parts[0], nil
	}
	entry := 20
	if c.fat64 {
		entry = 32
	}
	end := uint64(8 + len(parts)*entry)
	offsets := make([]uint64, len(parts))
	for i, b := range parts {
		alignment := uint64(1) << c.slices[i].alignment
		end = (end + alignment - 1) &^ (alignment - 1)
		offsets[i] = end
		end += uint64(len(b))
		if end > math.MaxUint32 && !c.fat64 {
			return nil, unsupported("universal file exceeds 32-bit offsets")
		}
	}
	if end > maxFileSize {
		return nil, unsupported("output exceeds memory limit")
	}
	out := make([]byte, int(end))
	copy(out, c.data[:8+len(parts)*entry])
	for i, b := range parts {
		p := 8 + i*entry
		if c.fat64 {
			c.order.PutUint64(out[p+8:], offsets[i])
			c.order.PutUint64(out[p+16:], uint64(len(b)))
			c.order.PutUint32(out[p+24:], c.slices[i].alignment)
		} else {
			c.order.PutUint32(out[p+8:], uint32(offsets[i]))
			c.order.PutUint32(out[p+12:], uint32(len(b)))
			c.order.PutUint32(out[p+16:], c.slices[i].alignment)
		}
		copy(out[offsets[i]:], b)
	}
	return out, nil
}
