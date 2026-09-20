package codesign

import (
	"encoding/binary"
	"math"
	"time"
	"unicode/utf16"
)

// Binary plists are object graphs. Count expanded references as well as table
// entries: a tiny acyclic graph can otherwise expand into an enormous Go value.
// The generic plist decoder does not impose these bounds. Keep the original
// input bytes in appBundle.info; decoded values drive discovery/resource policy.
type binaryBundlePlist struct {
	data    []byte
	offsets []uint64
	refSize uint64
	values  uint64
	bytes   uint64
	active  map[uint64]bool
}

func decodeBinaryBundlePlist(data []byte) (map[string]any, error) {
	if len(data) < 42 || len(data) > maxBundlePlist || string(data[:7]) != "bplist0" {
		return nil, malformed("binary bundle plist header or size")
	}
	t := data[len(data)-32:]
	width, refs := uint64(t[6]), uint64(t[7])
	n, top, table := binary.BigEndian.Uint64(t[8:]), binary.BigEndian.Uint64(t[16:]), binary.BigEndian.Uint64(t[24:])
	end := uint64(len(data) - 32)
	if width < 1 || width > 8 || refs < 1 || refs > 8 || n == 0 || n > maxBundlePlistValues || top >= n || table < 9 || table >= end || n > (end-table)/width || n*width != end-table {
		return nil, malformed("binary bundle plist trailer")
	}
	if refs < 8 && n >= uint64(1)<<(8*refs) || width < 8 && table >= uint64(1)<<(8*width) {
		return nil, malformed("binary bundle plist address width")
	}
	p := binaryBundlePlist{data: data[:table], offsets: make([]uint64, n), refSize: refs, values: 1, active: map[uint64]bool{}}
	for i := range p.offsets {
		off := plistUint(data[table+uint64(i)*width : table+uint64(i+1)*width])
		if off < 8 || off >= table {
			return nil, malformed("binary bundle plist object offset")
		}
		p.offsets[i] = off
	}
	v, err := p.object(top, 1)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, malformed("bundle plist must be a dictionary")
	}
	return m, nil
}

func plistUint(b []byte) (v uint64) {
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func (p *binaryBundlePlist) span(off, n uint64) ([]byte, error) {
	if off > uint64(len(p.data)) || n > uint64(len(p.data))-off {
		return nil, malformed("truncated binary bundle plist object")
	}
	return p.data[off : off+n], nil
}

func (p *binaryBundlePlist) length(off uint64, tag byte) (uint64, uint64, error) {
	n := uint64(tag & 15)
	if n != 15 {
		return n, off, nil
	}
	b, err := p.span(off, 1)
	if err != nil {
		return 0, 0, err
	}
	if b[0]>>4 != 1 || b[0]&15 > 3 {
		return 0, 0, malformed("binary bundle plist length integer")
	}
	size := uint64(1) << (b[0] & 15)
	b, err = p.span(off+1, size)
	if err != nil {
		return 0, 0, err
	}
	return plistUint(b), off + 1 + size, nil
}

func (p *binaryBundlePlist) object(ref uint64, depth int) (any, error) {
	if ref >= uint64(len(p.offsets)) || depth > maxBundlePlistDepth {
		return nil, malformed("binary bundle plist reference or depth")
	}
	off := p.offsets[ref]
	if p.active[off] {
		return nil, malformed("cyclic binary bundle plist")
	}
	p.active[off] = true
	defer delete(p.active, off)
	tag := p.data[off]
	off++
	kind, size := tag>>4, uint64(1)<<(tag&15)
	switch kind {
	case 0:
		if tag == 8 || tag == 9 {
			return tag == 9, nil
		}
	case 1:
		if size > 16 {
			return nil, malformed("binary bundle plist integer size")
		}
		b, err := p.span(off, size)
		if err != nil {
			return nil, err
		}
		v := plistUint(b)
		if size == 16 {
			hi := plistUint(b[:8])
			if hi == 0 {
				return v, nil
			}
			if hi != math.MaxUint64 || v>>63 == 0 {
				return nil, unsupported("bundle plist integer exceeds 64 bits")
			}
		}
		if size >= 8 {
			return int64(v), nil
		}
		return v, nil
	case 2, 3:
		if kind == 2 && size != 4 && size != 8 || kind == 3 && tag != 0x33 {
			return nil, malformed("binary bundle plist real/date size")
		}
		b, err := p.span(off, size)
		if err != nil {
			return nil, err
		}
		v := math.Float64frombits(plistUint(b))
		if size == 4 {
			v = float64(math.Float32frombits(uint32(plistUint(b))))
		}
		if kind == 2 {
			return v, nil
		}
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= -1<<62 || v >= 1<<62 {
			return nil, malformed("binary bundle plist date range")
		}
		seconds, fraction := math.Modf(v)
		return time.Unix(int64(seconds)+978307200, int64(fraction*1e9)).UTC(), nil
	case 4, 5, 6, 10, 13:
		n, start, err := p.length(off, tag)
		if err != nil {
			return nil, err
		}
		if kind == 10 || kind == 13 {
			return p.collection(kind, start, n, depth)
		}
		width := uint64(1)
		if kind == 6 {
			width = 2
		}
		// Three bytes per UTF-16 code unit bounds its decoded UTF-8 length.
		cost := uint64(1)
		if kind == 6 {
			cost = 3
		}
		if n > (maxBundlePlist-p.bytes)/cost {
			return nil, malformed("binary bundle plist expanded byte limit")
		}
		p.bytes += n * cost
		b, err := p.span(start, n*width)
		if err != nil {
			return nil, err
		}
		switch kind {
		case 4:
			return append([]byte{}, b...), nil
		case 5:
			for _, c := range b {
				if c > 127 {
					return nil, malformed("binary bundle plist ASCII string")
				}
			}
			return string(b), nil
		default:
			u := make([]uint16, n)
			for i := range u {
				u[i] = binary.BigEndian.Uint16(b[i*2:])
			}
			for i := 0; i < len(u); i++ {
				if utf16.IsSurrogate(rune(u[i])) {
					if u[i] >= 0xdc00 || i+1 == len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
						return nil, malformed("binary bundle plist UTF-16 string")
					}
					i++
				}
			}
			return string(utf16.Decode(u)), nil
		}
	}
	return nil, unsupported("binary bundle plist object type")
}

func (p *binaryBundlePlist) collection(kind byte, start, n uint64, depth int) (any, error) {
	count := n
	if kind == 13 {
		if n > maxBundlePlistValues/2 {
			return nil, malformed("binary bundle plist dictionary size")
		}
		count *= 2
	}
	if count > maxBundlePlistValues-p.values {
		return nil, malformed("binary bundle plist expanded value limit")
	}
	p.values += count
	b, err := p.span(start, count*p.refSize)
	if err != nil {
		return nil, err
	}
	get := func(i uint64) (any, error) {
		return p.object(plistUint(b[i*p.refSize:(i+1)*p.refSize]), depth+1)
	}
	if kind == 10 {
		values := make([]any, n)
		for i := range values {
			values[i], err = get(uint64(i))
			if err != nil {
				return nil, err
			}
		}
		return values, nil
	}
	m := make(map[string]any, n)
	for i := uint64(0); i < n; i++ {
		key, err := get(i)
		if err != nil {
			return nil, err
		}
		s, ok := key.(string)
		if !ok {
			return nil, malformed("binary bundle plist dictionary key is not a string")
		}
		if _, exists := m[s]; exists {
			return nil, malformed("duplicate bundle plist key")
		}
		m[s], err = get(i + n)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}
