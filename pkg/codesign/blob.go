package codesign

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

const (
	MagicDirectory       uint32 = 0xfade0c02
	MagicSignature       uint32 = 0xfade0cc0
	MagicRequirements    uint32 = 0xfade0c01
	MagicRequirement     uint32 = 0xfade0c00
	MagicEntitlements    uint32 = 0xfade7171
	MagicDEREntitlements uint32 = 0xfade7172
	MagicCMS             uint32 = 0xfade0b01
	SlotDirectory        uint32 = 0
	SlotInfo             uint32 = 1
	SlotRequirements     uint32 = 2
	SlotResources        uint32 = 3
	SlotEntitlements     uint32 = 5
	SlotRepSpecific      uint32 = 6
	SlotDEREntitlements  uint32 = 7
	SlotCMS              uint32 = 0x10000
	FlagAdhoc            uint32 = 2
	FlagRuntime          uint32 = 0x10000
)

var be = binary.BigEndian

func digest(kind uint8, data []byte) ([]byte, error) {
	switch kind {
	case 1:
		h := sha1.Sum(data)
		return h[:], nil
	case 2:
		h := sha256.Sum256(data)
		return h[:], nil
	case 3:
		h := sha256.Sum256(data)
		return h[:20], nil
	case 4:
		h := sha512.Sum384(data)
		return h[:], nil
	default:
		return nil, unsupported(fmt.Sprintf("hash type %d", kind))
	}
}

func rangeOK(off, size, total uint64) bool { return off <= total && size <= total-off }

// ParseSignature validates blob bounds before exposing any indexed data.
func ParseSignature(data []byte) (*Signature, error) {
	if len(data) < 12 || be.Uint32(data) != MagicSignature {
		return nil, malformed("signature SuperBlob")
	}
	length, count := be.Uint32(data[4:]), be.Uint32(data[8:])
	if length < 12 || uint64(length) > uint64(len(data)) || uint64(count)*8 > uint64(length)-12 {
		return nil, malformed("signature index bounds")
	}
	s := &Signature{Length: length}
	seen := map[uint32]bool{}
	type interval struct{ start, end uint32 }
	var spans []interval
	for i := uint32(0); i < count; i++ {
		entry := data[12+i*8:]
		slot, off := be.Uint32(entry), be.Uint32(entry[4:])
		if seen[slot] {
			return nil, malformed("duplicate signature slot %d", slot)
		}
		seen[slot] = true
		if off < 12+count*8 || !rangeOK(uint64(off), 8, uint64(length)) {
			return nil, malformed("blob header bounds")
		}
		n := be.Uint32(data[off+4:])
		if n < 8 || !rangeOK(uint64(off), uint64(n), uint64(length)) {
			return nil, malformed("blob length")
		}
		spans = append(spans, interval{off, off + n})
		blob := Blob{Slot: slot, Magic: be.Uint32(data[off:]), Data: bytes.Clone(data[off : off+n])}
		if expected := map[uint32]uint32{SlotRequirements: MagicRequirements, SlotEntitlements: MagicEntitlements, SlotDEREntitlements: MagicDEREntitlements, SlotCMS: MagicCMS}[slot]; expected != 0 && blob.Magic != expected {
			return nil, malformed("magic for signature slot %d", slot)
		}
		s.Blobs = append(s.Blobs, blob)
		if slot == 0 || slot >= 0x1000 && slot < 0x1005 {
			d, err := parseDirectory(blob.Data)
			if err != nil {
				return nil, err
			}
			s.Directories = append(s.Directories, d)
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return nil, malformed("overlapping signature blobs")
		}
	}
	if !seen[0] {
		return nil, malformed("missing primary CodeDirectory")
	}
	return s, nil
}

func cstring(data []byte, off uint32) (string, error) {
	if uint64(off) >= uint64(len(data)) {
		return "", malformed("string offset")
	}
	n := bytes.IndexByte(data[off:], 0)
	if n < 0 {
		return "", malformed("unterminated string")
	}
	return string(data[off : uint64(off)+uint64(n)]), nil
}

func parseDirectory(raw []byte) (Directory, error) {
	d := Directory{Raw: raw}
	if len(raw) < 44 || be.Uint32(raw) != MagicDirectory {
		return d, malformed("CodeDirectory header")
	}
	d.Version = be.Uint32(raw[8:])
	d.Flags = be.Uint32(raw[12:])
	d.HashOffset = be.Uint32(raw[16:])
	d.SpecialSlots = be.Uint32(raw[24:])
	d.CodeSlots = be.Uint32(raw[28:])
	d.CodeLimit = uint64(be.Uint32(raw[32:]))
	d.HashSize = raw[36]
	d.HashType = raw[37]
	d.Platform = raw[38]
	d.PageExponent = raw[39]
	if d.Version < 0x20001 || d.Version > 0x20600 {
		return d, unsupported(fmt.Sprintf("CodeDirectory version %#x", d.Version))
	}
	header := 44
	for _, v := range []struct {
		version uint32
		size    int
	}{{0x20100, 48}, {0x20200, 52}, {0x20300, 64}, {0x20400, 88}, {0x20500, 96}, {0x20600, 108}} {
		if d.Version >= v.version {
			header = v.size
		}
	}
	if len(raw) < header {
		return d, malformed("truncated versioned CodeDirectory")
	}
	h, err := digest(d.HashType, raw)
	if err != nil {
		return d, err
	}
	if int(d.HashSize) != len(h) || d.PageExponent > 31 {
		return d, malformed("hash size or page exponent")
	}
	if d.Version >= 0x20100 && be.Uint32(raw[44:]) != 0 {
		return d, unsupported("scatter CodeDirectory")
	}
	if be.Uint32(raw[20:]) < uint32(header) {
		return d, malformed("identifier overlaps header")
	}
	d.Identifier, err = cstring(raw, be.Uint32(raw[20:]))
	if err != nil {
		return d, err
	}
	if d.Version >= 0x20200 && be.Uint32(raw[48:]) != 0 {
		d.TeamID, err = cstring(raw, be.Uint32(raw[48:]))
		if err != nil {
			return d, err
		}
	}
	if d.Version >= 0x20300 && d.CodeLimit == 0 {
		d.CodeLimit = be.Uint64(raw[56:])
	}
	if d.Version >= 0x20400 {
		d.ExecBase = be.Uint64(raw[64:])
		d.ExecLimit = be.Uint64(raw[72:])
		d.ExecFlags = be.Uint64(raw[80:])
	}
	if d.Version >= 0x20500 {
		d.Runtime = be.Uint32(raw[88:])
	}
	specialBytes := uint64(d.SpecialSlots) * uint64(d.HashSize)
	if uint64(d.HashOffset) < uint64(header)+specialBytes || !rangeOK(uint64(d.HashOffset), uint64(d.CodeSlots)*uint64(d.HashSize), uint64(len(raw))) {
		return d, malformed("CodeDirectory hash bounds")
	}
	d.CDHash = hex.EncodeToString(h[:20])
	d.FullHash = hex.EncodeToString(h)
	return d, nil
}

func blob(magic uint32, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	be.PutUint32(b, magic)
	be.PutUint32(b[4:], uint32(len(b)))
	copy(b[8:], payload)
	return b
}

func superblob(magic uint32, blobs []Blob) []byte {
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].Slot < blobs[j].Slot })
	n := 12 + len(blobs)*8
	for _, b := range blobs {
		n += len(b.Data)
	}
	out := make([]byte, n)
	be.PutUint32(out, magic)
	be.PutUint32(out[4:], uint32(n))
	be.PutUint32(out[8:], uint32(len(blobs)))
	p := 12 + len(blobs)*8
	for i, b := range blobs {
		be.PutUint32(out[12+8*i:], b.Slot)
		be.PutUint32(out[16+8*i:], uint32(p))
		copy(out[p:], b.Data)
		p += len(b.Data)
	}
	return out
}

func (s *Signature) find(slot uint32) []byte {
	for _, b := range s.Blobs {
		if b.Slot == slot {
			return b.Data
		}
	}
	return nil
}
