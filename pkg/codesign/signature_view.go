package codesign

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
)

// signatureView borrows one operation's held source and scratch scope. It never
// escapes into a public Signature: public byte ownership remains independent.
// Only six directory slot numbers exist; arbitrary other components stay ranges.
type signatureView struct {
	source         codeSource
	length         uint32
	count          uint32
	slots          *signatureIndex
	directories    [6]directoryView
	directoryCount int
}
type directoryView struct {
	metadata         Directory
	source           codeSource
	identifier, team viewString
}
type viewString struct{ offset, length uint64 }

func parseSignatureView(source codeSource, allowUnsigned bool) (*signatureView, error) {
	if storageFrom(source.ctx) == nil {
		return nil, malformed("signature view requires working storage")
	}
	if source.source.size < 12 {
		return nil, malformed("signature SuperBlob")
	}
	header, err := source.read(0, 12)
	if err != nil {
		return nil, err
	}
	if be.Uint32(header) != MagicSignature {
		return nil, malformed("signature SuperBlob")
	}
	length, count := be.Uint32(header[4:]), be.Uint32(header[8:])
	if length < 12 || uint64(length) > uint64(source.source.size) || uint64(count)*8 > uint64(length)-12 {
		return nil, malformed("signature index bounds")
	}
	v := &signatureView{source: source, length: length, count: count, slots: &signatureIndex{ctx: source.ctx}}
	intervals := signatureIndex{ctx: source.ctx}
	overlap := false
	for i := uint32(0); i < count; i++ {
		entry, err := source.read(12+uint64(i)*8, 8)
		if err != nil {
			return nil, err
		}
		slot, off := be.Uint32(entry), be.Uint32(entry[4:])
		duplicate, err := v.slots.insert(slot, i)
		if err != nil {
			return nil, err
		}
		if duplicate {
			return nil, malformed("duplicate signature slot %d", slot)
		}
		if uint64(off) < 12+uint64(count)*8 || !rangeOK(uint64(off), 8, uint64(length)) {
			return nil, malformed("blob header bounds")
		}
		blobHeader, err := source.read(uint64(off), 8)
		if err != nil {
			return nil, err
		}
		n := be.Uint32(blobHeader[4:])
		if n < 8 || !rangeOK(uint64(off), uint64(n), uint64(length)) {
			return nil, malformed("blob length")
		}
		component := codeSource{source.ctx, outputSource{source.source.reader, source.source.offset + int64(off), int64(n)}}
		isDirectory := slot == 0 || slot >= 0x1000 && slot < 0x1005
		prefix, sum, err := scanSignatureComponent(component, blobHeader, isDirectory)
		if err != nil {
			return nil, err
		}
		magic := be.Uint32(blobHeader)
		if expected := map[uint32]uint32{SlotRequirements: MagicRequirements, SlotEntitlements: MagicEntitlements, SlotDEREntitlements: MagicDEREntitlements, SlotCMS: MagicCMS}[slot]; expected != 0 && expected != magic {
			return nil, malformed("magic for signature slot %d", slot)
		}
		if isDirectory {
			d, err := parseDirectoryView(component, prefix, sum)
			if err != nil {
				return nil, err
			}
			v.directories[v.directoryCount] = d
			v.directoryCount++
		}
		if !overlap {
			overlap, err = intervals.overlaps(off, off+n)
			if err != nil {
				return nil, err
			}
			if !overlap {
				if _, err = intervals.insert(off, off+n); err != nil {
					return nil, err
				}
			}
		}
	}
	// Overlap remains deferred until every component's original-order parse.
	if overlap {
		return nil, malformed("overlapping signature blobs")
	}
	_, primary, err := v.slots.find(0)
	if err != nil {
		return nil, err
	}
	if !primary && (!allowUnsigned || v.directoryCount != 0) {
		return nil, malformed("missing primary CodeDirectory")
	}
	return v, nil
}

// Consume every component byte before interpreting it, matching the old owned
// parser's read/error order. Only a fixed prefix and optional digest survive.
func scanSignatureComponent(source codeSource, header []byte, directory bool) ([108]byte, []byte, error) {
	var prefix [108]byte
	buffer, release, err := transferBuffer(source.ctx, source.source.size)
	if err != nil {
		return prefix, nil, err
	}
	defer release()
	var h hash.Hash
	var kind uint8
	for at := int64(0); at < source.source.size; {
		if err := source.ctx.Err(); err != nil {
			return prefix, nil, err
		}
		p := buffer[:min(int64(len(buffer)), source.source.size-at)]
		n, err := source.source.reader.ReadAt(p, source.source.offset+at)
		if n != len(p) {
			return prefix, nil, errors.Join(io.ErrUnexpectedEOF, err, source.ctx.Err())
		}
		if err != nil && err != io.EOF {
			return prefix, nil, errors.Join(err, source.ctx.Err())
		}
		if at < int64(len(prefix)) {
			copy(prefix[at:], p)
		}
		if at == 0 && directory && len(p) >= 44 {
			kind = p[37]
			switch kind {
			case 1:
				h = sha1.New()
			case 2, 3:
				h = sha256.New()
			case 4:
				h = sha512.New384()
			}
		}
		if h != nil {
			_, _ = h.Write(p)
		}
		at += int64(n)
	}
	if err := source.ctx.Err(); err != nil {
		return prefix, nil, err
	}
	if !bytes.Equal(prefix[:8], header) {
		return prefix, nil, malformed("signature component changed while reading")
	}
	if h == nil {
		return prefix, nil, nil
	}
	sum := h.Sum(nil)
	if kind == 3 {
		sum = sum[:20]
	}
	return prefix, sum, nil
}

func parseDirectoryView(source codeSource, prefix [108]byte, sum []byte) (directoryView, error) {
	v := directoryView{source: source}
	d := &v.metadata
	raw := prefix[:]
	if source.source.size < 44 || be.Uint32(raw) != MagicDirectory {
		return v, malformed("CodeDirectory header")
	}
	d.Version, d.Flags, d.HashOffset = be.Uint32(raw[8:]), be.Uint32(raw[12:]), be.Uint32(raw[16:])
	d.SpecialSlots, d.CodeSlots = be.Uint32(raw[24:]), be.Uint32(raw[28:])
	d.CodeLimit = uint64(be.Uint32(raw[32:]))
	d.HashSize, d.HashType, d.Platform, d.PageExponent = raw[36], raw[37], raw[38], raw[39]
	if d.Version < 0x20001 || d.Version > 0x20600 {
		return v, unsupported(fmt.Sprintf("CodeDirectory version %#x", d.Version))
	}
	header := 44
	for _, version := range []struct {
		version uint32
		size    int
	}{{0x20100, 48}, {0x20200, 52}, {0x20300, 64}, {0x20400, 88}, {0x20500, 96}, {0x20600, 108}} {
		if d.Version >= version.version {
			header = version.size
		}
	}
	if source.source.size < int64(header) {
		return v, malformed("truncated versioned CodeDirectory")
	}
	if len(sum) == 0 {
		return v, unsupported(fmt.Sprintf("hash type %d", d.HashType))
	}
	if int(d.HashSize) != len(sum) || d.PageExponent > 31 {
		return v, malformed("hash size or page exponent")
	}
	if d.Version >= 0x20100 && be.Uint32(raw[44:]) != 0 {
		return v, unsupported("scatter CodeDirectory")
	}
	if be.Uint32(raw[20:]) < uint32(header) {
		return v, malformed("identifier overlaps header")
	}
	var err error
	v.identifier, err = scanViewString(source, uint64(be.Uint32(raw[20:])))
	if err != nil {
		return v, err
	}
	if d.Version >= 0x20200 && be.Uint32(raw[48:]) != 0 {
		v.team, err = scanViewString(source, uint64(be.Uint32(raw[48:])))
		if err != nil {
			return v, err
		}
	}
	if d.Version >= 0x20300 {
		if limit := be.Uint64(raw[56:]); limit != 0 {
			d.CodeLimit = limit
		}
	}
	if d.Version >= 0x20400 {
		d.ExecBase, d.ExecLimit, d.ExecFlags = be.Uint64(raw[64:]), be.Uint64(raw[72:]), be.Uint64(raw[80:])
	}
	if d.Version >= 0x20500 {
		d.Runtime = be.Uint32(raw[88:])
	}
	specialBytes := uint64(d.SpecialSlots) * uint64(d.HashSize)
	if uint64(d.HashOffset) < uint64(header)+specialBytes || !rangeOK(uint64(d.HashOffset), uint64(d.CodeSlots)*uint64(d.HashSize), uint64(source.source.size)) {
		return v, malformed("CodeDirectory hash bounds")
	}
	d.CDHash, d.FullHash = hex.EncodeToString(sum[:20]), hex.EncodeToString(sum)
	return v, nil
}
func scanViewString(source codeSource, offset uint64) (viewString, error) {
	if offset >= uint64(source.source.size) {
		return viewString{}, malformed("string offset")
	}
	buffer, release, err := transferBuffer(source.ctx, source.source.size-int64(offset))
	if err != nil {
		return viewString{}, err
	}
	defer release()
	for at := offset; at < uint64(source.source.size); {
		if err := source.ctx.Err(); err != nil {
			return viewString{}, err
		}
		p := buffer[:min(uint64(len(buffer)), uint64(source.source.size)-at)]
		n, err := source.source.reader.ReadAt(p, source.source.offset+int64(at))
		if n != len(p) {
			return viewString{}, errors.Join(io.ErrUnexpectedEOF, err, source.ctx.Err())
		}
		if err != nil && err != io.EOF {
			return viewString{}, errors.Join(err, source.ctx.Err())
		}
		if err := source.ctx.Err(); err != nil {
			return viewString{}, err
		}
		if i := bytes.IndexByte(p, 0); i >= 0 {
			return viewString{offset, at - offset + uint64(i)}, nil
		}
		at += uint64(n)
	}
	return viewString{}, malformed("unterminated string")
}
