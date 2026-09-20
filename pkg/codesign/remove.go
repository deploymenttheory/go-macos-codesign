package codesign

import "bytes"

// removeImageSignature follows the deallocation rules recorded in
// spec/apple-removal.json. In particular, the symbol string table determines
// alignment padding; scanning trailing zero bytes would destroy real data.
func removeImageSignature(im *image) ([]byte, error) {
	switch im.filetype {
	case 2, 6, 7, 8, 11: // executable, dylib, dylinker, bundle, kext
	default:
		return nil, unsupported("Mach-O file type for signature removal")
	}
	if im.linkedit < 0 {
		return nil, malformed("missing LINKEDIT")
	}
	if im.sigCommand < 0 {
		return bytes.Clone(im.data), nil
	}
	// The parser has already bounded the signature range. Apple permits up to
	// seven trailing bytes beyond it, regardless of their contents.
	if uint64(len(im.data))-uint64(im.sigOffset)-uint64(im.sigSize) > 7 {
		return nil, unsupported("signature is not at end of slice")
	}
	o, p := im.order, im.linkedit
	linkStart := uint64(o.Uint32(im.data[p+32:]))
	is64 := o.Uint32(im.data[p:]) == 0x19
	if is64 {
		linkStart = o.Uint64(im.data[p+40:])
	}
	end := uint64(im.sigOffset)
	if linkStart > end {
		return nil, malformed("signature precedes LINKEDIT")
	}
	seenSymbols := false
	for _, cmd := range im.commands {
		if cmd.kind != 2 { // LC_SYMTAB
			continue
		}
		if cmd.size != 24 || seenSymbols {
			return nil, malformed("symbol table command")
		}
		seenSymbols = true
		b := im.data[cmd.offset:]
		stringsStart, stringsSize := uint64(o.Uint32(b[16:])), uint64(o.Uint32(b[20:]))
		symbolsStart, symbolCount := uint64(o.Uint32(b[8:])), uint64(o.Uint32(b[12:]))
		entrySize := uint64(12)
		if im.header == 32 {
			entrySize = 16
		}
		// Validate before using untrusted offsets to choose a truncation point.
		// Empty, absent tables may use a zero offset.
		if !rangeOK(stringsStart, stringsSize, end) ||
			(stringsSize != 0 && stringsStart < max(linkStart, uint64(im.header)+uint64(o.Uint32(im.data[20:])))) ||
			!rangeOK(symbolsStart, symbolCount*entrySize, end) ||
			(symbolCount != 0 && symbolsStart < linkStart) {
			return nil, malformed("symbol table range during removal")
		}
		stringsEnd := stringsStart + stringsSize
		if end > stringsEnd && end-stringsEnd <= 12 {
			if stringsEnd < linkStart || symbolsStart+symbolCount*entrySize > stringsEnd {
				return nil, malformed("symbol table overlaps alignment padding")
			}
			end = stringsEnd
		}
	}
	commandsEnd := im.header + int(o.Uint32(im.data[20:]))
	if end < uint64(commandsEnd) {
		return nil, malformed("removal overlaps load commands")
	}
	out := bytes.Clone(im.data[:end])
	copy(out[im.sigCommand:], out[im.sigCommand+16:commandsEnd])
	clear(out[commandsEnd-16 : commandsEnd])
	o.PutUint32(out[16:], o.Uint32(out[16:])-1)
	o.PutUint32(out[20:], o.Uint32(out[20:])-16)
	if p > im.sigCommand {
		p -= 16
	}
	// Deallocation changes only filesize. The signing helper also rounds
	// vmsize, which would incorrectly shrink a large signed LINKEDIT mapping.
	if is64 {
		o.PutUint64(out[p+48:], end-linkStart)
	} else {
		o.PutUint32(out[p+36:], uint32(end-linkStart))
	}
	return out, nil
}
