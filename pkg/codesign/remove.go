package codesign

import "context"

// removeImageSource follows the deallocation rules recorded in
// spec/apple-removal.json. In particular, the symbol string table determines
// alignment padding; scanning trailing zero bytes would destroy real data.
func removeImageSource(ctx context.Context, im *image, source outputSource) (outputSource, error) {
	switch im.filetype {
	case 2, 6, 7, 8, 11: // executable, dylib, dylinker, bundle, kext
	default:
		return outputSource{}, unsupported("Mach-O file type for signature removal")
	}
	if im.linkedit < 0 {
		return outputSource{}, malformed("missing LINKEDIT")
	}
	if im.sigCommand < 0 {
		return source, nil
	}
	// The parser has already bounded the signature range. Apple permits up to
	// seven trailing bytes beyond it, regardless of their contents.
	if uint64(source.size)-uint64(im.sigOffset)-uint64(im.sigSize) > 7 {
		return outputSource{}, unsupported("signature is not at end of slice")
	}
	o, p := im.order, im.linkedit
	linkStart := im.linkStart
	is64 := im.linkeditKind == 0x19
	end := uint64(im.sigOffset)
	if linkStart > end {
		return outputSource{}, malformed("signature precedes LINKEDIT")
	}
	if sym := im.symbols; sym.present {
		if sym.size != 24 {
			return outputSource{}, malformed("symbol table command")
		}
		stringsStart, stringsSize, symbolsStart, symbolCount := sym.strings, sym.stringSize, sym.symbols, sym.count
		entrySize := uint64(12)
		if im.header == 32 {
			entrySize = 16
		}
		if !rangeOK(stringsStart, stringsSize, end) ||
			(stringsSize != 0 && stringsStart < max(linkStart, uint64(im.header)+uint64(im.commandBytes))) ||
			!rangeOK(symbolsStart, symbolCount*entrySize, end) || (symbolCount != 0 && symbolsStart < linkStart) {
			return outputSource{}, malformed("symbol table range during removal")
		}
		stringsEnd := stringsStart + stringsSize
		if end > stringsEnd && end-stringsEnd <= 12 {
			if stringsEnd < linkStart || symbolsStart+symbolCount*entrySize > stringsEnd {
				return outputSource{}, malformed("symbol table overlaps alignment padding")
			}
			end = stringsEnd
		}
		if sym.duplicate {
			return outputSource{}, malformed("symbol table command")
		}
	}
	commandsEnd := int64(im.header) + int64(im.commandBytes)
	if end < uint64(commandsEnd) {
		return outputSource{}, malformed("removal overlaps load commands")
	}
	header, err := (codeSource{ctx, source}).read(0, uint64(im.header))
	if err != nil {
		return outputSource{}, err
	}
	o.PutUint32(header[16:], im.commandCount-1)
	o.PutUint32(header[20:], im.commandBytes-16)
	// Shift commands as a borrowed range rather than copying sizeofcmds bytes.
	shifted, err := patchedOutput(source, int64(end),
		outputSpan{0, byteOutput(header)},
		outputSpan{int64(im.sigCommand), outputSource{reader: source.reader, offset: source.offset + int64(im.sigCommand) + 16, size: commandsEnd - int64(im.sigCommand) - 16}},
		outputSpan{commandsEnd - 16, outputSource{reader: zeroSource{}, size: 16}})
	if err != nil {
		return outputSource{}, err
	}
	if p > im.sigCommand {
		p -= 16
	}
	// Deallocation changes only filesize; it does not shrink LINKEDIT vmsize.
	field := make([]byte, 4)
	at := p + 36
	if is64 {
		field = make([]byte, 8)
		at = p + 48
		o.PutUint64(field, end-linkStart)
	} else {
		o.PutUint32(field, uint32(end-linkStart))
	}
	return patchedOutput(shifted, int64(end), outputSpan{int64(at), byteOutput(field)})
}
