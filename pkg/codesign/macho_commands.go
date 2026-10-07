package codesign

import (
	"bytes"
	"context"
	"sort"
)

// signingCommandOutput owns only the changed fields. Untouched commands remain
// borrowed source ranges regardless of sizeofcmds or the number of commands.
func signingCommandOutput(ctx context.Context, im *image, source outputSource, codeEnd, sigSize, end int64) (outputSource, error) {
	commandsEnd := int64(im.header) + int64(im.commandBytes)
	headSize := commandsEnd
	if im.sigCommand < 0 {
		headSize += 16
	}
	if headSize > source.size {
		return outputSource{}, unsupported("no room for LC_CODE_SIGNATURE")
	}
	// Read the fixed header from the held source, preserving byte-path ownership
	// and reporting source failures before creating any generated metadata.
	header, err := (codeSource{ctx, source}).read(0, uint64(im.header))
	if err != nil {
		return outputSource{}, err
	}
	pos := int64(im.sigCommand)
	if pos < 0 {
		pos = commandsEnd
		padding, err := (codeSource{ctx, source}).read(uint64(pos), 16)
		if err != nil {
			return outputSource{}, err
		}
		if uint64(pos+16) > im.firstSection || !bytes.Equal(padding, make([]byte, 16)) {
			return outputSource{}, unsupported("no room for LC_CODE_SIGNATURE")
		}
		im.order.PutUint32(header[16:], im.commandCount+1)
		im.order.PutUint32(header[20:], im.commandBytes+16)
	}
	command := make([]byte, 16)
	im.order.PutUint32(command, 0x1d)
	im.order.PutUint32(command[4:], 16)
	im.order.PutUint32(command[8:], uint32(codeEnd))
	im.order.PutUint32(command[12:], uint32(sigSize))
	patches := []outputSpan{{0, byteOutput(header)}, {pos, byteOutput(command)}}
	size := uint64(end) - im.linkStart
	if im.linkeditKind == 0x19 {
		vm, file := make([]byte, 8), make([]byte, 8)
		im.order.PutUint64(vm, (size+16383)&^uint64(16383))
		im.order.PutUint64(file, size)
		patches = append(patches, outputSpan{int64(im.linkedit) + 32, byteOutput(vm)}, outputSpan{int64(im.linkedit) + 48, byteOutput(file)})
	} else {
		fields := make([]byte, 12)
		im.order.PutUint32(fields, (uint32(size)+16383)&^uint32(16383))
		im.order.PutUint32(fields[4:], uint32(im.linkStart))
		im.order.PutUint32(fields[8:], uint32(size))
		patches = append(patches, outputSpan{int64(im.linkedit) + 28, byteOutput(fields)})
	}
	sort.Slice(patches, func(i, j int) bool { return patches[i].start < patches[j].start })
	return patchedOutput(source, end, patches...)
}
