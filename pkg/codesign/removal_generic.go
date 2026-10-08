package codesign

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-macos-codesign/internal/sideband"
)

// SingleDiskRep::Writer lazily opens O_RDWR even when no signature exists.
// Bind that writable handle to the classified object before any mutation.
func removeGenericSignature(ctx context.Context, original *os.File, open func() (*os.File, error), carrier appledouble.Value) (result error) {
	return removeGenericSignatureBeforeFlush(ctx, original, open, carrier, nil)
}

func removeGenericSignatureBeforeFlush(ctx context.Context, original *os.File, open func() (*os.File, error), carrier appledouble.Value, beforeFlush func() error) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := original.Stat()
	if err != nil {
		return err
	}
	f, err := open()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) {
		return invalid("generic file changed before signature removal")
	}
	return sideband.RemoveSignatureBeforeFlush(ctx, f, carrier, beforeFlush)
}

// Match Universal::typeOf's bounded header probe. A short header or MH_OBJECT
// is generic, while a recognized executable with malformed commands must still
// fail through the Mach-O parser. Attribute-only removal never reads a whole
// generic data fork into memory, including files above the Mach-O memory limit.
func genericRemovalCandidate(ctx context.Context, f *os.File) (bool, error) {
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !st.Mode().IsRegular() {
		return false, unsupported("non-regular file")
	}
	return genericRemovalReader(ctx, f, st.Size())
}

func genericRemovalReader(ctx context.Context, reader io.ReaderAt, size int64) (bool, error) {
	var header [28]byte
	var offset int64
	for tries := 0; tries < 3; tries++ {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		n, err := reader.ReadAt(header[:], offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}
		if n != len(header) {
			break
		}
		var kind uint32
		switch be.Uint32(header[:]) {
		case 0xfeedface, 0xfeedfacf:
			kind = be.Uint32(header[12:])
		case 0xcefaedfe, 0xcffaedfe:
			kind = binary.LittleEndian.Uint32(header[12:])
		case 0xcafebabe, 0xbebafeca:
			offset = int64(be.Uint32(header[16:]))
			continue
		case 0xcafebabf, 0xbfbafeca:
			// Retain the existing FAT64 parser/validation path.
			return false, nil
		}
		switch kind {
		case 2, 5, 6, 7, 8, 11: // EXECUTE, PRELOAD, DYLIB, DYLINKER, BUNDLE, KEXT_BUNDLE
			return false, nil
		}
		break
	}
	// Specialized disk/cache representations must never fall through to xattr
	// removal. Their signing/removal support remains a separate format contract.
	var start [72]byte
	_, err := reader.ReadAt(start[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if size >= 72 && (string(start[:4]) == "encr" || string(start[4:8]) == "cdsa") && be.Uint32(start[8:]) == 2 {
		return false, unsupported("signature removal for encrypted disk images")
	}
	if string(start[:7]) == "dyld_v1" {
		return false, unsupported("signature removal for dyld caches")
	}
	if size >= 520 {
		var tail [8]byte
		if _, err := reader.ReadAt(tail[:], size-512); err != nil {
			return false, err
		}
		if string(tail[:4]) == "koly" && be.Uint32(tail[4:]) == 4 {
			return false, unsupported("signature removal for disk images")
		}
	}
	return true, ctx.Err()
}
