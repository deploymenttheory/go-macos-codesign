package codesign

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
)

func signDMGFile(ctx context.Context, file *os.File, path string, source codeSource, opts SignOptions) error {
	before, err := file.Stat()
	if err != nil {
		return err
	}
	trailer, err := source.read(uint64(source.source.size)-uint64(dmgFooterSize), uint64(dmgFooterSize))
	if err != nil {
		return err
	}
	m, err := parseDMGRange(uint64(source.source.size), trailer, source.read)
	if err != nil {
		return err
	}
	if m.signature != nil {
		if opts.Force && opts.OnReplace != nil {
			opts.OnReplace()
		}
		if !opts.Force && m.signature.Directories[0].Flags&0x20000 == 0 {
			return ErrSigned
		}
	}
	if opts.Identifier == "" {
		opts.Identifier = m.identifier(path, opts.Identity == nil)
	}
	if err := prepareSigningOptions(&opts); err != nil {
		return err
	}
	tail, err := signDMGTailSource(ctx, m, opts, opts.DryRun, source.digest)
	if err != nil {
		return err
	}
	if err := sourceUnchanged(file, before); err != nil {
		return err
	}
	return writeDMGTailSource(ctx, path, file, before, m.footer.CodeSignatureOffset, tail)
}

// The payload has already been hashed. Apple's Writer::flush writes only the
// signature and trailer, then truncates; the source and destination never overlap
// bytes still needed for hashing. Existing hard links retain the same object.
func writeDMGTail(ctx context.Context, path string, source *os.File, before os.FileInfo, offset uint64, tail []byte) (result error) {
	return writeDMGTailSource(ctx, path, source, before, offset, byteOutput(tail))
}

func writeDMGTailSource(ctx context.Context, path string, source *os.File, before os.FileInfo, offset uint64, tail outputSource) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return unsupported("replacing non-regular file")
	}
	if !os.SameFile(before, st) {
		return fmt.Errorf("target changed during signing")
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	current, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, current) {
		return fmt.Errorf("target changed during signing")
	}
	if err := sourceUnchanged(source, before); err != nil {
		return err
	}
	return populateDMGTailSource(ctx, f, offset, tail)
}

type tailOutput struct {
	outputFile
	offset int64
}

func (w tailOutput) WriteAt(p []byte, offset int64) (int, error) {
	return w.outputFile.WriteAt(p, w.offset+offset)
}

func (w tailOutput) Truncate(size int64) error { return w.outputFile.Truncate(w.offset + size) }

func populateDMGTail(ctx context.Context, dst outputFile, offset uint64, tail []byte) error {
	return populateDMGTailSource(ctx, dst, offset, byteOutput(tail))
}

func populateDMGTailSource(ctx context.Context, dst outputFile, offset uint64, tail outputSource) error {
	if tail.size < 0 || uint64(tail.size) > math.MaxInt64 || offset > math.MaxInt64-uint64(tail.size) {
		return malformed("disk image output range")
	}
	return populateOutput(ctx, tailOutput{dst, int64(offset)}, tail, nil)
}
