package codesign

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/accesstime"
)

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	return readBoundedContext(context.Background(), r, limit)
}

func readBoundedContext(ctx context.Context, r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 || limit == math.MaxInt64 {
		return nil, malformed("input memory limit")
	}
	b, err := io.ReadAll(io.LimitReader(operationReader{ctx, r}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, unsupported("input exceeds memory limit")
	}
	return b, nil
}

func replaceFile(ctx context.Context, path string, data []byte) error {
	return writeFile(ctx, path, data, false)
}

func writeFile(ctx context.Context, path string, data []byte, dryRun bool) (result error) {
	// Apple's UDIF writer updates the image in place; MachOEditor replaces its
	// selected directory entry with a prepared copy, detaching every hard link.
	if isDMG(data) {
		// Native UDIF dry runs still flush their components and trailer in place.
		// The signer omits the CodeDirectory in that case, leaving unsigned code.
		return overwriteFile(ctx, path, data)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return unsupported("replacing non-regular file")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	sourceCloser := operationCloser{source.Close}
	defer func() { result = errors.Join(result, sourceCloser.Close()) }()
	return replaceSource(ctx, path, source, &sourceCloser, st, byteOutput(data), dryRun)
}

// Keep the preflight descriptor through payload transfer and metadata restore.
// Windows requires closing that ordinary read handle before the final rename.
func replaceSource(ctx context.Context, path string, source *os.File, sourceCloser *operationCloser, st os.FileInfo, output outputSource, dryRun bool) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() {
		return unsupported("replacing non-regular file")
	}
	if !os.SameFile(st, current) {
		return fmt.Errorf("target changed during signing")
	}
	if err := sourceUnchanged(source, st); err != nil {
		return err
	}
	replacement, err := hostdata.PrepareReplacementContext(ctx, source, filepath.Dir(path))
	if err != nil {
		return err
	}
	replacementCloser := operationCloser{replacement.Close}
	defer func() { result = errors.Join(result, replacementCloser.Close()) }()
	// Mach-O dry runs require a temporary allocation but do not restore metadata
	// or commit it. This checks directory permissions without touching source bytes.
	if dryRun {
		return ctx.Err()
	}
	f := replacement.File
	if err := populateOutput(ctx, f, output, func() error {
		if err := sourceUnchanged(source, st); err != nil {
			return err
		}
		if err := replacement.RestoreMetadataContext(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := accesstime.RecordReadAccess(f); err != nil && !errors.Is(err, accesstime.ErrReadAccessUnsupported) {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := sourceCloser.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err = os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(st, current) {
		return fmt.Errorf("target changed during signing")
	}
	return os.Rename(f.Name(), path)
}

func overwriteFile(ctx context.Context, path string, data []byte) (result error) {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return unsupported("replacing non-regular file")
	}
	// UDIF updates retain ownership, attributes and the inode shared by hard links.
	// Construction completes first, but an I/O failure can leave partial data.
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	current, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(st, current) {
		return fmt.Errorf("target changed during signing")
	}
	return populateOutput(ctx, f, byteOutput(data), nil)
}
