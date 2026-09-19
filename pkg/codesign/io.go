package codesign

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, unsupported("input exceeds memory limit")
	}
	return b, nil
}

func replaceFile(ctx context.Context, path string, data []byte) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return unsupported("replacing non-regular file")
	}
	// In-place writes retain ownership, xattrs and hard-link semantics. Parsing and
	// construction complete before this function; I/O failure can leave partial data,
	// as with Apple's signing tool. Callers needing atomicity must sign a copy.
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	current, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if !os.SameFile(st, current) {
		f.Close()
		return fmt.Errorf("target changed during signing")
	}
	_, err = f.WriteAt(data, 0)
	if err == nil {
		err = f.Truncate(int64(len(data)))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
