package codesign

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
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
	// Apple's UDIF writer updates the image in place; MachOEditor replaces its
	// selected directory entry with a prepared copy, detaching every hard link.
	if isDMG(data) {
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
	defer source.Close()
	current, err := source.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(st, current) {
		return fmt.Errorf("target changed during signing")
	}
	replacement, err := hostmeta.PrepareReplacement(source, filepath.Dir(path))
	if err != nil {
		return err
	}
	defer replacement.Close()
	f := replacement.File
	if _, err := f.WriteAt(data, 0); err != nil {
		return err
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return err
	}
	if err := replacement.RestoreMetadata(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := source.Close(); err != nil {
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

func overwriteFile(ctx context.Context, path string, data []byte) error {
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
