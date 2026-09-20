package codesign

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

type preparedBundleExecutable struct {
	write       bundleWrite
	original    os.FileInfo
	replacement *hostmeta.RootReplacement
}

// Construct and stage every executable before the first resource or executable
// commit. Commit order remains descendant-first, with each resource envelope
// preceding its main executable. Later commit failures do not roll back earlier
// writes; each Mach-O commit replaces only its selected directory entry.
func commitBundleWrites(ctx context.Context, writes []bundleWrite) (result error) {
	prepared := make([]*preparedBundleExecutable, len(writes))
	defer func() {
		for _, p := range prepared {
			if p != nil {
				result = errors.Join(result, p.replacement.Close())
			}
		}
	}()
	for i, write := range writes {
		if write.kind == bundleMachOWrite {
			p, err := prepareBundleExecutable(ctx, write)
			if err != nil {
				return err
			}
			prepared[i] = p
		}
	}
	for i, write := range writes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p := prepared[i]; p != nil {
			if err := p.commit(); err != nil {
				return err
			}
			continue
		}
		if write.kind == bundleSignatureCleanup {
			if err := write.bundle.purgeSignatureFiles(ctx, true); err != nil {
				return err
			}
			continue
		}
		if err := write.bundle.root.Mkdir(write.bundle.base+"_CodeSignature", 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := write.bundle.writeResource(ctx, write.name, write.data); err != nil {
			return err
		}
	}
	return nil
}

// Apple flushes the metadata directory after committing the main executable.
// Only regular files are supported; unlink them without following links or
// replacing or rewriting any hard-link neighbours. Keep the directory itself.
func (b *appBundle) purgeSignatureFiles(ctx context.Context, keepResources bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := b.base + "_CodeSignature"
	st, err := b.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return unsupported("signature directory is not a directory")
	}
	root, err := b.root.OpenRoot(name)
	if err != nil {
		return err
	}
	defer root.Close()
	current, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(st, current) {
		return fmt.Errorf("bundle signature directory changed")
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	for count := 0; ; count++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := dir.ReadDir(1)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if count >= maxBundleEntries {
			return unsupported("signature directory entry count limit")
		}
		entry := entries[0].Name()
		info, err := root.Lstat(entry)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return unsupported("non-regular signature file: " + entry)
		}
		if keepResources && entry == "CodeResources" {
			continue
		}
		if err := root.Remove(entry); err != nil {
			return err
		}
	}
}

func prepareBundleExecutable(ctx context.Context, write bundleWrite) (_ *preparedBundleExecutable, result error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := write.bundle.root
	st, err := root.Lstat(write.name)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, unsupported("writing non-regular bundle file")
	}
	source, err := root.Open(write.name)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	current, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(st, current) {
		return nil, fmt.Errorf("bundle write target changed")
	}
	r, err := hostmeta.PrepareReplacementAt(source, root, filepath.Dir(write.name))
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, r.Close())
		}
	}()
	if _, err := r.File.WriteAt(write.data, 0); err != nil {
		return nil, err
	}
	if err := r.File.Truncate(int64(len(write.data))); err != nil {
		return nil, err
	}
	if err := r.RestoreMetadata(); err != nil {
		return nil, err
	}
	if err := r.File.Sync(); err != nil {
		return nil, err
	}
	if err := r.File.Close(); err != nil {
		return nil, err
	}
	if err := source.Close(); err != nil {
		return nil, err
	}
	return &preparedBundleExecutable{write: write, original: st, replacement: r}, nil
}

func (p *preparedBundleExecutable) commit() error {
	root := p.write.bundle.root
	current, err := root.Lstat(p.write.name)
	if err != nil {
		return err
	}
	if !os.SameFile(p.original, current) {
		return fmt.Errorf("bundle write target changed")
	}
	return root.Rename(p.replacement.Path, p.write.name)
}
