package codesign

import (
	"context"
	"errors"
	"fmt"
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
		if err := write.bundle.root.Mkdir(write.bundle.base+"_CodeSignature", 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := write.bundle.writeResource(ctx, write.name, write.data); err != nil {
			return err
		}
	}
	return nil
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
