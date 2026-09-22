package codesign

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

type preparedBundleExecutable struct {
	write       bundleWrite
	original    os.FileInfo
	staged      os.FileInfo
	replacement *hostmeta.RootReplacement
}

type bundleAllocationError struct {
	err      error
	original os.FileInfo
}

func (e *bundleAllocationError) Error() string { return e.err.Error() }
func (e *bundleAllocationError) Unwrap() error { return e.err }

func commitBundleWrites(ctx context.Context, writes []bundleWrite) error {
	return applyBundleWrites(ctx, writes, false)
}

// Stage executables before committing resource envelopes and replacements.
// Allocation permission failures retain the affected envelope and independent
// sibling commits, but prevent ancestor writes. Other preparation errors abort.
func applyBundleWrites(ctx context.Context, writes []bundleWrite, dryRun bool) (result error) {
	prepared := make([]*preparedBundleExecutable, len(writes))
	allocationErrors := make([]*bundleAllocationError, len(writes))
	failed, blocked := map[*appBundle]bool{}, map[*appBundle]bool{}
	var allocationErr error
	defer func() {
		for _, p := range prepared {
			if p != nil {
				result = errors.Join(result, p.replacement.Close())
			}
		}
	}()
	for i, write := range writes {
		if write.kind != bundleMachOWrite {
			continue
		}
		b := write.bundle
		if write.name == b.executable {
			for _, child := range b.children {
				if failed[child] {
					failed[b], blocked[b] = true, true
				}
			}
			if blocked[b] {
				continue
			}
		}
		p, err := prepareBundleExecutable(ctx, write, dryRun)
		if err != nil {
			var allocation *bundleAllocationError
			if !errors.As(err, &allocation) {
				return err
			}
			allocationErrors[i] = allocation
			allocationErr = errors.Join(allocationErr, err)
			failed[b] = true
			if write.name != b.executable {
				blocked[b] = true
			}
			continue
		}
		prepared[i] = p
	}
	if dryRun {
		return allocationErr
	}
	for i, write := range writes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if blocked[write.bundle] && (write.kind != bundleMachOWrite || write.name == write.bundle.executable) {
			continue
		}
		if allocation := allocationErrors[i]; allocation != nil {
			if err := recordBundleReadAccess(write.bundle.root, write.name, allocation.original); err != nil {
				return errors.Join(allocationErr, err)
			}
			continue
		}
		if p := prepared[i]; p != nil {
			if err := p.commit(ctx); err != nil {
				return err
			}
			continue
		}
		if err := write.bundle.createSignatureDirectory(ctx); err != nil {
			return err
		}
		if err := write.bundle.writeResource(ctx, write.name, write.data); err != nil {
			return err
		}
	}
	return allocationErr
}

// Copy root stat metadata into newly created signature directories. Leave
// existing directories unchanged; explicit ACL entries are not copied.
func (b *appBundle) createSignatureDirectory(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := b.base + "_CodeSignature"
	if err := b.root.Mkdir(name, 0755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	canonical := "."
	if b.version != "" {
		canonical = b.base
	}
	source, err := b.root.Open(canonical)
	if err != nil {
		return err
	}
	defer source.Close()
	st, err := b.root.Lstat(name)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return unsupported("signature directory is not a directory")
	}
	target, err := b.root.Open(name)
	if err != nil {
		return err
	}
	defer target.Close()
	current, err := target.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(st, current) {
		return fmt.Errorf("bundle signature directory changed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return hostmeta.CopyDirectoryStat(source, target)
}

// Purge regular signature files after executable commit. Keep the directory and
// preserve hard-link neighbours by unlinking entries without following symlinks.
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
	// Use case-insensitive APFS order so partial cleanup leaves the same entries
	// on every host. Read one extra entry to detect overflow with bounded memory.
	entries, err := dir.ReadDir(maxBundleEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) > maxBundleEntries {
		return unsupported("signature directory entry count limit")
	}
	type signatureEntry struct {
		name string
		hash uint32
	}
	ordered := make([]signatureEntry, len(entries))
	for i, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		ordered[i] = signatureEntry{entry.Name(), apfs.CalculateNameHash([]byte(entry.Name()), true)}
	}
	slices.SortFunc(ordered, func(a, b signatureEntry) int {
		if a.hash < b.hash {
			return -1
		}
		if a.hash > b.hash {
			return 1
		}
		return apfs.CompareNamesWithUTF8([]byte(a.name), []byte(b.name), true)
	})
	for _, entry := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := root.Lstat(entry.name)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return unsupported("non-regular signature file: " + entry.name)
		}
		if keepResources && entry.name == "CodeResources" {
			continue
		}
		if err := root.Remove(entry.name); err != nil {
			return err
		}
	}
	return nil
}

func prepareBundleExecutable(ctx context.Context, write bundleWrite, dryRun bool) (_ *preparedBundleExecutable, result error) {
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
	// Dry runs reach allocation without writing envelopes or committing children.
	if dryRun {
		if err := hostmeta.RecordReadAccess(source); err != nil && !errors.Is(err, hostmeta.ErrReadAccessUnsupported) {
			return nil, err
		}
	}
	created := time.Now()
	if st.ModTime().Before(created) {
		created = st.ModTime()
	}
	r, err := hostmeta.PrepareReplacementAt(source, root, filepath.Dir(write.name))
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, &bundleAllocationError{err: err, original: st}
		}
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, r.Close())
		}
	}()
	if dryRun {
		return nil, errors.Join(ctx.Err(), r.Close())
	}
	if _, err := r.File.WriteAt(write.data, 0); err != nil {
		return nil, err
	}
	if err := r.File.Truncate(int64(len(write.data))); err != nil {
		return nil, err
	}
	// Darwin's new executable inherits an earlier source modification time as
	// its creation time. Other hosts retain their replacement metadata policy.
	if err := hostmeta.SetCreationTime(r.File, created); err != nil && !errors.Is(err, hostmeta.ErrCreationTimeUnsupported) {
		return nil, err
	}
	if err := r.RestoreMetadata(); err != nil {
		return nil, err
	}
	if err := r.File.Sync(); err != nil {
		return nil, err
	}
	staged, err := r.File.Stat()
	if err != nil {
		return nil, err
	}
	if err := r.File.Close(); err != nil {
		return nil, err
	}
	if err := source.Close(); err != nil {
		return nil, err
	}
	return &preparedBundleExecutable{write: write, original: st, staged: staged, replacement: r}, nil
}

func (p *preparedBundleExecutable) commit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.copySourceAccess(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root := p.write.bundle.root
	current, err := root.Lstat(p.write.name)
	if err != nil {
		return err
	}
	if !os.SameFile(p.original, current) {
		return fmt.Errorf("bundle write target changed")
	}
	if err := root.Rename(p.replacement.Path, p.write.name); err != nil {
		return err
	}
	if p.write.cleanup != bundleCleanupNone {
		if err := p.write.bundle.purgeSignatureFiles(ctx, p.write.cleanup == bundleCleanupKeepResources); err != nil {
			return err
		}
	}
	return p.recordReadAccess()
}

// Refresh the committed inode only after its signature cleanup succeeds.
// Failed cleanup retains the replacement's copied source access time.
func (p *preparedBundleExecutable) recordReadAccess() error {
	return recordBundleReadAccess(p.write.bundle.root, p.write.name, p.staged)
}

// Defer source access until preceding envelope writes and descendant cleanup
// succeed. Copy its exact time into the private replacement before rename.
func (p *preparedBundleExecutable) copySourceAccess() (result error) {
	root := p.write.bundle.root
	source, err := openBundleExecutable(root, p.write.name, p.original)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, source.Close()) }()
	target, err := openBundleExecutable(root, p.replacement.Path, p.staged)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, target.Close()) }()
	if err := hostmeta.RecordReadAccess(source); err != nil && !errors.Is(err, hostmeta.ErrReadAccessUnsupported) {
		return err
	}
	if err := hostmeta.CopyAccessTime(source, target); err != nil {
		if errors.Is(err, hostmeta.ErrAccessTimeUnsupported) {
			return nil
		}
		return err
	}
	return target.Sync()
}

func recordBundleReadAccess(root *os.Root, name string, expected os.FileInfo) error {
	file, err := openBundleExecutable(root, name, expected)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := hostmeta.RecordReadAccess(file); err != nil && !errors.Is(err, hostmeta.ErrReadAccessUnsupported) {
		return err
	}
	return file.Close()
}

func openBundleExecutable(root *os.Root, name string, expected os.FileInfo) (*os.File, error) {
	current, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(expected, current) {
		return nil, fmt.Errorf("bundle executable changed")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	current, err = file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if !os.SameFile(expected, current) {
		return nil, errors.Join(fmt.Errorf("bundle executable changed"), file.Close())
	}
	return file, nil
}
