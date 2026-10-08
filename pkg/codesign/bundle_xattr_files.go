package codesign

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// DirValidator permits an attribute carrier at the bundle root only on a
// filesystem using xattr files, and only if the companion has visible attrs.
// ResourceBuilder does not apply this exemption to nested-code traversal.
func (b *appBundle) validXattrFile(ctx context.Context, name string, entry fs.DirEntry) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	base := path.Base(name)
	if !entry.Type().IsRegular() || !strings.HasPrefix(base, "._") || len(base) < 3 {
		return false, nil
	}
	directory, err := b.root.Open(".")
	if err != nil {
		return false, ctx.Err()
	}
	uses, err := hostdata.FilesystemUsesXattrFiles(ctx, directory)
	err = errors.Join(err, directory.Close())
	if err != nil || !uses {
		return false, ctx.Err()
	}
	companion := path.Join(path.Dir(name), base[2:])
	view, err := hostdata.OpenFilesystemMetadata(ctx, b.root, companion)
	if err != nil {
		return false, ctx.Err()
	}
	names, err := view.List(ctx, hostdata.MaxXattrListSize)
	err = errors.Join(err, view.Close())
	if err != nil {
		return false, ctx.Err()
	}
	return len(names) != 0, ctx.Err()
}

// A regular nested resource can be a generic FileDiskRep rather than Mach-O.
// Absence of its CodeDirectory is an unsigned-code failure, not a malformed
// Mach-O. Retain parser errors for recognized executable formats and retain
// the unsupported-format result for signed generic objects pending that API.
func (b *appBundle) nestedFormatError(ctx context.Context, name string, data codeSource, formatErr error) error {
	generic, err := genericRemovalReader(ctx, data.source.reader, data.source.size)
	if err != nil {
		return err
	}
	if !generic {
		return formatErr
	}
	view, err := hostdata.FilesystemMetadataForFile(ctx, b.sources[name].file)
	if err != nil {
		return err
	}
	_, signed, err := view.Size(ctx, "com.apple.cs.CodeDirectory")
	// FileDiskRep::getAttribute treats these failures as an absent component.
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, hostdata.ErrXattrUnsupported) {
		signed, err = false, nil
	}
	err = errors.Join(err, view.Close())
	if err != nil {
		return err
	}
	if signed {
		return formatErr
	}
	return signingNestedError(filepath.Join(b.sidebandBase, filepath.FromSlash(name)), verificationFailure(ErrUnsigned.Error(), ErrUnsigned))
}

// Verification removes present, valid attribute files from the missing-resource
// inventory without comparing their bytes or requiring a nested signature.
type xattrResourceExemption struct{}
