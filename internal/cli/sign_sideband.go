package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-macos-codesign/internal/sideband"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func signWithMetadata(ctx context.Context, path, carrier, manifest string, opts codesign.SignOptions) error {
	var err error
	opts.AppleDouble, opts.AppleDoubleFiles, err = mutableMetadata(ctx, carrier, manifest)
	if err != nil {
		return err
	}
	return codesign.Sign(ctx, path, opts)
}

func mutableMetadata(ctx context.Context, carrier, manifest string) (appledouble.Value, map[string]appledouble.Value, error) {
	if manifest != "" {
		values, err := readSidebandManifest(ctx, manifest)
		return nil, values, err
	}
	if carrier != "" {
		info, err := os.Stat(carrier)
		if err != nil {
			return nil, nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("AppleDouble carrier must be a regular file")
		}
		return &mappedCarrier{path: carrier, info: info}, nil, nil
	}
	return nil, nil, nil
}

// Commit through the held carrier, preserving its identity, hard links, mode and
// native metadata. Encoding completes in bounded-memory temporary storage first.
// A write failure may leave a partial carrier; completed removals never roll back.
func (m *mappedCarrier) RemoveAttribute(ctx context.Context, name string) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.OpenFile(m.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(m.info, info) || info.Size() != m.info.Size() || !info.ModTime().Equal(m.info.ModTime()) {
		return fmt.Errorf("AppleDouble carrier changed before removal")
	}
	staged, err := os.CreateTemp("", "codesign-appledouble-*")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, staged.Close(), os.Remove(staged.Name())) }()
	if err := sideband.RewriteCarrier(ctx, io.NewSectionReader(f, 0, info.Size()), staged, name); err != nil {
		return err
	}
	size, err := staged.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := io.Copy(f, &carrierReader{ctx, io.NewSectionReader(staged, 0, size)}); err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	m.info, err = f.Stat()
	return err
}

type carrierReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *carrierReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
