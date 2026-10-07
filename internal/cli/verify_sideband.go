package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"io"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func verifyWithMetadataMap(ctx context.Context, path, carrier, manifest string, opts codesign.VerifyOptions) (*codesign.Report, error) {
	return verificationMetadata(ctx, path, carrier, manifest, opts, codesign.Verify)
}

func visitVerificationWithMetadataMap(ctx context.Context, path, carrier, manifest string, opts codesign.VerifyOptions, visitor codesign.ReportVisitor) error {
	_, err := verificationMetadata(ctx, path, carrier, manifest, opts, func(ctx context.Context, path string, opts codesign.VerifyOptions) (*codesign.Report, error) {
		return nil, codesign.VisitVerification(ctx, path, opts, visitor)
	})
	return err
}

func verificationMetadata(ctx context.Context, path, carrier, manifest string, opts codesign.VerifyOptions, verify func(context.Context, string, codesign.VerifyOptions) (*codesign.Report, error)) (*codesign.Report, error) {
	if manifest != "" {
		var err error
		opts.AppleDoubleFiles, err = readSidebandManifest(ctx, manifest)
		if err != nil {
			return nil, err
		}
	}
	if carrier != "" {
		f, err := os.Open(carrier)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: AppleDouble input must be a regular file", codesign.ErrUnsupported)
		}
		opts.AppleDouble = io.NewSectionReader(f, 0, st.Size())
	}
	return verify(ctx, path, opts)
}

// A manifest is a JSON object mapping object paths to carrier paths. Carrier
// paths are relative to the manifest. Object paths are relative to the resolved
// bundle operand. Absolute paths are explicit, including outside link targets.
func readSidebandManifest(ctx context.Context, path string) (map[string]appledouble.Value, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 8<<20 {
		return nil, fmt.Errorf("AppleDouble map must be a regular file no larger than 8 MiB")
	}
	d := json.NewDecoder(io.LimitReader(f, (8<<20)+1))
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, fmt.Errorf("AppleDouble map must be a JSON object")
	}
	values := make(map[string]appledouble.Value)
	for d.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key := token.(string)
		if key == "" || values[key] != nil || len(values) >= 10000 {
			return nil, fmt.Errorf("invalid, duplicate or excessive AppleDouble map entry")
		}
		var name string
		if err := d.Decode(&name); err != nil {
			return nil, err
		}
		if name == "" {
			return nil, fmt.Errorf("AppleDouble map requires nonempty carrier paths")
		}
		if !filepath.IsAbs(name) {
			name = filepath.Dir(path) + string(filepath.Separator) + name
		}
		info, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("AppleDouble carrier must be a regular file")
		}
		carrier := &mappedCarrier{path: name, info: info}
		for _, previous := range values {
			if existing := previous.(*mappedCarrier); os.SameFile(existing.info, info) {
				carrier = existing
				break
			}
		}
		values[key] = carrier
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing AppleDouble map data")
	}
	return values, nil
}

// Header reads hold a file and verify its identity. They neither allocate a
// resource fork nor exhaust descriptors on large manifests. The caller must
// keep carrier contents stable throughout verification, as for the library API.
type mappedCarrier struct {
	path string
	info os.FileInfo
}

func (c *mappedCarrier) Size() int64 { return c.info.Size() }
func (c *mappedCarrier) ReadAt(p []byte, off int64) (int, error) {
	f, err := os.Open(c.path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !os.SameFile(info, c.info) || info.Size() != c.info.Size() || !info.ModTime().Equal(c.info.ModTime()) {
		return 0, fmt.Errorf("AppleDouble carrier changed during verification")
	}
	return f.ReadAt(p, off)
}
