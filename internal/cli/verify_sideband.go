package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func verifyWithMetadata(ctx context.Context, path, carrier string, opts codesign.VerifyOptions) (*codesign.Report, error) {
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
	return codesign.Verify(ctx, path, opts)
}
