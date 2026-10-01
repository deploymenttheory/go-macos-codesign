package codesign

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-macos-codesign/internal/sideband"
)

func sidebandOptions(ctx context.Context, opts VerifyOptions, bytesOnly bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.AppleDouble != nil && (!opts.StrictSideband || opts.NoStrict) {
		return unsupported("AppleDouble input requires enabled strict sideband verification")
	}
	if bytesOnly && opts.StrictSideband && !opts.NoStrict && opts.sidebandFile == nil {
		return unsupported("strict sideband verification requires a held filesystem object; use Verify")
	}
	return nil
}

// Apple checks code bytes and signature slots before SingleDiskRep sideband
// policy, and performs the remaining strict Mach-O layout checks afterwards.
// This stage does not acquire a second file by name or mutate either input.
func verifySideband(ctx context.Context, opts VerifyOptions) error {
	if !opts.StrictSideband || opts.NoStrict {
		return nil
	}
	name, err := sideband.First(ctx, opts.sidebandFile, opts.AppleDouble)
	if err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	message := fmt.Sprintf("Disallowed xattr %s found on %s", name, opts.sidebandPath)
	return &VerificationError{
		Diagnostic:       "resource fork, Finder information, or similar detritus not allowed",
		AttachedData:     []string{message},
		cause:            invalid("%s", message),
		omitArchitecture: true,
	}
}
