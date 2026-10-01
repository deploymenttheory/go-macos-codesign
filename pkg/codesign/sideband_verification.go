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
	if (opts.AppleDouble != nil || len(opts.AppleDoubleFiles) != 0) && (!opts.StrictSideband || opts.NoStrict) {
		return unsupported("AppleDouble input requires enabled strict sideband verification")
	}
	if bytesOnly && opts.StrictSideband && !opts.NoStrict && opts.sidebandFile == nil && opts.sidebandObject == nil {
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
	var name string
	var err error
	if opts.sidebandObject != nil {
		name, err = opts.sidebandObject.first(ctx)
	} else {
		name, err = sideband.First(ctx, opts.sidebandFile, opts.AppleDouble)
	}
	if err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	return sidebandFailure(opts.sidebandPath, []string{name}, false)
}

func sidebandFailure(path string, names []string, resource bool) error {
	var messages []string
	for _, name := range names {
		messages = append(messages, fmt.Sprintf("Disallowed xattr %s found on %s", name, path))
	}
	return &VerificationError{
		Diagnostic:       "resource fork, Finder information, or similar detritus not allowed",
		AttachedData:     messages,
		cause:            invalid("%s", messages),
		resourceFailure:  resource,
		omitArchitecture: true,
	}
}
