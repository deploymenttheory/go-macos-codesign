package sideband

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

const signaturePrefix = "com.apple.cs."

// FileDiskRep removes canonical slots first, then flushes all remaining names
// in its namespace. Listing failures therefore leave a partially removed seal.
var signatureSlots = [...]string{
	"CodeDirectory", "CodeRequirements", "CodeResources", "CodeTopDirectory",
	"CodeEntitlements", "CodeRepSpecific", "CodeEntitlementDER",
	"LaunchConstraintSelf", "LaunchConstraintParent", "LaunchConstraintResponsible",
	"LibraryConstraint", "CodeSignature",
}

// RemoveSignature removes a generic file's attached signature without changing
// its data fork or identity. Native metadata is processed before an explicit
// carrier. Successful mutations survive later errors and cancellation.
func RemoveSignature(ctx context.Context, file *os.File, carrier appledouble.Value) error {
	list := func() ([]string, error) { return hostdata.ListXattrNames(file, hostdata.MaxXattrListSize) }
	if err := removeNativeSignature(ctx, runtime.GOOS, list, func(name string) error {
		return removeAttribute(file, name)
	}); err != nil {
		return err
	}
	if carrier == nil {
		return nil
	}
	f, err := appledouble.DecodeStream(ctx, carrier, appledouble.DefaultStreamLimits())
	if err != nil {
		return err
	}
	names := make([]string, 0, len(f.Attrs))
	for _, attr := range f.Attrs {
		names = append(names, attr.Name)
	}
	return removeSignatureAttributes(ctx, false, func() ([]string, error) { return slices.Clone(names), nil }, func(name string) error {
		if !slices.Contains(names, name) {
			return nil
		}
		mutable, ok := carrier.(MutableCarrier)
		if !ok {
			return fmt.Errorf("signature removal requires a mutable AppleDouble carrier")
		}
		if err := mutable.RemoveAttribute(ctx, name); err != nil {
			return err
		}
		names = slices.DeleteFunc(names, func(n string) bool { return n == name })
		return nil
	})
}

func removeNativeSignature(ctx context.Context, platform string, list func() ([]string, error), remove func(string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if platform == "linux" {
		// Unnamespaced names cannot exist on Linux. Establish absence from the
		// native inventory; never reinterpret user.com.apple.cs.* as Apple names.
		names, err := list()
		if err != nil {
			return err
		}
		original := remove
		remove = func(name string) error {
			if !slices.Contains(names, name) {
				return nil
			}
			return original(name)
		}
	}
	return removeSignatureAttributes(ctx, platform == "windows", list, remove)
}

func removeSignatureAttributes(ctx context.Context, fold bool, list func() ([]string, error), remove func(string) error) error {
	for _, slot := range signatureSlots {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := remove(signaturePrefix + slot); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	names, err := list()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		match := name
		if fold {
			match = strings.ToLower(name) // NTFS EA names are case-insensitive.
		}
		if strings.HasPrefix(match, signaturePrefix) {
			if err := remove(name); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
