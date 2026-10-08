package sideband

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
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

// SignatureComponents returns the canonical component names shared by
// FileDiskRep attributes and BundleDiskRep metadata files, in native slot order.
// The returned slice belongs to the caller.
func SignatureComponents() []string { return slices.Clone(signatureSlots[:]) }

// RemoveSignature removes a generic file's attached signature without changing
// its data fork or identity. Native metadata is processed before an explicit
// carrier. Successful mutations survive later errors and cancellation.
func RemoveSignature(ctx context.Context, file *os.File, carrier appledouble.Value) (err error) {
	return RemoveSignatureBeforeFlush(ctx, file, carrier, nil)
}

// RemoveSignatureBeforeFlush performs the enclosing representation's component
// removal after canonical slots and before the generic writer's namespace flush.
// BundleDiskRep uses this order even when the later attribute listing fails.
// Explicit library carriers retain native-before-explicit processing.
func RemoveSignatureBeforeFlush(ctx context.Context, file *os.File, carrier appledouble.Value, beforeFlush func() error) (err error) {
	q, err := openFilesystemQueries(ctx, file)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, q.view.Close()) }()
	nativeBeforeFlush := beforeFlush
	if carrier != nil {
		nativeBeforeFlush = nil
	}
	if err = removeNativeSignatureSteps(ctx, q.platform(), q.list, q.remove, nativeBeforeFlush); err != nil {
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
	return removeSignatureAttributeSteps(ctx, false, func() ([]string, error) { return slices.Clone(names), nil }, func(name string) error {
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
	}, beforeFlush)
}

func removeNativeSignature(ctx context.Context, platform string, list func() ([]string, error), remove func(string) error) error {
	return removeNativeSignatureSteps(ctx, platform, list, remove, nil)
}

func removeNativeSignatureSteps(ctx context.Context, platform string, list func() ([]string, error), remove func(string) error, beforeFlush func() error) error {
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
	return removeSignatureAttributeSteps(ctx, platform == "windows", list, remove, beforeFlush)
}

func removeSignatureAttributes(ctx context.Context, fold bool, list func() ([]string, error), remove func(string) error) error {
	return removeSignatureAttributeSteps(ctx, fold, list, remove, nil)
}

func removeSignatureAttributeSteps(ctx context.Context, fold bool, list func() ([]string, error), remove func(string) error, beforeFlush func() error) error {
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
	if beforeFlush != nil {
		if err := beforeFlush(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
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
