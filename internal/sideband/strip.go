package sideband

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// MutableCarrier explicitly authorizes changes to a supplied metadata snapshot.
// Removal must preserve unrelated values and make subsequent reads see the change.
// Each successful removal is permanent, including during dry runs or later errors.
type MutableCarrier interface {
	appledouble.Value
	RemoveAttribute(context.Context, string) error
}

// Strip removes only nonempty prohibited attributes, from the held native object
// first, then an explicitly supplied mutable carrier. It does not roll back a
// completed removal when a later query, removal or cancellation fails.
func Strip(ctx context.Context, file *os.File, carrier appledouble.Value) error {
	if err := stripNative(ctx, runtime.GOOS,
		func() ([]string, error) { return hostdata.ListXattrNames(file, hostdata.MaxXattrListSize) },
		func(name string) (int, bool, error) { return hostdata.XattrSize(file, name) },
		func(name string) error { return removeAttribute(file, name) }); err != nil {
		return err
	}
	if carrier == nil {
		return nil
	}
	attrs, err := inspectCarrier(ctx, carrier)
	if err != nil {
		return err
	}
	for _, name := range attrs.Names() {
		if err := ctx.Err(); err != nil {
			return err
		}
		mutable, ok := carrier.(MutableCarrier)
		if !ok {
			return fmt.Errorf("AppleDouble stripping requires a mutable carrier")
		}
		if err := mutable.RemoveAttribute(ctx, name); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func removeAttribute(file *os.File, name string) error {
	removed, err := hostdata.RemoveXattr(file, name)
	if err == nil && !removed {
		return fmt.Errorf("attribute disappeared before removal: %s", name)
	}
	return err
}

func stripNative(ctx context.Context, platform string, list func() ([]string, error), size func(string) (int, bool, error), remove func(string) error) error {
	var removal error
	_, err := inspectPolicy(ctx, platform, list, func(name string) (int, bool, error) {
		n, present, err := size(name)
		if err == nil && present && n > 0 {
			if err = ctx.Err(); err == nil {
				err = remove(name)
			}
			if err != nil {
				// Only presence queries ignore Darwin EPERM. Removal EPERM is fatal.
				removal = fmt.Errorf("remove sideband attribute %s: %w", name, err)
				err = errors.New("sideband removal failed")
			}
		}
		return n, present, err
	}, nil, false)
	if removal != nil {
		return removal
	}
	return err
}

// RewriteCarrier uses the shared streaming codec to remove a prohibited value.
// The caller owns destination staging/commit. Unrelated decoded attribute values
// remain intact; the output is a canonical AppleDouble encoding, not a wire copy.
func RewriteCarrier(ctx context.Context, source appledouble.Value, dst io.Writer, name string) error {
	if name != appledouble.ResourceForkName && name != appledouble.FinderInfoName {
		return os.ErrInvalid
	}
	f, err := appledouble.DecodeStream(ctx, source, appledouble.DefaultStreamLimits())
	if err != nil {
		return err
	}
	if name == appledouble.ResourceForkName {
		f.ResourceFork = nil
	} else {
		f.FinderInfo = [32]byte{}
	}
	f.Attrs = slices.DeleteFunc(f.Attrs, func(attr appledouble.StreamAttr) bool {
		return attr.Name == name && attr.Value != nil && attr.Value.Size() > 0
	})
	_, err = f.EncodeTo(ctx, dst, appledouble.DefaultStreamLimits())
	return err
}
