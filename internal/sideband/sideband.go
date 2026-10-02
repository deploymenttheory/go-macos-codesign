// Package sideband handles codesign's disallowed data and attached signatures.
// It owns policy only; native metadata and AppleDouble decoding belong to APFS.
package sideband

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Attributes records nonempty prohibited attributes, in native diagnostic order.
// A successful empty result proves absence only in the supplied inputs.
type Attributes struct {
	ResourceFork bool
	FinderInfo   bool
}

// Names returns fresh storage in ResourceFork-before-FinderInfo order. Code
// objects report the first name; ordinary resources can report both names.
func (a Attributes) Names() []string {
	var names []string
	if a.ResourceFork {
		names = append(names, appledouble.ResourceForkName)
	}
	if a.FinderInfo {
		names = append(names, appledouble.FinderInfoName)
	}
	return names
}

// Inspect reads native attributes from the caller's held object and, when
// explicitly supplied, an AppleDouble snapshot. It never opens a pathname,
// guesses a sidecar, restores metadata, changes offsets or closes either input.
// The caller must keep the inputs open and stable for the duration of the call.
// Following a resource link, binding a carrier to its object and scheduling
// checks relative to signature/resource verification belong to the caller.
//
// Native and carrier observations are additive: empty carrier fields cannot
// hide native attributes. Carrier inspection tests the supplied snapshot, not
// the hypothetical result of running copyfile's mutating restore protocol.
// Errors return no partial observations. Context cancellation is checked between
// operations; it cannot interrupt a native filesystem syscall already in flight.
func Inspect(ctx context.Context, file *os.File, carrier appledouble.Value) (Attributes, error) {
	return inspectFile(ctx, file, carrier, false)
}

// First applies the single-code-object policy: stop at the first prohibited
// attribute, ResourceFork before FinderInfo. A positive native ResourceFork
// observation rejects the object without querying later metadata. Carrier errors
// still propagate whenever decoding is needed to establish the first match.
func First(ctx context.Context, file *os.File, carrier appledouble.Value) (string, error) {
	a, err := inspectFile(ctx, file, carrier, true)
	if names := a.Names(); len(names) != 0 {
		return names[0], err
	}
	return "", err
}

// CheckPlatformAttribute performs BundleDiskRep's early metadata query. The
// attribute does not grant this implementation Apple platform-signing status;
// only its read failure affects construction. Linux cannot query unnamespaced
// names, so its native inventory establishes absence, as for sideband checks.
func CheckPlatformAttribute(ctx context.Context, file *os.File) error {
	return checkPlatformAttribute(ctx, runtime.GOOS,
		func() ([]string, error) { return hostdata.ListXattrNames(file, hostdata.MaxXattrListSize) },
		func(name string) (int, bool, error) { return hostdata.XattrSize(file, name) })
}

func checkPlatformAttribute(ctx context.Context, platform string, list func() ([]string, error), size func(string) (int, bool, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	const name = "com.apple.root.installed"
	if platform == "linux" {
		names, err := list()
		if err != nil || !slices.Contains(names, name) {
			return err
		}
	}
	_, _, err := size(name)
	if platform == "darwin" && errors.Is(err, syscall.EPERM) {
		return nil
	}
	return err
}

func inspectFile(ctx context.Context, file *os.File, carrier appledouble.Value, first bool) (Attributes, error) {
	return inspectPolicy(ctx, runtime.GOOS,
		func() ([]string, error) { return hostdata.ListXattrNames(file, hostdata.MaxXattrListSize) },
		func(name string) (int, bool, error) { return hostdata.XattrSize(file, name) }, carrier, first)
}

func inspectPolicy(ctx context.Context, platform string, list func() ([]string, error), size func(string) (int, bool, error), carrier appledouble.Value, first bool) (Attributes, error) {
	if err := ctx.Err(); err != nil {
		return Attributes{}, err
	}
	var names []string
	if platform == "linux" {
		// Linux rejects unnamespaced com.apple.* queries even when no such
		// attribute exists. A complete native inventory establishes absence;
		// user.com.apple.* is a different name and is never remapped here.
		var err error
		names, err = list()
		if err != nil {
			return Attributes{}, fmt.Errorf("sideband attribute inventory: %w", err)
		}
	}
	var result Attributes
	var extra Attributes
	decoded := false
	for _, attr := range []struct {
		name    string
		present *bool
	}{{appledouble.ResourceForkName, &result.ResourceFork}, {appledouble.FinderInfoName, &result.FinderInfo}} {
		if err := ctx.Err(); err != nil {
			return Attributes{}, err
		}
		var n int
		var present bool
		var err error
		if platform != "linux" || slices.Contains(names, attr.name) {
			n, present, err = size(attr.name)
		}
		// Apple's checkFork ignores EPERM, not EACCES or arbitrary permission
		// failures. Preserve this Darwin-specific rule without applying Unix
		// errno numbers to Windows errors or to Linux inventory failures.
		if platform == "darwin" && errors.Is(err, syscall.EPERM) {
			n, present, err = 0, false, nil
		}
		if err != nil {
			return Attributes{}, fmt.Errorf("sideband attribute %s: %w", attr.name, err)
		}
		*attr.present = present && n > 0
		if first {
			if err := ctx.Err(); err != nil {
				return Attributes{}, err
			}
			if *attr.present {
				return result, nil
			}
			if carrier != nil && !decoded {
				extra, err = inspectCarrier(ctx, carrier)
				if err != nil {
					return Attributes{}, fmt.Errorf("sideband AppleDouble snapshot: %w", err)
				}
				decoded = true
			}
			if err := ctx.Err(); err != nil {
				return Attributes{}, err
			}
			*attr.present = attr.name == appledouble.ResourceForkName && extra.ResourceFork || attr.name == appledouble.FinderInfoName && extra.FinderInfo
			if *attr.present {
				return result, nil
			}
		}
	}
	if carrier != nil && !first {
		x, err := inspectCarrier(ctx, carrier)
		if err != nil {
			return Attributes{}, fmt.Errorf("sideband AppleDouble snapshot: %w", err)
		}
		result.ResourceFork = result.ResourceFork || x.ResourceFork
		result.FinderInfo = result.FinderInfo || x.FinderInfo
	}
	if err := ctx.Err(); err != nil {
		return Attributes{}, err
	}
	return result, nil
}

func inspectCarrier(ctx context.Context, carrier appledouble.Value) (Attributes, error) {
	f, err := appledouble.DecodeStream(ctx, carrier, appledouble.DefaultStreamLimits())
	if err != nil {
		return Attributes{}, err
	}
	// The fixed FinderInfo slot is always present on the wire. Its all-zero
	// placeholder is not an attached attribute. ATTR records, in contrast,
	// explicitly declare attributes; inspect every record, including duplicates.
	result := Attributes{FinderInfo: f.FinderInfo != [32]byte{}}
	result.ResourceFork = f.ResourceFork != nil && f.ResourceFork.Size() > 0
	for _, attr := range f.Attrs {
		if attr.Value == nil || attr.Value.Size() == 0 {
			continue
		}
		switch attr.Name {
		case appledouble.ResourceForkName:
			result.ResourceFork = true
		case appledouble.FinderInfoName:
			result.FinderInfo = true
		}
	}
	return result, nil
}
