// Package sideband inspects inputs for codesign's disallowed attached data.
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
	return inspect(ctx, runtime.GOOS,
		func() ([]string, error) { return hostdata.ListXattrNames(file, hostdata.MaxXattrListSize) },
		func(name string) (int, bool, error) { return hostdata.XattrSize(file, name) }, carrier)
}

func inspect(ctx context.Context, platform string, list func() ([]string, error), size func(string) (int, bool, error), carrier appledouble.Value) (Attributes, error) {
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
	for _, attr := range []struct {
		name    string
		present *bool
	}{{appledouble.ResourceForkName, &result.ResourceFork}, {appledouble.FinderInfoName, &result.FinderInfo}} {
		if err := ctx.Err(); err != nil {
			return Attributes{}, err
		}
		if platform == "linux" && !slices.Contains(names, attr.name) {
			continue
		}
		n, present, err := size(attr.name)
		// Apple's checkFork ignores EPERM, not EACCES or arbitrary permission
		// failures. Preserve this Darwin-specific rule without applying Unix
		// errno numbers to Windows errors or to Linux inventory failures.
		if platform == "darwin" && errors.Is(err, syscall.EPERM) {
			continue
		}
		if err != nil {
			return Attributes{}, fmt.Errorf("sideband attribute %s: %w", attr.name, err)
		}
		*attr.present = present && n > 0
	}
	if carrier != nil {
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
