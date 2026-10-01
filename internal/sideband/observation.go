package sideband

import (
	"context"
	"os"
	"runtime"
	"slices"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Observation retains native query results from the same held object used for
// hashing. It permits bounded streaming traversal without retaining one open
// descriptor per resource. Policy errors and carrier reads are deferred until
// the caller reaches that object's validation stage. Inputs must remain stable.
type Observation struct {
	platform  string
	names     []string
	inventory error
	attrs     map[string]attributeObservation
}

type attributeObservation struct {
	size    int
	present bool
	err     error
}

// Observe captures both queries, including their errors. A later First call
// still short-circuits: a FinderInfo query error cannot override a resource fork.
func Observe(ctx context.Context, file *os.File) *Observation {
	o := &Observation{platform: runtime.GOOS, attrs: make(map[string]attributeObservation)}
	if o.platform == "linux" {
		o.names, o.inventory = hostdata.ListXattrNames(file, hostdata.MaxXattrListSize)
	}
	for _, name := range []string{appledouble.ResourceForkName, appledouble.FinderInfoName} {
		if o.platform == "linux" && (o.inventory != nil || !slices.Contains(o.names, name)) {
			continue
		}
		var a attributeObservation
		a.err = ctx.Err()
		if a.err == nil {
			a.size, a.present, a.err = hostdata.XattrSize(file, name)
		}
		o.attrs[name] = a
	}
	return o
}

// Inspect applies resource policy to captured native results plus a carrier.
func (o *Observation) Inspect(ctx context.Context, carrier appledouble.Value) (Attributes, error) {
	return o.inspect(ctx, carrier, false)
}

// First applies code-object policy to captured native results plus a carrier.
func (o *Observation) First(ctx context.Context, carrier appledouble.Value) (string, error) {
	a, err := o.inspect(ctx, carrier, true)
	if names := a.Names(); len(names) != 0 {
		return names[0], err
	}
	return "", err
}

func (o *Observation) inspect(ctx context.Context, carrier appledouble.Value, first bool) (Attributes, error) {
	return inspectPolicy(ctx, o.platform, func() ([]string, error) { return o.names, o.inventory }, func(name string) (int, bool, error) { a := o.attrs[name]; return a.size, a.present, a.err }, carrier, first)
}
