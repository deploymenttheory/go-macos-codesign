package codesign

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-macos-codesign/internal/sideband"
)

type sidebandBinding struct {
	info  os.FileInfo
	value appledouble.Value
}
type bundleSidebandInputs struct {
	ctx      context.Context
	bindings []sidebandBinding
}
type bundleSidebandObject struct {
	native  *sideband.Observation
	carrier appledouble.Value
	err     error
}

func prepareBundleSideband(ctx context.Context, path string, opts VerifyOptions) (*bundleSidebandInputs, error) {
	if opts.AppleDouble != nil {
		return nil, unsupported("bundle metadata requires AppleDoubleFiles with explicit object paths")
	}
	if !opts.StrictSideband || opts.NoStrict {
		return nil, nil
	}
	if len(opts.AppleDoubleFiles) > maxBundleEntries {
		return nil, unsupported("AppleDouble binding count limit")
	}
	inputs := &bundleSidebandInputs{ctx: ctx}
	for _, key := range slices.Sorted(maps.Keys(opts.AppleDoubleFiles)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value := opts.AppleDoubleFiles[key]
		if key == "" || value == nil {
			return nil, unsupported("AppleDouble binding requires an object path and source")
		}
		name := filepath.FromSlash(key)
		if !filepath.IsAbs(name) {
			name = path + string(filepath.Separator) + name
		}
		// Preserve physical path/.. semantics, and bind by held-file identity
		// later. An alias cannot hide a target's explicitly supplied metadata.
		info, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		for _, binding := range inputs.bindings {
			if os.SameFile(info, binding.info) {
				return nil, unsupported("duplicate AppleDouble bindings to the same filesystem object")
			}
		}
		inputs.bindings = append(inputs.bindings, sidebandBinding{info, value})
	}
	return inputs, nil
}

func (s *bundleSidebandInputs) observe(file *os.File) *bundleSidebandObject {
	o := &bundleSidebandObject{}
	info, err := file.Stat()
	if err != nil {
		o.err = err
		return o
	}
	for _, binding := range s.bindings {
		if os.SameFile(info, binding.info) {
			o.carrier = binding.value
			break
		}
	}
	o.native = sideband.Observe(s.ctx, file)
	return o
}

func (o *bundleSidebandObject) first(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if o.err != nil {
		return "", o.err
	}
	return o.native.First(ctx, o.carrier)
}

func (b *appBundle) observeSideband(name string, file *os.File) {
	if b.sidebandInputs != nil {
		b.sideband[name] = b.sidebandInputs.observe(file)
	}
}

func (b *appBundle) openSideband(name string) {
	if b.sidebandInputs == nil {
		return
	}
	f, err := b.root.Open(name)
	if err != nil {
		b.sideband[name] = &bundleSidebandObject{err: err}
		return
	}
	defer f.Close()
	b.observeSideband(name, f)
}

func (b *appBundle) observeSidebandLink(name string) {
	if b.sidebandInputs == nil {
		return
	}
	// Resource validation follows links, even when only sideband policy is
	// enabled. Metadata reads may reach an explicitly referenced outside file;
	// no contents or metadata are written through the link.
	path, err := resolveMetadataLink(b.sidebandDiagnostic(name), 32, true)
	if err != nil {
		b.sideband[name] = &bundleSidebandObject{err: sidebandOpenError(err)}
		return
	}
	f, err := os.Open(path)
	if err != nil {
		b.sideband[name] = &bundleSidebandObject{err: sidebandOpenError(err)}
		return
	}
	defer f.Close()
	b.observeSideband(name, f)
}

func (b *appBundle) sidebandDiagnostic(name string) string {
	if b.version != "" && strings.HasPrefix(name, b.base) {
		name = "Versions/" + b.selection + "/" + strings.TrimPrefix(name, b.base)
	}
	return filepath.Join(b.path, filepath.FromSlash(name))
}

func sidebandOpenError(err error) error {
	message := ""
	switch {
	case errors.Is(err, syscall.ELOOP):
		message = "Too many levels of symbolic links"
	case errors.Is(err, syscall.ENOTDIR):
		message = "Not a directory"
	case errors.Is(err, os.ErrNotExist):
		message = "No such file or directory"
	case errors.Is(err, os.ErrPermission):
		message = "Permission denied"
	default:
		return err
	}
	return &VerificationError{Diagnostic: message, cause: err, omitArchitecture: true}
}

func (b *appBundle) startSideband(inputs *bundleSidebandInputs) {
	b.sidebandInputs = inputs
	if inputs == nil {
		return
	}
	b.sideband = make(map[string]*bundleSidebandObject)
	b.openSideband(".")
	if b.version != "" {
		b.openSideband(strings.TrimSuffix(b.base, "/"))
	}
}

func (b *appBundle) verifyRootSideband(ctx context.Context, opts VerifyOptions) error {
	if !opts.StrictSideband || opts.NoStrict {
		return nil
	}
	name, path := ".", b.path
	if b.version != "" {
		name = strings.TrimSuffix(b.base, "/")
		path = filepath.Join(b.path, "Versions", b.selection) + string(filepath.Separator) + "."
	}
	opts.sidebandObject, opts.sidebandPath = b.sideband[name], path
	return verifySideband(ctx, opts)
}

func verifyResourceSideband(ctx context.Context, name string, opts VerifyOptions) error {
	if !opts.StrictSideband || opts.NoStrict {
		return nil
	}
	b := opts.linkScope.bundle
	o := b.sideband[b.base+name]
	if o == nil {
		return invalid("missing held sideband observation: %s", name)
	}
	if o.err != nil {
		return o.err
	}
	attrs, err := o.native.Inspect(ctx, o.carrier)
	if err != nil {
		return err
	}
	if names := attrs.Names(); len(names) != 0 {
		return sidebandFailure(filepath.Join(opts.resourceBase, name), names, true)
	}
	return nil
}
