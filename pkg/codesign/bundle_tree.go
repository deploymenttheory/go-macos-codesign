package codesign

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
)

const maxBundleDepth = 8

// A single checked byte count, entry budget and inode registry cover the tree.
type bundleScan struct {
	entries, nested   int
	bytes             int64
	recurse           bool
	verifyVersions    bool
	verifyLinks       bool // verification compares sealed text without resolving targets
	signatureCleanup  bool // exclude stale entries; defer directory/symlink rejection to flush
	seen              map[string]bool
	regular, writable map[string]os.FileInfo
}

func newBundleScan() *bundleScan {
	return &bundleScan{recurse: true, seen: map[string]bool{}, regular: map[string]os.FileInfo{}, writable: map[string]os.FileInfo{}}
}

func (s *bundleScan) entry(name string) error {
	s.entries++
	if s.entries > maxBundleEntries {
		return unsupported("bundle entry count limit")
	}
	if err := bundleRelativePath(name); err != nil {
		return err
	}
	lower := strings.ToLower(name)
	if s.seen[lower] {
		return unsupported("case-colliding bundle paths")
	}
	s.seen[lower] = true
	return nil
}

func (s *bundleScan) addBytes(n int64) error {
	if n < 0 || s.bytes > math.MaxInt64-n {
		return unsupported("bundle byte count overflow")
	}
	s.bytes += n
	return nil
}

func (s *bundleScan) addChild() error {
	s.nested++
	if s.nested > maxNestedFiles {
		return unsupported("nested code count limit")
	}
	return nil
}

func (s *bundleScan) writeTarget(name string, st os.FileInfo) error {
	for previous, info := range s.regular {
		if previous != name && os.SameFile(st, info) {
			return unsupported("hard-linked bundle write target: " + name)
		}
	}
	s.writable[name] = st
	return nil
}

func (s *bundleScan) regularFile(name string, st os.FileInfo) error {
	for target, info := range s.writable {
		if name != target && os.SameFile(st, info) {
			return unsupported("hard-linked bundle write target: " + target)
		}
	}
	s.regular[name] = st
	return nil
}

type nestedAppResource struct {
	bundle        *appBundle
	files, files2 map[string]any
	data          codeSource
	resources     []byte
	otherVersions []*nestedAppResource
}

func (b *appBundle) scanChild(ctx context.Context, name string, scope *bundleScan, depth int, prefix string) (*nestedAppResource, error) {
	if depth > maxBundleDepth {
		return nil, unsupported("nested app depth limit")
	}
	if err := scope.addChild(); err != nil {
		return nil, err
	}
	root, err := b.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	child, err := loadAppBundle(root, filepath.Join(b.path, filepath.FromSlash(name)))
	if err != nil {
		return nil, err
	}
	b.children = append(b.children, child) // top-level close owns all descendant roots
	if err := child.startSideband(b.sidebandInputs); err != nil {
		return nil, err
	}
	if b.signing != nil && b.signing.Deep {
		data, err := child.signingExecutable(ctx)
		if err != nil {
			return nil, signingNestedError(filepath.Join(b.sidebandBase, filepath.FromSlash(name)), err)
		}
		if signingNeedsNested(data, b.signing.Force) {
			if err := child.startSigningSideband(ctx, *b.signing, b.signingInputs); err != nil {
				child.signingFailure, child.signingPreflightFailed = err, true
				child.signing = nil // No child workers start before its code preflight succeeds.
			}
		}
	}
	app, err := child.snapshot(ctx, scope, depth, prefix+name+"/")
	if err != nil {
		if b.signing != nil {
			return nil, signingNestedError(child.path, err)
		}
		return nil, err
	}
	if scope.verifyVersions {
		for _, version := range child.versions {
			if version == child.version {
				continue
			}
			if err := scope.addChild(); err != nil {
				return nil, err
			}
			root, err := child.root.OpenRoot(".")
			if err != nil {
				return nil, err
			}
			other, err := loadAppBundleVersion(root, child.path, version)
			if err != nil {
				return nil, err
			}
			other.alternate = true
			child.children = append(child.children, other)
			if err := other.startSideband(b.sidebandInputs); err != nil {
				return nil, err
			}
			snapshot, err := other.snapshot(ctx, scope, depth, prefix+name+"/")
			if err != nil {
				return nil, err
			}
			app.otherVersions = append(app.otherVersions, snapshot)
		}
	}
	return app, nil
}

func (child *appBundle) snapshot(ctx context.Context, scope *bundleScan, depth int, prefix string) (*nestedAppResource, error) {
	if err := scope.addBytes(int64(len(child.info))); err != nil {
		return nil, err
	}
	var files, files2 map[string]any
	var err error
	if scope.recurse {
		files, files2, err = child.scanTree(ctx, scope, depth, prefix)
		if err != nil {
			return nil, err
		}
	} else if !child.alternate {
		for _, entry := range child.layoutEntries {
			if err := scope.entry(prefix + entry); err != nil {
				return nil, err
			}
		}
	}
	data, err := child.holdCode(ctx, child.executable)
	if err != nil {
		return nil, err
	}
	if _, err := data.container(); err != nil {
		return nil, err
	}
	if err := scope.addBytes(data.source.size); err != nil {
		return nil, err
	}
	var resources []byte
	// Read child envelopes only to verify resource seals. Signing rebuilds
	// envelopes or seals existing executables; removal preserves children.
	if scope.recurse && !scope.signatureCleanup {
		resources, err = child.read(child.resourcesPath(), maxBundlePlist)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if err := scope.addBytes(int64(len(resources))); err != nil {
		return nil, err
	}
	return &nestedAppResource{bundle: child, files: files, files2: files2, data: data, resources: resources}, nil
}

// forceMain controls this executable; opts.Force controls signed descendants.
// Dry-run seal errors retain reached child allocations with their owning roots.
func (b *appBundle) planSignature(ctx context.Context, data codeSource, files, files2 map[string]any, opts SignOptions, forceMain bool) (codeSource, []bundleWrite, error) {
	data.ctx = ctx
	if b.signingPreflightFailed {
		return codeSource{}, nil, &signingMetadataError{b.signingFailure}
	}
	writes, err := prepareNestedForBundle(ctx, files2, opts, b.base, b)
	for i := range writes {
		if writes[i].bundle == nil {
			writes[i].bundle = b
		}
	}
	if err != nil {
		return codeSource{}, writes, err
	}
	if b.signingFailure != nil {
		return codeSource{}, writes, &signingMetadataError{b.signingFailure}
	}
	opts.InfoPlist, opts.Resources = b.info, encodeBundleResources(files, files2)
	if len(opts.Resources) > maxBundlePlist {
		return codeSource{}, nil, unsupported("bundle resource envelope size")
	}
	if opts.Identifier == "" {
		opts.Identifier = b.identifier
	}
	opts.Force = forceMain
	out, err := signCodeSource(data, opts)
	if err != nil {
		return codeSource{}, nil, err
	}
	writes = append(writes, bundleWrite{name: b.resourcesPath(), data: opts.Resources, bundle: b, kind: bundleResourceWrite}, bundleWrite{name: b.executable, output: out, bundle: b, kind: bundleMachOWrite, cleanup: bundleCleanupKeepResources})
	return codeSource{ctx, out}, writes, nil
}

func verifyNestedApp(ctx context.Context, name string, value any, app *nestedAppResource, opts VerifyOptions) error {
	requirement, err := nestedRequirement(name, value)
	if err != nil {
		return err
	}
	if _, _, err := nestedSignature(app.data); err != nil {
		return nestedVerificationError(filepath.Join(opts.resourceBase, name), err)
	}
	opts.Requirement = requirement
	opts.Architecture = ""
	opts.directoryOnly = !opts.Deep
	if _, err := verifyBundleSnapshot(ctx, app.bundle, app.data, app.resources, app.files2, opts); err != nil {
		return nestedVerificationError(filepath.Join(opts.resourceBase, name), err)
	}
	for _, other := range app.otherVersions {
		if _, _, err := nestedSignature(other.data); err != nil {
			return frameworkVersionFailure(name, other.bundle.version, err, opts)
		}
		if _, err := verifyBundleSnapshot(ctx, other.bundle, other.data, other.resources, other.files2, opts); err != nil {
			return frameworkVersionFailure(name, other.bundle.version, err, opts)
		}
	}
	return nil
}

func frameworkVersionFailure(name, version string, err error, opts VerifyOptions) error {
	return &VerificationError{Diagnostic: "embedded framework contains modified or invalid version", Subcomponent: filepath.Join(opts.resourceBase, name), cause: invalid("embedded framework %s version %s: %v", name, version, err), omitArchitecture: true}
}
