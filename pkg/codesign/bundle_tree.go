package codesign

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxBundleDepth = 8

// A single budget and inode registry cover the complete containment tree.
type bundleScan struct {
	entries, nested   int
	bytes             int64
	recurse           bool
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

type nestedAppResource struct {
	bundle          *appBundle
	files, files2   map[string]any
	data, resources []byte
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
	scope.bytes += int64(len(child.info))
	if scope.bytes > maxFileSize {
		return nil, unsupported("bundle input exceeds 1 GiB")
	}
	var files, files2 map[string]any
	if scope.recurse {
		files, files2, err = child.scanTree(ctx, scope, depth, prefix+name+"/")
		if err != nil {
			return nil, err
		}
	} else {
		for _, entry := range child.layoutEntries {
			if err := scope.entry(prefix + name + "/" + entry); err != nil {
				return nil, err
			}
		}
	}
	data, err := child.read(child.executable, maxFileSize-scope.bytes)
	if err != nil {
		return nil, err
	}
	if _, err := parseContainer(data); err != nil {
		return nil, err
	}
	scope.bytes += int64(len(data))
	var resources []byte
	if scope.recurse {
		resources, err = child.read(child.resourcesPath(), min(maxBundlePlist, maxFileSize-scope.bytes))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	scope.bytes += int64(len(resources))
	return &nestedAppResource{child, files, files2, data, resources}, nil
}

// forceMain replaces this executable without changing whether already signed
// descendants are preserved. Native deep signing distinguishes these choices.
func (b *appBundle) planSignature(ctx context.Context, data []byte, files, files2 map[string]any, opts SignOptions, forceMain bool) ([]byte, []bundleWrite, error) {
	writes, err := prepareNestedAt(ctx, files2, opts, b.base)
	if err != nil {
		return nil, nil, err
	}
	opts.InfoPlist, opts.Resources = b.info, encodeBundleResources(files, files2)
	if len(opts.Resources) > maxBundlePlist {
		return nil, nil, unsupported("bundle resource envelope size")
	}
	if opts.Identifier == "" {
		opts.Identifier = b.identifier
	}
	opts.Force = forceMain
	out, err := SignBytes(ctx, data, opts)
	if err != nil {
		return nil, nil, err
	}
	writes = append(writes, bundleWrite{name: b.resourcesPath(), data: opts.Resources, bundle: b, create: true}, bundleWrite{name: b.executable, data: out, bundle: b})
	var total int64
	for i := range writes {
		if writes[i].bundle == nil {
			writes[i].bundle = b
		}
		total += int64(len(writes[i].data))
	}
	if total > maxFileSize {
		return nil, nil, unsupported("bundle signature output exceeds 1 GiB")
	}
	return out, writes, nil
}

func verifyNestedApp(ctx context.Context, name string, value any, app *nestedAppResource, opts VerifyOptions) error {
	requirement, err := nestedRequirement(name, value)
	if err != nil {
		return err
	}
	if _, _, err := nestedSignature(app.data); err != nil {
		return err
	}
	opts.Requirement = requirement
	opts.Architecture = ""
	opts.directoryOnly = !opts.Deep
	if _, err := verifyBundleSnapshot(ctx, app.bundle, app.data, app.resources, app.files2, opts); err != nil {
		return fmt.Errorf("nested %s: %w", name, err)
	}
	return nil
}
