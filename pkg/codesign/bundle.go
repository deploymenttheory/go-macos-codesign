package codesign

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const bundleResourcesPath = "Contents/_CodeSignature/CodeResources"

// BundleInfo describes the supported bundle representation. Inspection is not trust.
type BundleInfo struct {
	Executable      string
	InfoEntries     int
	ResourceVersion int
	ResourceRules   int
	ResourceFiles   int
}

type appBundle struct {
	root                         *os.Root
	path, executable, identifier string
	info                         []byte
	entries                      int
	children                     []*appBundle
	base, infoPath, format       string
	framework                    bool
	version, current, selection  string
	versions                     []string
	alternate                    bool // another view of a root whose layout was already counted
	layoutEntries                []string
}

func bundleRelativePath(name string) error {
	if !fs.ValidPath(name) || len(name) > 1024 || strings.Count(name, "/") > 32 {
		return unsupported("bundle path length or structure")
	}
	for _, part := range strings.Split(name, "/") {
		stem, _, _ := strings.Cut(strings.ToUpper(part), ".")
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9' {
			return unsupported("reserved bundle filename")
		}
		if len(part) > 255 || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return unsupported("bundle filename")
		}
		for _, c := range part {
			if c < 32 || c > 126 || strings.ContainsRune(`\:*?"<>|`, c) {
				return unsupported("bundle filenames require portable ASCII characters")
			}
		}
	}
	return nil
}

func openAppBundle(path string) (*appBundle, error) {
	return openAppBundleVersion(path, "")
}

func openAppBundleVersion(path, version string) (*appBundle, error) {
	path, err := resolveFrameworkCurrent(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, unsupported("bundle root must be a directory, not a symlink")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return loadAppBundleVersion(root, path, version)
}

// root ownership transfers to the returned bundle, or is closed on failure.
func loadAppBundle(root *os.Root, path string) (*appBundle, error) {
	return loadAppBundleVersion(root, path, "")
}

func loadAppBundleVersion(root *os.Root, path, version string) (*appBundle, error) {
	b := &appBundle{root: root, path: path, selection: version}
	fail := func(err error) (*appBundle, error) { root.Close(); return nil, err }
	if err := b.discoverLayout(); err != nil {
		return fail(err)
	}
	info, err := b.read(b.infoPath, maxBundlePlist)
	if err != nil {
		return fail(err)
	}
	values, err := decodeBundlePlist(info)
	if err != nil {
		return fail(err)
	}
	executable, ok := values["CFBundleExecutable"].(string)
	if !ok || executable == "" || executable == "." || strings.Contains(executable, "/") {
		return fail(malformed("CFBundleExecutable must name one file"))
	}
	if err := bundleRelativePath(executable); err != nil {
		return fail(err)
	}
	identifier, ok := values["CFBundleIdentifier"].(string)
	if !ok || identifier == "" || strings.ContainsRune(identifier, 0) {
		return fail(malformed("CFBundleIdentifier must be a nonempty string"))
	}
	if b.framework {
		if values["CFBundlePackageType"] != "FMWK" || executable != frameworkName(path) {
			return fail(unsupported("framework metadata must name its FMWK executable"))
		}
	} else {
		switch values["CFBundlePackageType"] {
		case "APPL":
		case "BNDL", "XPC!":
			b.format = "bundle with "
		default:
			return fail(unsupported("Contents bundle package type"))
		}
	}
	for _, key := range []string{"CFBundleResourceSpecification", "MainHTML", "IFMajorVersion"} {
		if _, exists := values[key]; exists {
			return fail(unsupported("bundle metadata: " + key))
		}
	}
	b.info, b.entries, b.identifier, b.executable = info, len(values), identifier, b.base+"MacOS/"+executable
	if b.framework {
		b.executable = b.base + executable
	}
	return b, nil
}

func (b *appBundle) close() {
	for _, child := range b.children {
		child.close()
	}
	_ = b.root.Close()
}

func (b *appBundle) read(name string, limit int64) ([]byte, error) {
	st, err := b.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, unsupported("non-regular bundle file: " + name)
	}
	f, err := b.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(st, current) {
		return nil, invalid("bundle file changed: %s", name)
	}
	return readBounded(f, limit)
}

// scan validates the supported tree, seals resource symlinks without following
// them, and streams hashes. os.Root confines all reads and writes to the bundle.
func (b *appBundle) scan(ctx context.Context) (map[string]any, map[string]any, error) {
	return b.scanTree(ctx, newBundleScan(), 0, "")
}

func (b *appBundle) scanTree(ctx context.Context, scope *bundleScan, depth int, prefix string) (map[string]any, map[string]any, error) {
	files, files2 := map[string]any{}, map[string]any{}
	if err := b.validateFrameworkRoot(); err != nil {
		return nil, nil, err
	}
	for _, name := range b.layoutEntries {
		if b.alternate {
			break
		}
		if err := scope.entry(prefix + name); err != nil {
			return nil, nil, err
		}
	}
	// Writing any signature target must not also change another bundle member
	// through a hard link, invalidating the envelope we just constructed.
	for _, name := range []string{b.executable, b.resourcesPath()} {
		st, err := b.root.Lstat(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		if err == nil {
			if err := scope.writeTarget(prefix+name, st); err != nil {
				return nil, nil, err
			}
		}
	}
	start := "."
	if b.version != "" {
		start = strings.TrimSuffix(b.base, "/")
	}
	err := fs.WalkDir(b.root.FS(), start, func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == start {
			return nil
		}
		if err := scope.entry(prefix + name); err != nil {
			return err
		}
		rel := strings.TrimPrefix(name, b.base)
		if name == strings.TrimSuffix(b.base, "/") || rel == "MacOS" || rel == "Resources" || rel == "_CodeSignature" {
			if !d.IsDir() {
				return malformed("bundle directory: %s", name)
			}
			return nil
		}
		if name == ".DS_Store" && d.Type().IsRegular() {
			return nil
		}
		if !strings.HasPrefix(name, b.base) {
			return unsupported("unsealed app root entry: " + name)
		}
		nested, container := nestedCodePath(rel)
		if b.framework && !strings.Contains(rel, "/") && !d.IsDir() {
			nested = true // additional top-level Mach-O files are nested code
		}
		link := d.Type()&os.ModeSymlink != 0
		switch {
		case name == b.executable, name == b.infoPath, rel == "Info.plist", rel == "PkgInfo", rel == "version.plist", rel == "embedded.provisionprofile", name == b.resourcesPath():
			nested = false
			if d.IsDir() || link {
				return malformed("bundle file is not regular: %s", name)
			}
		case strings.HasPrefix(rel, "Resources/"), b.framework && frameworkResourcePath(rel):
			if d.IsDir() {
				return nil
			}
		case container:
			if !d.IsDir() {
				return malformed("nested code container is not a directory: %s", rel)
			}
			return nil
		case nested:
			if d.IsDir() {
				if strings.Contains(d.Name(), ".") {
					if !nestedBundleSuffix(d.Name()) {
						return unsupported("nested bundle layout: " + rel)
					}
					child, err := b.scanChild(ctx, name, scope, depth+1, prefix)
					if err != nil {
						return fmt.Errorf("nested %s: %w", rel, err)
					}
					files2[rel] = child
					return fs.SkipDir
				}
				return nil
			}
		default:
			return unsupported("bundle layout or nested code: " + rel)
		}
		if link {
			if strings.EqualFold(d.Name(), ".DS_Store") {
				return unsupported("DS_Store symlink")
			}
			target, err := b.resourceLink(name, rel, scope)
			if err != nil {
				return err
			}
			if include, optional := resourcePolicy(rel, false); include {
				files2[rel] = symlinkSeal(target, optional)
			}
			return nil // legacy envelopes omit every symlink
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return unsupported("non-regular bundle resource: " + rel)
		}
		if err := scope.regularFile(prefix+name, st); err != nil {
			return err
		}
		if nested && name != b.executable {
			if err := scope.writeTarget(prefix+name, st); err != nil {
				return err
			}
		}
		if name == b.executable || rel == "Info.plist" || name == b.resourcesPath() {
			return nil
		}
		include1, optional1 := resourcePolicy(rel, true)
		include2, optional2 := resourcePolicy(rel, false)
		if !include1 && !include2 {
			return nil
		}
		if nested {
			if err := scope.addChild(); err != nil {
				return err
			}
			data, err := b.read(name, maxFileSize-scope.bytes)
			if err != nil {
				return err
			}
			// Format validation applies even during inspection/removal; unsigned
			// Mach-O files are permitted until a seal is actually requested.
			if _, err := parseContainer(data); err != nil {
				return err
			}
			scope.bytes += int64(len(data))
			files2[rel] = nestedResource{data}
			return nil
		}
		f, err := b.root.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		current, err := f.Stat()
		if err != nil {
			return err
		}
		if !os.SameFile(st, current) {
			return invalid("resource changed: %s", rel)
		}
		if current.Size() > maxFileSize-scope.bytes {
			return unsupported("bundle resource data exceeds 1 GiB")
		}
		h1, h2 := sha1.New(), sha256.New()
		n, err := io.Copy(io.MultiWriter(h1, h2), io.LimitReader(f, maxFileSize-scope.bytes+1))
		if err != nil {
			return err
		}
		scope.bytes += n
		if scope.bytes > maxFileSize {
			return unsupported("bundle resource data exceeds 1 GiB")
		}
		if include1 {
			files[rel] = resourceSeal(h1.Sum(nil), optional1, true)
		}
		if include2 {
			files2[rel] = resourceSeal(h2.Sum(nil), optional2, false)
		}
		return nil
	})
	if err == nil && !b.alternate && (!scope.verifyVersions || depth == 0) {
		err = b.inventoryOtherVersions(ctx, scope, prefix)
	}
	return files, files2, err
}

func (b *appBundle) annotate(r *Report, resources []byte) {
	if r == nil {
		return
	}
	r.Path = b.path
	r.Format = b.format + r.Format
	executable := b.executable
	if b.version != "" {
		executable = "Versions/" + b.selection + "/" + strings.TrimPrefix(executable, b.base)
	}
	r.Bundle = &BundleInfo{Executable: filepath.Join(b.path, filepath.FromSlash(executable)), InfoEntries: b.entries}
	if m, err := decodeBundlePlist(resources); err == nil {
		if files, ok := m["files2"].(map[string]any); ok {
			r.Bundle.ResourceVersion = 2
			r.Bundle.ResourceFiles = len(files)
		}
		if rules, ok := m["rules2"].(map[string]any); ok {
			r.Bundle.ResourceRules = len(rules)
		}
	}
}

func inspectBundle(ctx context.Context, path string, opts PathOptions) (*Report, error) {
	b, err := openAppBundleVersion(path, opts.BundleVersion)
	if err != nil {
		return nil, err
	}
	defer b.close()
	if _, _, err = b.scan(ctx); err != nil {
		return nil, err
	}
	data, err := b.read(b.executable, maxFileSize)
	if err != nil {
		return nil, err
	}
	r, err := InspectBytes(data)
	resources, _ := b.read(b.resourcesPath(), maxBundlePlist)
	b.annotate(r, resources)
	return r, err
}

func verifyBundle(ctx context.Context, path string, opts VerifyOptions) (*Report, error) {
	if len(opts.InfoPlist) > 0 || len(opts.Resources) > 0 {
		return nil, unsupported("external special-slot overrides for bundles")
	}
	b, err := openAppBundleVersion(path, opts.BundleVersion)
	if err != nil {
		return nil, err
	}
	defer b.close()
	scope := newBundleScan()
	scope.recurse = opts.Deep
	scope.verifyVersions = true
	_, actual, err := b.scanTree(ctx, scope, 0, "")
	if err != nil {
		return nil, err
	}
	data, err := b.read(b.executable, maxFileSize)
	if err != nil {
		return nil, err
	}
	resources, err := b.read(b.resourcesPath(), maxBundlePlist)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return verifyBundleSnapshot(ctx, b, data, resources, actual, opts)
}

func verifyBundleSnapshot(ctx context.Context, b *appBundle, data, resources []byte, actual map[string]any, opts VerifyOptions) (*Report, error) {
	opts.InfoPlist, opts.Resources = b.info, resources
	r, err := VerifyBytes(ctx, data, opts)
	b.annotate(r, resources)
	if err != nil {
		return r, err
	}
	r.Valid = false
	for _, a := range r.Architectures {
		if opts.Architecture != "" && opts.Architecture != a.Name {
			continue
		}
		for _, d := range a.Signature.Directories {
			if d.SpecialSlots < 3 {
				return r, invalid("bundle signature lacks Info.plist/resource binding")
			}
		}
	}
	if !opts.directoryOnly {
		if _, err := verifyBundleResourcesWithOptions(ctx, resources, actual, opts); err != nil {
			return r, err
		}
	}
	r.Valid = true
	return r, nil
}

func signBundle(ctx context.Context, path string, opts SignOptions) error {
	if len(opts.InfoPlist) > 0 || len(opts.Resources) > 0 {
		return unsupported("external special-slot overrides for bundles")
	}
	b, err := openAppBundleVersion(path, opts.BundleVersion)
	if err != nil {
		return err
	}
	defer b.close()
	files, files2, err := b.scan(ctx)
	if err != nil {
		return err
	}
	data, err := b.read(b.executable, maxFileSize)
	if err != nil {
		return err
	}
	_, writes, err := b.planSignature(ctx, data, files, files2, opts, opts.Force)
	if err != nil {
		return err
	}
	if opts.DryRun {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// All construction (including TSA requests) precedes mutation. As with file
	// signing, I/O failures during the writes can leave partial output.
	for _, write := range writes {
		if write.create {
			if err := write.bundle.root.Mkdir(write.bundle.base+"_CodeSignature", 0755); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
		}
		if err := write.bundle.write(ctx, write.name, write.data, write.create); err != nil {
			return err
		}
	}
	return nil
}

func (b *appBundle) write(ctx context.Context, name string, data []byte, create bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	st, err := b.root.Lstat(name)
	flags := os.O_WRONLY
	if errors.Is(err, os.ErrNotExist) && create {
		flags |= os.O_CREATE | os.O_EXCL
	} else if err != nil {
		return err
	} else if !st.Mode().IsRegular() {
		return unsupported("writing non-regular bundle file")
	}
	f, err := b.root.OpenFile(name, flags, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil {
		return err
	}
	if st != nil && !os.SameFile(st, current) {
		return fmt.Errorf("bundle write target changed")
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		return err
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

func removeBundle(ctx context.Context, path string, opts PathOptions) error {
	b, err := openAppBundleVersion(path, opts.BundleVersion)
	if err != nil {
		return err
	}
	defer b.close()
	if _, _, err = b.scan(ctx); err != nil {
		return err
	}
	data, err := b.read(b.executable, maxFileSize)
	if err != nil {
		return err
	}
	out, err := RemoveSignatureBytes(ctx, data)
	if err != nil {
		return err
	}
	if err := b.write(ctx, b.executable, out, false); err != nil {
		return err
	}
	if err := b.root.Remove(b.resourcesPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Apple's bundle writer unlinks signature files but retains the directory.
	return nil
}
