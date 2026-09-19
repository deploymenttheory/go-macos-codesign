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

// BundleInfo describes the supported app representation. Inspection is not trust.
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
}

func isBundle(path string) bool { st, err := os.Stat(path); return err == nil && st.IsDir() }

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
	b := &appBundle{root: root, path: path}
	fail := func(err error) (*appBundle, error) { root.Close(); return nil, err }
	info, err := b.read("Contents/Info.plist", maxBundlePlist)
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
	if values["CFBundlePackageType"] != "APPL" {
		return fail(unsupported("only Contents-based APPL bundles are supported"))
	}
	for _, key := range []string{"CFBundleResourceSpecification", "MainHTML", "IFMajorVersion"} {
		if _, exists := values[key]; exists {
			return fail(unsupported("bundle metadata: " + key))
		}
	}
	b.info, b.entries, b.identifier, b.executable = info, len(values), identifier, "Contents/MacOS/"+executable
	return b, nil
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

// scan validates the entire supported tree, never follows symlinks and streams
// hashes. os.Root keeps all reads and writes confined to the opened bundle.
func (b *appBundle) scan(ctx context.Context) (map[string]any, map[string]any, error) {
	files, files2 := map[string]any{}, map[string]any{}
	entries := 0
	var total int64
	seen := map[string]bool{}
	// Writing either signature file must not also change another bundle member
	// through a hard link, invalidating the envelope we just constructed.
	writable := map[string]os.FileInfo{}
	for _, name := range []string{b.executable, bundleResourcesPath} {
		st, err := b.root.Lstat(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		if err == nil {
			writable[name] = st
		}
	}
	err := fs.WalkDir(b.root.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		entries++
		if entries > maxBundleEntries {
			return unsupported("bundle entry count limit")
		}
		if err := bundleRelativePath(name); err != nil {
			return err
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			return unsupported("case-colliding bundle paths")
		}
		seen[lower] = true
		if d.Type()&os.ModeSymlink != 0 {
			return unsupported("bundle symlinks")
		}
		if name == "Contents" || name == "Contents/MacOS" || name == "Contents/Resources" || name == "Contents/_CodeSignature" {
			if !d.IsDir() {
				return malformed("bundle directory: %s", name)
			}
			return nil
		}
		if name == ".DS_Store" && d.Type().IsRegular() {
			return nil
		}
		if !strings.HasPrefix(name, "Contents/") {
			return unsupported("unsealed app root entry: " + name)
		}
		rel := strings.TrimPrefix(name, "Contents/")
		switch {
		case name == b.executable, rel == "Info.plist", rel == "PkgInfo", rel == "version.plist", rel == "embedded.provisionprofile", name == bundleResourcesPath:
			if d.IsDir() {
				return malformed("bundle file is a directory: %s", name)
			}
		case strings.HasPrefix(rel, "Resources/"):
			if d.IsDir() {
				return nil
			}
		default:
			return unsupported("bundle layout or nested code: " + rel)
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return unsupported("non-regular bundle resource: " + rel)
		}
		for target, targetInfo := range writable {
			if name != target && os.SameFile(st, targetInfo) {
				return unsupported("hard-linked bundle write target: " + target)
			}
		}
		if name == b.executable || rel == "Info.plist" || name == bundleResourcesPath {
			return nil
		}
		include1, optional1 := resourcePolicy(rel, true)
		include2, optional2 := resourcePolicy(rel, false)
		if !include1 && !include2 {
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
		if current.Size() > maxFileSize-total {
			return unsupported("bundle resource data exceeds 1 GiB")
		}
		h1, h2 := sha1.New(), sha256.New()
		n, err := io.Copy(io.MultiWriter(h1, h2), io.LimitReader(f, maxFileSize-total+1))
		if err != nil {
			return err
		}
		total += n
		if total > maxFileSize {
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
	return files, files2, err
}

func (b *appBundle) annotate(r *Report, resources []byte) {
	if r == nil {
		return
	}
	r.Path = b.path
	r.Format = "app bundle with " + r.Format
	r.Bundle = &BundleInfo{Executable: filepath.Join(b.path, filepath.FromSlash(b.executable)), InfoEntries: b.entries}
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

func inspectBundle(ctx context.Context, path string) (*Report, error) {
	b, err := openAppBundle(path)
	if err != nil {
		return nil, err
	}
	defer b.root.Close()
	if _, _, err = b.scan(ctx); err != nil {
		return nil, err
	}
	data, err := b.read(b.executable, maxFileSize)
	if err != nil {
		return nil, err
	}
	r, err := InspectBytes(data)
	resources, _ := b.read(bundleResourcesPath, maxBundlePlist)
	b.annotate(r, resources)
	return r, err
}

func verifyBundle(ctx context.Context, path string, opts VerifyOptions) (*Report, error) {
	if len(opts.InfoPlist) > 0 || len(opts.Resources) > 0 {
		return nil, unsupported("external special-slot overrides for bundles")
	}
	b, err := openAppBundle(path)
	if err != nil {
		return nil, err
	}
	defer b.root.Close()
	_, actual, err := b.scan(ctx)
	if err != nil {
		return nil, err
	}
	data, err := b.read(b.executable, maxFileSize)
	if err != nil {
		return nil, err
	}
	resources, err := b.read(bundleResourcesPath, maxBundlePlist)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
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
	if _, err := verifyBundleResources(resources, actual); err != nil {
		return r, err
	}
	r.Valid = true
	return r, nil
}

func signBundle(ctx context.Context, path string, opts SignOptions) error {
	if len(opts.InfoPlist) > 0 || len(opts.Resources) > 0 {
		return unsupported("external special-slot overrides for bundles")
	}
	b, err := openAppBundle(path)
	if err != nil {
		return err
	}
	defer b.root.Close()
	files, files2, err := b.scan(ctx)
	if err != nil {
		return err
	}
	opts.InfoPlist, opts.Resources = b.info, encodeBundleResources(files, files2)
	if len(opts.Resources) > maxBundlePlist {
		return unsupported("bundle resource envelope size")
	}
	if opts.Identifier == "" {
		opts.Identifier = b.identifier
	}
	data, err := b.read(b.executable, maxFileSize)
	if err != nil {
		return err
	}
	out, err := SignBytes(ctx, data, opts)
	if err != nil {
		return err
	}
	if opts.DryRun {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.root.Mkdir("Contents/_CodeSignature", 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	// All construction (including TSA requests) precedes mutation. As with file
	// signing, I/O failures during these two writes can leave partial output.
	if err := b.write(ctx, bundleResourcesPath, opts.Resources, true); err != nil {
		return err
	}
	return b.write(ctx, b.executable, out, false)
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

func removeBundle(ctx context.Context, path string) error {
	b, err := openAppBundle(path)
	if err != nil {
		return err
	}
	defer b.root.Close()
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
	if err := b.root.Remove(bundleResourcesPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := b.root.Remove("Contents/_CodeSignature"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
