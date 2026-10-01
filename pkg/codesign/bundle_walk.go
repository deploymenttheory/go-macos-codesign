package codesign

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
)

// os.Root.FS().ReadDir eagerly lstats every entry. Darwin permits reading a
// resource through a descriptor despite denying pathname READ_ATTRIBUTES.
// Enumerate names inside the held root, obtaining identities through held
// no-follow resource handles only when that particular pathname lookup fails.
type signingBundleFS struct{ *appBundle }

func (b signingBundleFS) Open(name string) (fs.File, error) { return b.root.Open(name) }

func (b signingBundleFS) ReadDir(name string) ([]fs.DirEntry, error) {
	dir, err := b.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	entries := make([]fs.DirEntry, 0, len(names))
	for _, child := range names {
		entry := path.Join(name, child)
		info, err := b.root.Lstat(entry)
		if errors.Is(err, os.ErrPermission) && b.ordinarySigningResource(entry) {
			info, err = b.resourceInfo(entry)
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, fs.FileInfoToDirEntry(info))
	}
	return entries, nil
}

func (b *appBundle) ordinarySigningResource(name string) bool {
	if name == b.executable || name == b.infoPath || name == b.resourcesPath() {
		return false
	}
	rel := strings.TrimPrefix(name, b.base)
	return strings.HasPrefix(rel, "Resources/") || b.framework && frameworkResourcePath(rel)
}

func (b *appBundle) resourceInfo(name string) (os.FileInfo, error) {
	f, err := openResourceFile(b.root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, unsupported("non-regular bundle resource: " + name)
	}
	return st, nil
}
