package codesign

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// os.Root.FS().ReadDir eagerly lstats every entry. Darwin permits reading a
// resource through a descriptor despite denying pathname READ_ATTRIBUTES.
// Enumerate names inside the held root, obtaining identities through held
// no-follow resource handles only when that particular pathname lookup fails.
type signingBundleWalker struct{ *appBundle }

// WalkDir retains the filesystem's enumeration order. It deliberately does not
// implement fs.ReadDirFS, whose contract requires sorted results.
func (b signingBundleWalker) WalkDir(name string, visit fs.WalkDirFunc) error {
	info, err := b.root.Stat(name)
	if err != nil {
		err = visit(name, nil, err)
	} else {
		err = b.walk(name, fs.FileInfoToDirEntry(info), visit)
	}
	if errors.Is(err, fs.SkipAll) || errors.Is(err, fs.SkipDir) {
		return nil
	}
	return err
}

func (b signingBundleWalker) walk(name string, entry fs.DirEntry, visit fs.WalkDirFunc) error {
	err := visit(name, entry, nil)
	if errors.Is(err, fs.SkipDir) && entry.IsDir() {
		return nil
	}
	if err != nil || !entry.IsDir() {
		return err
	}
	children, err := b.ReadDir(name)
	if err != nil {
		err = visit(name, entry, err)
		if errors.Is(err, fs.SkipDir) {
			return nil
		}
		return err
	}
	for _, child := range children {
		err := b.walk(path.Join(name, child.Name()), child, visit)
		if errors.Is(err, fs.SkipDir) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (b signingBundleWalker) ReadDir(name string) ([]fs.DirEntry, error) {
	return b.directoryEntries(name, true)
}

// Windows directory enumeration on FAT can omit file IDs. Obtain each identity
// with the SDK's rooted metadata query before comparing the opened descriptor.
// Verification retains fs.ReadDirFS's lexical order and its metadata failures.
type verificationBundleFS struct {
	fs.FS
	bundle *appBundle
}

func (b verificationBundleFS) Stat(name string) (fs.FileInfo, error) {
	return b.bundle.root.Stat(name)
}

func (b verificationBundleFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := b.bundle.directoryEntries(name, false)
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, err
}

func (b *appBundle) directoryEntries(name string, signing bool) ([]fs.DirEntry, error) {
	dir, err := b.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	// Apple's ResourceBuilder opens FTS without a comparison function. Retain
	// the filesystem's enumeration order: stripping a resource can mutate its
	// later-enumerated attribute file before that file's bytes are sealed.
	entries := make([]fs.DirEntry, 0, len(names))
	for _, child := range names {
		entry := path.Join(name, child)
		var info os.FileInfo
		if signing {
			info, err = b.root.Lstat(entry)
		} else {
			// This does not request content or EA rights on Windows. Directory
			// enumeration permissions must not become unrelated metadata reads.
			info, err = hostdata.StatMetadata(b.root, entry)
		}
		if signing && errors.Is(err, os.ErrPermission) && b.ordinarySigningResource(entry) {
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
