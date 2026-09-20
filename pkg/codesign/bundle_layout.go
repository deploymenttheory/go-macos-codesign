package codesign

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

func nestedBundleSuffix(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".app", ".bundle", ".plugin", ".xpc", ".appex", ".framework":
		return true
	}
	return false
}

// Framework aliases identify Current independently of the selected version. Never traverse an alias
// when reading or writing code; only its validated spelling selects that path.
func (b *appBundle) discoverLayout() error {
	b.base, b.infoPath, b.format = "Contents/", "Contents/Info.plist", "app bundle with "
	if !strings.EqualFold(filepath.Ext(b.path), ".framework") {
		return nil
	}
	b.framework, b.base, b.infoPath, b.format = true, "", "Resources/Info.plist", "bundle with "
	st, err := b.root.Lstat("Versions")
	if errors.Is(err, os.ErrNotExist) {
		if b.selection != "" {
			return unsupported("framework has no selectable versions")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return unsupported("framework Versions must be a directory")
	}
	current, err := b.root.Readlink("Versions/Current")
	if err != nil {
		return err
	}
	current = strings.TrimPrefix(filepath.ToSlash(current), "./")
	if current == "Current" || strings.Contains(current, "/") || current == "." || current == ".." {
		return unsupported("framework Current must name one version")
	}
	if err := bundleRelativePath(current); err != nil {
		return err
	}
	b.current, b.version = current, current
	if b.selection == "" {
		b.selection = "Current"
	}
	if b.selection != "Current" {
		if strings.Contains(b.selection, "/") || b.selection == "." {
			return unsupported("framework version must name one directory")
		}
		if err := bundleRelativePath(b.selection); err != nil {
			return err
		}
		b.version = b.selection
	}
	b.base = "Versions/" + b.version + "/"
	b.infoPath = b.base + "Resources/Info.plist"
	return b.validateFrameworkRoot()
}

// Root aliases always name Current, even when another version is selected.
func (b *appBundle) validateFrameworkRoot() error {
	if b.version == "" {
		return nil
	}
	b.layoutEntries = nil
	b.versions = nil
	required := map[string]bool{"Versions": false, "Versions/Current": false, "Versions/" + b.current: false, "Resources": false, strings.TrimSuffix(filepath.Base(b.path), filepath.Ext(b.path)): false}
	required["Versions/"+b.version] = false
	for _, dir := range []string{".", "Versions"} {
		f, err := b.root.Open(dir)
		if err != nil {
			return err
		}
		entries, err := f.ReadDir(maxBundleEntries + 1)
		_ = f.Close()
		if err != nil {
			return err
		}
		if len(entries) > maxBundleEntries {
			return unsupported("framework root entry count")
		}
		for _, entry := range entries {
			name := path.Join(dir, entry.Name())
			if err := bundleRelativePath(name); err != nil {
				return err
			}
			if name == "Contents" || name == "Support Files" {
				return unsupported("ambiguous framework layout")
			}
			if _, ok := required[name]; ok {
				required[name] = true
			}
			b.layoutEntries = append(b.layoutEntries, name)
			if name == "Versions" {
				if !entry.IsDir() {
					return unsupported("framework version is not a directory")
				}
				continue
			}
			if dir == "Versions" && entry.IsDir() && entry.Name() != "Current" {
				b.versions = append(b.versions, entry.Name())
				if len(b.versions) > maxNestedFiles {
					return unsupported("framework version count limit")
				}
				continue
			}
			if (entry.Name() == ".DS_Store" || name == "module.map") && entry.Type().IsRegular() {
				st, err := entry.Info()
				if err != nil {
					return err
				}
				if st.Mode().Perm()&0111 != 0 {
					return unsupported("executable unsealed framework metadata")
				}
				continue
			}
			if entry.Type()&os.ModeSymlink == 0 || dir == "Versions" && entry.Name() != "Current" {
				return unsupported("unsealed framework root: " + name)
			}
			target, err := b.root.Readlink(name)
			if err != nil {
				return err
			}
			target = strings.TrimPrefix(filepath.ToSlash(target), "./")
			if name == "Versions/Current" {
				if target != b.current {
					return invalid("framework version changed")
				}
			} else if target != "Versions/Current/"+name && target != "Versions/"+b.current+"/"+name {
				return unsupported("framework alias must name the current version's matching entry: " + name)
			}
		}
	}
	sort.Strings(b.versions)
	for name, found := range required {
		if !found {
			return unsupported("missing framework layout entry: " + name)
		}
	}
	return nil
}

func (b *appBundle) resourcesPath() string { return b.base + "_CodeSignature/CodeResources" }

func frameworkResourcePath(name string) bool {
	for _, dir := range []string{"Headers", "PrivateHeaders", "Modules"} {
		if name == dir || strings.HasPrefix(name, dir+"/") {
			return true
		}
	}
	return false
}

// Resource links are sealed as text. Target existence is checked within os.Root,
// but target bytes are never hashed through the link. Native absolute/system and
// outer-scope link policy remains outside this portable profile.
func (b *appBundle) resourceLink(name, rel string, scope *bundleScan) (string, error) {
	target, err := b.root.Readlink(name)
	if err != nil {
		return "", err
	}
	// Go's Windows symlink API stores backslashes; envelopes use POSIX spelling.
	target = filepath.ToSlash(target)
	if target == "" || strings.HasPrefix(target, "/") || len(target) > 1024 {
		return "", unsupported("bundle symlink target")
	}
	for _, part := range strings.Split(target, "/") {
		if part == "." || part == ".." {
			continue
		}
		if err := bundleRelativePath(part); err != nil {
			return "", err
		}
	}
	resolved := path.Clean(path.Join(path.Dir(rel), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return "", unsupported("bundle symlink escapes resource base")
	}
	if _, err := b.root.Stat(name); err != nil {
		return "", err
	}
	scope.bytes += int64(len(target))
	if scope.bytes > maxFileSize {
		return "", unsupported("bundle input exceeds 1 GiB")
	}
	return target, nil
}

func symlinkSeal(target string, optional bool) map[string]any {
	m := map[string]any{"symlink": target}
	if optional {
		m["optional"] = true
	}
	return m
}
