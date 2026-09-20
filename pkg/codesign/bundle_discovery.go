package codesign

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// bundlePath identifies supported directories and main-executable inputs. A
// helper in the same directory is still a standalone file: path identity, not
// inode identity, selects the bundle. Empty means use a single-file format.
func bundlePath(name string) (string, error) {
	if framework, _ := frameworkVersionDirectory(name); framework != "" {
		return name, nil // retain structural Current validation for directory inputs
	}
	// Resolve before Clean/Abs: link/.. must select the physical parent on every
	// OS. File aliases select the target's bundle, not the alias's neighbours.
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return name, nil
	}
	parent := filepath.Dir(resolved)
	bundle, info := "", ""
	if filepath.Base(parent) == "MacOS" && filepath.Base(filepath.Dir(parent)) == "Contents" {
		bundle, info = filepath.Dir(filepath.Dir(parent)), "Contents/Info.plist"
	} else if framework, _ := frameworkVersionDirectory(parent); framework != "" || strings.EqualFold(filepath.Ext(parent), ".framework") {
		bundle, info = parent, "Resources/Info.plist"
	} else {
		return "", nil
	}
	root, err := os.OpenRoot(bundle)
	if err != nil {
		return "", err
	}
	defer root.Close()
	b := appBundle{root: root}
	data, err := b.read(info, maxBundlePlist)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	values, err := decodeBundlePlist(data)
	if err != nil {
		return "", err
	}
	executable, ok := values["CFBundleExecutable"].(string)
	if !ok || executable == "" {
		// CFBundle falls back to the bundle's stem. Loading the selected bundle
		// still enforces our explicit metadata requirements before any write.
		executable = frameworkName(bundle)
	}
	if executable != filepath.Base(resolved) {
		return "", nil
	}
	return filepath.Abs(bundle)
}
