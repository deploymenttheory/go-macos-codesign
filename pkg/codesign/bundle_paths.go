package codesign

import (
	"os"
	"path/filepath"
	"strings"
)

// A physical framework version is a standalone shallow bundle. Its containing
// framework identifies the executable name, but is not its resource boundary.
func frameworkVersionDirectory(name string) (framework, version string) {
	name = filepath.Clean(name)
	versions := filepath.Dir(name)
	framework = filepath.Dir(versions)
	if filepath.Base(versions) != "Versions" || !strings.EqualFold(filepath.Ext(framework), ".framework") {
		return "", ""
	}
	return framework, filepath.Base(name)
}

func frameworkName(name string) string {
	if framework, _ := frameworkVersionDirectory(name); framework != "" {
		name = framework
	}
	return strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
}

// Resolve directory parents before lexical cleanup, preserving physical link/..
// selection. The final directory must remain physical except for a framework's
// validated structural Current alias. Internal resource/write links keep their
// existing containment rules.
func resolveBundleDirectory(name string) (string, error) {
	// Strip only directory suffixes before checking the final component. Clean
	// must not collapse an interior link/.. before the link has been resolved.
	name = filepath.FromSlash(name)
	original := name
	for {
		name = strings.TrimRight(name, string(filepath.Separator))
		if !strings.HasSuffix(name, string(filepath.Separator)+".") {
			break
		}
		name = strings.TrimSuffix(name, string(filepath.Separator)+".")
	}
	if name == "" || name == filepath.VolumeName(original) {
		name = original // retain filesystem/volume roots when stripping suffixes
	}
	parent, leaf := filepath.Split(name)
	if parent == "" {
		parent = "."
	}
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	name = filepath.Join(parent, leaf)
	framework, version := frameworkVersionDirectory(name)
	if framework == "" {
		return name, nil
	}
	if err := bundleRelativePath(version); err != nil {
		return "", err
	}
	if version == "Current" {
		target, err := os.Readlink(name)
		if err != nil {
			return "", err
		}
		target = strings.TrimPrefix(filepath.ToSlash(target), "./")
		if target == "Current" || strings.Contains(target, "/") || target == "." {
			return "", unsupported("framework Current must name one physical version")
		}
		if err := bundleRelativePath(target); err != nil {
			return "", err
		}
		name = filepath.Join(filepath.Dir(name), target)
	}
	st, err := os.Lstat(name)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", unsupported("framework version root must be a physical directory")
	}
	return name, nil
}
