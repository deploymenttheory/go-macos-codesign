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

// Accept only the structural Current alias, with one physical sibling target.
// Other root symlinks remain unsupported. The physical target is opened and
// checked by openAppBundleVersion, so reads/writes never traverse Current.
func resolveFrameworkCurrent(name string) (string, error) {
	framework, version := frameworkVersionDirectory(name)
	if framework == "" {
		return name, nil
	}
	if err := bundleRelativePath(version); err != nil {
		return "", err
	}
	// Strip only directory suffixes before checking the final component. Clean
	// must not collapse an interior link/.. before the link has been resolved.
	name = filepath.FromSlash(name)
	for {
		name = strings.TrimRight(name, string(filepath.Separator))
		if !strings.HasSuffix(name, string(filepath.Separator)+".") {
			break
		}
		name = strings.TrimSuffix(name, string(filepath.Separator)+".")
	}
	parent, leaf := filepath.Split(name)
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	name = filepath.Join(parent, leaf)
	if _, version = frameworkVersionDirectory(name); version == "Current" {
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
