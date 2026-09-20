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
	if version != "Current" {
		return filepath.Clean(name), nil
	}
	target, err := os.Readlink(filepath.Clean(name))
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
	return filepath.Join(framework, "Versions", target), nil
}
