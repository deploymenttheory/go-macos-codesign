package codesign

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Removal does not need signing identifiers or package types. Keep its discovery
// separate from the stricter loader used to construct and verify signatures.
// root ownership transfers on success and is released on every failure.
func loadRemovalBundle(root *os.Root, path, version string) (*appBundle, error) {
	b := &appBundle{root: root, path: path, selection: version}
	if err := b.discoverRemovalExecutable(); err != nil {
		root.Close()
		return nil, err
	}
	return b, nil
}

func (b *appBundle) discoverRemovalExecutable() error {
	if err := b.discoverLayout(); err != nil {
		return err
	}
	info, err := b.read(b.infoPath, maxBundlePlist)
	if err != nil {
		return err
	}
	values, err := decodeBundlePlist(info)
	if err != nil {
		return err
	}
	// These require separate disk representations or resource-root policies.
	for _, key := range []string{"MainHTML", "CFBundleResourceSpecification"} {
		if _, exists := values[key]; exists {
			return unsupported("bundle metadata: " + key)
		}
	}
	value, present := values["CFBundleExecutable"]
	if !present {
		value = values["NSExecutable"]
	}
	name, _ := value.(string)
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(b.path), filepath.Ext(b.path))
	}
	if name == "." || strings.Contains(name, "/") {
		return malformed("CFBundleExecutable must name one file")
	}
	if err := bundleRelativePath(name); err != nil {
		return err
	}
	// macOS 27 probes select MacOS, the support-files directory, then the
	// wrapper root. Historical CF's Mac OS X/MacOSClassic search is not observed.
	candidates := []string{b.base + "MacOS/" + name, b.base + name}
	if b.base == "Contents/" {
		candidates = append(candidates, name)
	}
	for _, candidate := range candidates {
		_, err := hostdata.StatMetadata(b.root, candidate)
		// CoreFoundation's existence query rejects inaccessible metadata too.
		// This is solely the discovery stat, before any data or attribute read;
		// errors from opening a selected file must never trigger this fallback.
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			continue
		}
		if err != nil {
			return err
		}
		// Selection is based on existence, not a successful data read. A present
		// directory, denied read, or malformed Mach-O must fail without fallback.
		b.executable = candidate
		return nil
	}
	// BundleDiskRep uses FileDiskRep for this nominal main executable. A valid
	// plist cannot be a Mach-O, so the existing generic remover handles it.
	b.executable = b.infoPath
	return nil
}
