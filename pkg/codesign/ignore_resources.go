package codesign

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path"
)

// Ignoring resources does not disable Apple's later structural validation.
// Inspect only the outer root and signature directory; do not open resources,
// their targets, child code or the contents of CodeResources.
func (b *appBundle) verifyIgnoredResourceStructure(report *Report) error {
	unsealed := func() error {
		return verificationFailure("unsealed contents present in the bundle root", invalid("unsealed bundle structure"))
	}
	if !b.framework {
		entries, err := b.structureEntries(".")
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() == "Contents" && entry.IsDir() || entry.Name() == ".DS_Store" && entry.Type().IsRegular() {
				continue
			}
			return unsealed()
		}
	}
	name := path.Join(b.base, "_CodeSignature")
	st, err := b.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return unsupported("symlinked signature directory")
	}
	if !st.IsDir() {
		return verificationFailure("Not a directory", invalid("signature directory is not a directory"))
	}
	entries, err := b.structureEntries(name)
	if err != nil {
		return err
	}
	selected, err := report.SelectArchitecture(report.verifiedArchitecture)
	if err != nil {
		return err
	}
	d := selected.Signature.Directories[0]
	resourceSlot := false
	if d.SpecialSlots >= SlotResources {
		offset := d.HashOffset - SlotResources*uint32(d.HashSize)
		resourceSlot = !bytes.Equal(d.Raw[offset:offset+uint32(d.HashSize)], make([]byte, d.HashSize))
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		allowed := entry.Name() == "CodeResources" && resourceSlot || entry.Name() == "CodeSignature" && info.Size() == 0
		if !info.Mode().IsRegular() || !allowed {
			return unsealed()
		}
	}
	return nil
}

func (b *appBundle) structureEntries(name string) ([]os.DirEntry, error) {
	f, err := b.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(maxBundleEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxBundleEntries {
		return nil, unsupported("bundle structural entry count limit")
	}
	return entries, nil
}
