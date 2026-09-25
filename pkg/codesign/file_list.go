package codesign

import (
	"fmt"
	"os"
	"path/filepath"
)

// SelectArchitecture selects a signed architecture for descriptive operations.
// An empty name prefers arm64, then the first architecture in the container.
// Selection and inspection do not establish integrity or trust.
func (r *Report) SelectArchitecture(name string) (*Architecture, error) {
	var selected *Architecture
	for i := range r.Architectures {
		a := &r.Architectures[i]
		if name != "" {
			if a.Name == name {
				selected = a
				break
			}
		} else if selected == nil || a.Name == "arm64" {
			selected = a
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("architecture %q not present", name)
	}
	if selected.Signature == nil {
		return nil, ErrUnsigned
	}
	return selected, nil
}

// SignatureFiles describes the selected representation's signature files in
// native file-list order. It is a packaging list, not a mutation journal: it
// includes existing external signature components absent from the executable,
// excludes ordinary resources and nested code, and does not verify their bytes.
// The report must come from path-based inspection; filesystem existence is
// observed at the time of this call. Framework resource spelling retains /./.
func (r *Report) SignatureFiles(architecture string) ([]string, error) {
	a, err := r.SelectArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	if r.Path == "" {
		return nil, unsupported("file list requires path-based inspection")
	}
	executable := r.Path
	if r.Bundle != nil {
		executable = r.Bundle.Executable
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return nil, err
	}
	files := []string{executable}
	if r.Bundle == nil {
		return files, nil
	}
	base, err := filepath.Abs(r.Path)
	if err != nil {
		return nil, err
	}
	// Join would erase the literal dot in versioned framework metadata paths.
	base += string(filepath.Separator) + filepath.FromSlash(r.Bundle.signaturePath) + string(filepath.Separator)
	for _, component := range []struct {
		slot uint32
		name string
	}{
		{SlotDirectory, "CodeDirectory"}, {SlotCMS, "CodeSignature"},
		{SlotResources, "CodeResources"}, {4, "CodeTopDirectory"},
		{SlotEntitlements, "CodeEntitlements"}, {SlotDEREntitlements, "CodeEntitlementDER"},
		{SlotRepSpecific, "CodeRepSpecific"},
		{0x1000, "CodeRequirements-1"}, {0x1001, "CodeRequirements-2"},
		{0x1002, "CodeRequirements-3"}, {0x1003, "CodeRequirements-4"}, {0x1004, "CodeRequirements-5"},
	} {
		if a.Signature.find(component.slot) != nil {
			continue
		}
		name := base + component.name
		if _, err := os.Stat(name); err == nil {
			files = append(files, name)
		}
	}
	return files, nil
}
