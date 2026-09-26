package codesign

import (
	"bytes"
	"fmt"
	"strings"
)

// RequirementText returns owned, canonical source text for the selected code's
// internal requirements. An absent designated requirement is synthesized and
// emitted as a comment. Ad-hoc synthesis includes the selected architecture's
// hash first, followed by the other architectures in container order. An
// explicit architecture restricts synthesis to that architecture.
//
// This descriptive operation checks the requirements component's binding, not
// executable pages or trust. It supports the existing requirement expression
// subset, sets up to 1 MiB and one CodeDirectory per architecture. Unsupported
// expressions and alternate directories return ErrUnsupported.
func (r *Report) RequirementText(architecture string) ([]byte, error) {
	a, err := r.SelectArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	directory, err := requirementDirectory(a.Signature)
	if err != nil {
		return nil, err
	}
	data := a.Signature.find(SlotRequirements)
	if stored := directory.specialSlotHash(SlotRequirements); stored == nil {
		data = nil // Native ignores a component with no nonzero directory hash.
	} else {
		actual, _ := digest(directory.HashType, data)
		if data == nil || !bytes.Equal(actual, stored) {
			return nil, invalid("requirements component hash")
		}
	}
	text, designated, err := requirementSetText(data)
	if err != nil || designated {
		return []byte(text), err
	}
	if directory.Flags&FlagAdhoc != 0 {
		hashes := []string{`cdhash H"` + directory.CDHash + `"`}
		for i := range r.Architectures {
			other := &r.Architectures[i]
			if other == a || architecture != "" {
				continue
			}
			d, err := requirementDirectory(other.Signature)
			if err != nil {
				return nil, err
			}
			hashes = append(hashes, `cdhash H"`+d.CDHash+`"`)
		}
		return []byte(text + "# designated => " + strings.Join(hashes, " or ") + "\n"), nil
	}
	metadata, err := InspectCertificateMetadata(a.Signature)
	if err != nil {
		return nil, err
	}
	if metadata == nil {
		return nil, unsupported("designated requirement synthesis without a bound certificate chain")
	}
	chain, err := linkedCertificates(metadata.Certificates[0], metadata.Certificates)
	if err != nil {
		return nil, err
	}
	generated, err := defaultCertificateRequirement(directory.Identifier, chain)
	if err != nil {
		return nil, err
	}
	implicit, _, err := requirementSetText(generated)
	return []byte(text + "# " + implicit), err
}

func requirementDirectory(signature *Signature) (Directory, error) {
	if signature == nil {
		return Directory{}, ErrUnsigned
	}
	if len(signature.Directories) > 1 {
		return Directory{}, unsupported("requirement extraction with alternate CodeDirectories")
	}
	return parseDirectory(signature.find(SlotDirectory))
}

func requirementSetText(data []byte) (string, bool, error) {
	if data == nil {
		return "", false, nil
	}
	if len(data) > 1<<20 {
		return "", false, unsupported("requirements set exceeds 1 MiB")
	}
	if len(data) >= 12 && be.Uint32(data[8:]) > 64 {
		return "", false, unsupported("requirements set exceeds 64 entries")
	}
	if err := validateRequirements(data); err != nil {
		return "", false, err
	}
	var text strings.Builder
	designated := false
	names := [...]string{"invalid", "host", "guest", "designated", "library", "plugin"}
	for i := uint32(0); i < be.Uint32(data[8:]); i++ {
		kind, offset := be.Uint32(data[12+i*8:]), be.Uint32(data[16+i*8:])
		length := be.Uint32(data[offset+4:])
		n, _ := decodeRequirement(data[offset : offset+length]) // validated above
		name := fmt.Sprintf("/*unknown type*/ %d", int32(kind))
		if kind < uint32(len(names)) {
			name = names[kind]
		}
		text.WriteString(name + " => " + n.text(3) + "\n")
		designated = designated || kind == 3
	}
	return text.String(), designated, nil
}

// specialSlotHash requires a parsed directory. A zero hash denotes absence.
func (d Directory) specialSlotHash(slot uint32) []byte {
	if slot == 0 || slot > d.SpecialSlots {
		return nil
	}
	offset := d.HashOffset - slot*uint32(d.HashSize)
	hash := d.Raw[offset : offset+uint32(d.HashSize)]
	if bytes.Equal(hash, make([]byte, len(hash))) {
		return nil
	}
	return hash
}
