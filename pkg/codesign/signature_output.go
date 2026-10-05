package codesign

import (
	"context"
	"math"
	"sort"
	"strings"
)

// Names remain borrowed from the caller until transfer completes. The section
// starts zero-filled, supplying the terminating NULs and unused special slots.
func writeDirectoryPrefix(ctx context.Context, section workingSection, header []byte, identifier, team string) error {
	if _, err := section.WriteAt(header, 0); err != nil {
		return err
	}
	base := int64(len(header))
	for _, name := range []string{identifier, team} {
		dst := workingSection{reader: section, writer: section, base: base, size: int64(len(name))}
		if err := transferOutput(ctx, dst, outputSource{reader: strings.NewReader(name), size: int64(len(name))}); err != nil {
			return err
		}
		base += int64(len(name)) + 1
	}
	return nil
}

type signatureSection struct {
	slot uint32
	data outputSource
}

// superblobOutput builds only the index in memory. Components, including a
// spilled CodeDirectory, retain their source ranges through final transfer.
func superblobOutput(magic uint32, sections []signatureSection) (outputSource, error) {
	sort.Slice(sections, func(i, j int) bool { return sections[i].slot < sections[j].slot })
	if uint64(len(sections)) > (math.MaxUint32-12)/8 {
		return outputSource{}, malformed("signature index exceeds 32-bit length")
	}
	header := make([]byte, 12+8*len(sections))
	length := int64(len(header))
	be.PutUint32(header, magic)
	be.PutUint32(header[8:], uint32(len(sections)))
	plan := new(outputPlan)
	if err := plan.append(byteOutput(header)); err != nil {
		return outputSource{}, err
	}
	for i, section := range sections {
		if section.data.size < 8 || section.data.size > math.MaxUint32-length {
			return outputSource{}, malformed("signature component exceeds 32-bit length")
		}
		if i > 0 && section.slot == sections[i-1].slot {
			return outputSource{}, malformed("duplicate signature output slot")
		}
		be.PutUint32(header[12+8*i:], section.slot)
		be.PutUint32(header[16+8*i:], uint32(length))
		length += section.data.size
		if err := plan.append(section.data); err != nil {
			return outputSource{}, err
		}
	}
	be.PutUint32(header[4:], uint32(length))
	return plan.output(), nil
}
