package codesign

// prepareRequirements follows Apple's InternalRequirements maker: copy supplied
// entries, synthesize a designated requirement only when absent, and repack by
// unsigned kind. Representation-specific library/interpreter defaults are not
// implemented. The caller's bytes are never modified, including on failure.
func prepareRequirements(opts *SignOptions, chain []*certificate) error {
	data := opts.Requirements
	if len(data) > 1<<20 || len(data) >= 12 && be.Uint32(data) == MagicRequirements && be.Uint32(data[8:]) > 64 {
		return unsupported("requirements set exceeds 1 MiB or 64 entries")
	}
	var entries []Blob
	designated := false
	if len(data) != 0 {
		if err := validateRequirements(data); err != nil {
			return err
		}
		for i := uint32(0); i < be.Uint32(data[8:]); i++ {
			kind, offset := be.Uint32(data[12+8*i:]), be.Uint32(data[16+8*i:])
			length := be.Uint32(data[offset+4:])
			entries = append(entries, Blob{Slot: kind, Data: data[offset : offset+length]})
			designated = designated || kind == 3
		}
	}
	if !designated && len(chain) != 0 {
		generated, err := defaultCertificateRequirement(opts.Identifier, chain)
		if err != nil {
			return err
		}
		// The shared builder returns exactly one designated entry.
		offset := be.Uint32(generated[16:])
		entries = append(entries, Blob{Slot: 3, Data: generated[offset:]})
	}
	if len(entries) > 64 {
		return unsupported("default requirement exceeds 64-entry set limit")
	}
	merged := superblob(MagicRequirements, entries)
	if len(merged) > 1<<20 {
		return unsupported("default requirement exceeds 1 MiB set limit")
	}
	opts.Requirements = merged
	return nil
}
