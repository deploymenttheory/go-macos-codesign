package codesign

func (s codeSource) inspectView() (*Report, error) {
	dmg, err := s.isDMG()
	if err != nil {
		return nil, err
	}
	if dmg {
		trailer, err := s.read(uint64(s.source.size)-uint64(dmgFooterSize), uint64(dmgFooterSize))
		if err != nil {
			return nil, err
		}
		var signature *Signature
		m, err := parseDMGStructure(uint64(s.source.size), trailer, func(offset, length uint64) (dmgSignatureState, error) {
			view, err := parseSignatureView(codeSource{s.ctx, outputSource{s.source.reader, s.source.offset + int64(offset), int64(length)}}, true)
			if err != nil {
				return dmgSignatureState{}, err
			}
			state := dmgSignatureState{length: view.length, signed: view.directoryCount != 0}
			if state.signed {
				signature, err = view.report()
				state.flags = view.directories[0].metadata.Flags
			}
			return state, err
		})
		if err != nil {
			return nil, err
		}
		m.signature = signature
		return inspectDMGImage(m, uint64(s.source.size)), nil
	}
	c, err := s.container()
	if err != nil {
		return nil, err
	}
	r := &Report{Format: "Mach-O thin"}
	if c.fat {
		r.Format = "Mach-O universal"
	}
	for _, slice := range c.slices {
		im := slice.image
		a := Architecture{Name: archName(slice.cpu, slice.subtype), CPU: slice.cpu, Subtype: slice.subtype, Offset: slice.offset, Size: slice.size, SignatureOffset: uint64(im.sigOffset), SignatureSize: im.sigSize}
		a.VersionPlatform, a.VersionMin, a.VersionSDK = im.versionPlatform, im.versionMin, im.versionSDK
		if im.sigCommand >= 0 {
			source := codeSource{s.ctx, outputSource{s.source.reader, s.source.offset + int64(slice.offset) + int64(im.sigOffset), int64(im.sigSize)}}
			view, err := parseSignatureView(source, false)
			if err != nil {
				return nil, err
			}
			a.Signature, err = view.report()
			if err != nil {
				return nil, err
			}
			a.Signature.CertificateMetadata, _ = InspectCertificateMetadata(a.Signature)
		}
		r.Architectures = append(r.Architectures, a)
	}
	return r, nil
}
