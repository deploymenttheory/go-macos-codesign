package codesign

// signingSignatureState is all a replacement notice/admission needs. Every
// architecture is nevertheless parsed before reporting any notice, so a later
// malformed signature keeps the existing whole-inspection precedence.
type signingSignatureState struct {
	present bool
	flags   uint32
}

func (s codeSource) signingSignatures(c *container) ([]signingSignatureState, error) {
	states := make([]signingSignatureState, len(c.slices)) // parser bounds universal slices to128
	for i, slice := range c.slices {
		im := slice.image
		if im.sigCommand < 0 {
			continue
		}
		source := codeSource{s.ctx, outputSource{s.source.reader, s.source.offset + int64(slice.offset) + int64(im.sigOffset), int64(im.sigSize)}}
		view, err := parseSignatureView(source, false)
		if err != nil {
			return nil, err
		}
		states[i] = signingSignatureState{true, view.directories[0].metadata.Flags}
	}
	return states, nil
}

func parseDMGSigningSource(source codeSource, trailer []byte) (*dmgImage, error) {
	return parseDMGStructure(uint64(source.source.size), trailer, func(offset, length uint64) (dmgSignatureState, error) {
		view, err := parseSignatureView(codeSource{source.ctx, outputSource{source.source.reader, source.source.offset + int64(offset), int64(length)}}, true)
		if err != nil {
			return dmgSignatureState{}, err
		}
		state := dmgSignatureState{length: view.length, signed: view.directoryCount != 0}
		if state.signed {
			state.flags = view.directories[0].metadata.Flags
		}
		return state, nil
	})
}
