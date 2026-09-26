package codesign

// CheckRequirement evaluates a caller-supplied predicate against every directory
// in a verified architecture. An empty architecture checks all architectures
// selected by the successful Verify/VerifyBytes call; an explicit name narrows
// that selection and cannot select an architecture that was not verified.
// It does not reread the code or change Valid. The verified report must not be
// modified before this check. Inspection alone cannot supply a verified context.
func (r *Report) CheckRequirement(source, architecture string) error {
	n, err := parseRequirement(source)
	if err != nil {
		return err
	}
	return r.checkRequirements(architecture, func(_ *Signature, d Directory) error {
		if !n.matches(d) {
			return ErrRequirement
		}
		return nil
	})
}

// CheckDesignatedRequirement separately tests the code's stored designated
// requirement after successful verification. An absent stored requirement passes;
// the supported implicit requirements identify the code from which they derive.
// This is the additional check performed by verbose native CLI verification.
// Architecture selection follows CheckRequirement. It does not change Valid or
// reread the input. Callers must not modify the report before checking it.
func (r *Report) CheckDesignatedRequirement(architecture string) error {
	return r.checkRequirements(architecture, func(s *Signature, d Directory) error {
		return checkDesignatedRequirement(s.find(SlotRequirements), d)
	})
}

func (r *Report) checkRequirements(architecture string, check func(*Signature, Directory) error) error {
	if r == nil || !r.Valid || len(r.Architectures) == 0 {
		return invalid("requirement evaluation requires successful verification")
	}
	if architecture == "" {
		architecture = r.verifiedArchitecture
	} else {
		if _, err := r.SelectArchitecture(architecture); err != nil {
			return err
		}
		if r.verifiedArchitecture != "" && r.verifiedArchitecture != architecture {
			return invalid("architecture %s was not verified", architecture)
		}
	}
	for _, a := range r.Architectures {
		if architecture != "" && architecture != a.Name {
			continue
		}
		for _, d := range a.Signature.Directories {
			if err := check(a.Signature, d); err != nil {
				return err
			}
		}
	}
	return nil
}
