package codesign

import "errors"

// VerificationError carries native diagnostic context for a verified failure
// class. Error and Unwrap retain the detailed Go error and its sentinel identity.
// Unclassified failures (including portable trust policy) keep their own errors.
type VerificationError struct {
	Diagnostic        string
	Architecture      string
	Subcomponent      string
	ModifiedResources []string
	cause             error
	omitArchitecture  bool
}

func (e *VerificationError) Error() string { return e.cause.Error() }
func (e *VerificationError) Unwrap() error { return e.cause }

const signatureDiagnostic = "invalid signature (code or signature have been modified)"

func verificationFailure(message string, err error) error {
	return &VerificationError{Diagnostic: message, cause: err}
}

func verificationArchitecture(err error, architecture string) error {
	var detail *VerificationError
	if errors.As(err, &detail) && architecture != "dmg" && !detail.omitArchitecture {
		copy := *detail
		copy.Architecture = architecture
		copy.cause = err
		return &copy
	}
	return err
}

func slotVerificationFailure(slot uint32, err error) error {
	message := signatureDiagnostic
	switch slot {
	case SlotInfo:
		message = "invalid Info.plist (plist or signature have been modified)"
	case SlotResources:
		message = "invalid resource directory (directory or signature have been modified)"
	}
	return &VerificationError{Diagnostic: message, cause: err, omitArchitecture: slot == SlotResources}
}
