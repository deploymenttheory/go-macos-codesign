package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

// Native verification has separate integrity, verbose self-requirement and
// explicit requirement stages. A failed self check does not skip the -R check.
func checkVerificationRequirements(stderr io.Writer, report *codesign.Report, path string, o options) (bool, error) {
	passed := true
	selected, err := report.SelectArchitecture(o.architecture)
	if err != nil {
		return false, err
	}
	if o.verbose > 0 {
		fmt.Fprintf(stderr, "%s: valid on disk\n", path)
		err := report.CheckDesignatedRequirement(selected.Name)
		if err != nil && !errors.Is(err, codesign.ErrDesignatedRequirement) {
			return false, err
		}
		if err != nil {
			passed = false
			fmt.Fprintf(stderr, "%s: does not satisfy its designated Requirement\n", path)
		} else {
			fmt.Fprintf(stderr, "%s: satisfies its Designated Requirement\n", path)
		}
	}
	if o.testRequirement != "" {
		err := report.CheckRequirement(o.testRequirement, o.architecture)
		if err != nil && !errors.Is(err, codesign.ErrRequirement) {
			return false, err
		}
		if err != nil {
			passed = false
			fmt.Fprintln(stderr, "test-requirement: "+codesign.ErrRequirement.Error())
		} else if o.verbose > 0 {
			fmt.Fprintf(stderr, "%s: explicit requirement satisfied\n", path)
		}
	}
	return passed, nil
}
