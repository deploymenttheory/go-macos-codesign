package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func verificationDiagnostic(stdout, stderr io.Writer, path string, err error, o options) {
	var detail *codesign.VerificationError
	if !errors.As(err, &detail) {
		fmt.Fprintf(stderr, "%s: %s\n", path, diagnostic(err))
		return
	}
	fmt.Fprintf(stderr, "%s: %s\n", path, detail.Diagnostic)
	if detail.Subcomponent != "" {
		fmt.Fprintf(stderr, "In subcomponent: %s\n", detail.Subcomponent)
	}
	if detail.Architecture != "" {
		fmt.Fprintf(stderr, "In architecture: %s\n", detail.Architecture)
	}
	if o.verbose > 0 {
		// --json is a portable extension: keep its stdout parseable.
		if o.json {
			stdout = stderr
		}
		for _, message := range detail.AttachedData {
			fmt.Fprintf(stdout, "file with invalid attached data: %s\n", message)
		}
		for _, group := range []struct {
			label string
			paths []string
		}{{"added", detail.AddedResources}, {"modified", detail.ModifiedResources}, {"missing", detail.MissingResources}} {
			for _, resource := range group.paths {
				fmt.Fprintf(stdout, "file %s: %s\n", group.label, resource)
			}
		}
	}
}
