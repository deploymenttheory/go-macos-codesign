package cli

import (
	"errors"
	"io"
	"os"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func extractRequirements(stdout io.Writer, report *codesign.Report, o options) error {
	// Native truncates/creates the destination before fetching the component.
	out := stdout
	var file *os.File
	var err error
	if o.requirements != "-" {
		file, err = os.OpenFile(o.requirements, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			return &outputFileError{o.requirements, certificateOutputError(o.requirements, err)}
		}
		defer file.Close()
		out = file
	}
	text, err := report.RequirementText(o.architecture)
	if errors.Is(err, codesign.ErrInvalid) {
		return certificateOutputDiagnostic("invalid signature (code or signature have been modified)")
	}
	if err != nil {
		return err
	}
	_, err = out.Write(text)
	if file != nil {
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return &outputFileError{o.requirements, certificateOutputError(o.requirements, err)}
	}
	return nil
}
