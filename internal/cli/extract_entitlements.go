package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func extractEntitlements(stdout, stderr io.Writer, report *codesign.Report, o *options) error {
	arch, err := report.SelectArchitecture(o.architecture)
	if err != nil {
		return err
	}
	path := o.entitlements
	xml := strings.HasPrefix(path, ":")
	if xml {
		path = strings.TrimPrefix(path, ":")
		o.entitlements = path
		fmt.Fprintln(stderr, "warning: Specifying ':' in the path is deprecated and will not work in a future release")
	}
	metadata, err := codesign.InspectEntitlements(arch.Signature)
	if errors.Is(err, codesign.ErrInvalid) || errors.Is(err, codesign.ErrFormat) || xml && metadata != nil && metadata.XML == nil {
		fmt.Fprintln(stderr, "warning: binary contains an invalid entitlements blob. The OS will ignore these entitlements.")
		return nil
	}
	if err != nil || metadata == nil {
		return err
	}
	// Native opens the append destination before validating the text form.
	out := stdout
	var file *os.File
	if path != "-" {
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return &outputFileError{path, certificateOutputError(path, err)}
		}
		out = file
	}
	if !xml && !metadata.TextValid {
		if file != nil {
			_ = file.Close()
		}
		return &nativeCLIError{"codesign: could not validate entitlement data", 65}
	}
	data := metadata.Text
	if xml {
		data = metadata.XML
	}
	_, err = out.Write(data)
	if file != nil {
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return &outputFileError{path, certificateOutputError(path, err)}
	}
	return nil
}
