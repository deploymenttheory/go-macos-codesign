package cli

import (
	"errors"
	"os"
	"strconv"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func extractCertificates(report *codesign.Report, o options) error {
	arch, err := displayArchitecture(report, o.architecture)
	if err != nil {
		return err
	}
	metadata := arch.Signature.CertificateMetadata
	if metadata == nil {
		return nil // Native display supplies no chain for ad-hoc/unreadable CMS.
	}
	for i, der := range metadata.Certificates {
		name := o.certificatePrefix + strconv.Itoa(i)
		// Native extraction truncates existing files in place, follows aliases,
		// retains their modes and leaves earlier outputs on a later failure.
		if err := os.WriteFile(name, der, 0644); err != nil {
			return certificateOutputError(name, err)
		}
	}
	return nil
}

// The recorded English native profile reports the output failure against the
// input operand, without exposing Go's operation/path wrapper. Keep unknown OS
// errors explicit instead of claiming all filesystem diagnostics are equivalent.
func certificateOutputError(name string, err error) error {
	if info, statErr := os.Stat(name); statErr == nil && info.IsDir() {
		return certificateOutputDiagnostic("Is a directory")
	}
	if errors.Is(err, os.ErrNotExist) {
		return certificateOutputDiagnostic("No such file or directory")
	}
	if errors.Is(err, os.ErrPermission) {
		return certificateOutputDiagnostic("Permission denied")
	}
	return err
}

// These user-facing diagnostics retain native codesign's capitalization.
type certificateOutputDiagnostic string

func (e certificateOutputDiagnostic) Error() string { return string(e) }
