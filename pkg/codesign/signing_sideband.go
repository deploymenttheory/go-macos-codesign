package codesign

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-macos-codesign/internal/sideband"
)

// BundleDiskRep constructs its executable representation before signing starts.
// checkPlainFile qualifies pathname failures with the executable; the subsequent
// appleInternalForcePlatform metadata query fails without that qualification.
func (b *appBundle) signingExecutable(ctx context.Context) ([]byte, error) {
	data, err := b.read(b.executable, maxFileSize)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			name, absErr := filepath.Abs(filepath.Join(b.path, filepath.FromSlash(b.executable)))
			if absErr != nil {
				return nil, absErr
			}
			return nil, signingNestedError(name, err)
		}
		return nil, err
	}
	f, err := b.root.Open(b.executable)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := sideband.CheckPlatformAttribute(ctx, f); err != nil {
		return nil, err
	}
	return data, nil
}

func signingNestedError(name string, err error) error {
	err = nestedVerificationError(name, signingIOError(err))
	var detail *VerificationError
	if errors.As(err, &detail) {
		copy := *detail
		copy.AttachedData = nil // Apple's signing wrapper drops the child's detail dictionary.
		copy.Subcomponent = name
		return &copy
	}
	return err
}

// Preserve the underlying host error for errors.Is while reporting the native
// signing diagnostic. Convert before nested wrapping to retain Subcomponent.
// Do not replace an already-qualified diagnostic or hide cancellation.
func signingIOError(err error) error {
	var detail *VerificationError
	if errors.As(err, &detail) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	message := ""
	switch {
	case errors.Is(err, syscall.EPERM):
		message = "Operation not permitted"
	case errors.Is(err, os.ErrPermission):
		message = "Permission denied"
	default:
		return err
	}
	return &VerificationError{Diagnostic: message, cause: err, omitArchitecture: true}
}

type signingMetadataError struct{ err error }

func (e *signingMetadataError) Error() string { return e.err.Error() }
func (e *signingMetadataError) Unwrap() error { return e.err }

func metadataSigningFailure(err error) bool {
	var failure *signingMetadataError
	return errors.As(err, &failure)
}

func signingHasSignature(data []byte) bool {
	r, err := InspectBytes(data)
	if err != nil {
		return false
	}
	for _, arch := range r.Architectures {
		if arch.Signature != nil && arch.Signature.Directories[0].Flags&0x20000 == 0 {
			return true
		}
	}
	return false
}

func signingNeedsNested(data []byte, force bool) bool {
	if force {
		return true
	}
	r, err := InspectBytes(data)
	return err != nil || !signingComplete(r)
}

func signingComplete(report *Report) bool {
	for _, arch := range report.Architectures {
		if arch.Signature == nil || arch.Signature.Directories[0].Flags&0x20000 != 0 {
			return false
		}
	}
	return len(report.Architectures) != 0
}

func signingSideband(ctx context.Context, file *os.File, path string, carrier appledouble.Value, opts SignOptions, resource bool) error {
	if opts.NoStrict && (!resource || !opts.StripDisallowedXattrs) {
		return nil
	}
	if opts.StripDisallowedXattrs {
		if err := sideband.Strip(ctx, file, carrier); err != nil {
			return err
		}
	}
	if opts.NoStrict {
		return nil
	}
	name, err := sideband.First(ctx, file, carrier)
	if err != nil {
		return err
	}
	if name != "" {
		return sidebandFailure(path, []string{name}, false)
	}
	return nil
}

func (s *bundleSidebandInputs) carrier(file *os.File) (appledouble.Value, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	for _, binding := range s.bindings {
		if os.SameFile(info, binding.info) {
			return binding.value, nil
		}
	}
	return nil, nil
}

func (b *appBundle) startSigningSideband(ctx context.Context, opts SignOptions, inputs *bundleSidebandInputs) error {
	b.signing, b.signingInputs = &opts, inputs
	var err error
	b.sidebandBase, err = filepath.Abs(b.path)
	if err != nil {
		return err
	}
	name, diagnostic := ".", b.sidebandBase
	if b.version != "" {
		name = strings.TrimSuffix(b.base, "/")
		diagnostic = filepath.Join(b.sidebandBase, "Versions", b.selection) + string(filepath.Separator) + "."
	}
	if err := b.signingPath(ctx, name, diagnostic, false); err != nil {
		return err
	}
	return b.signingPath(ctx, b.executable, b.sidebandDiagnostic(b.executable), false)
}

func (b *appBundle) signingPath(ctx context.Context, name, diagnostic string, resource bool) error {
	f, err := b.root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return b.signingFile(ctx, f, diagnostic, resource)
}

func (b *appBundle) signingFile(ctx context.Context, file *os.File, diagnostic string, resource bool) error {
	carrier, err := b.signingInputs.carrier(file)
	if err != nil {
		return err
	}
	return signingSideband(ctx, file, diagnostic, carrier, *b.signing, resource)
}
