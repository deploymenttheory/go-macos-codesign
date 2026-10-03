package codesign

import (
	"errors"

	"github.com/deploymenttheory/go-macos-codesign/pkg/plist"
)

type bundlePlistLimitError = plist.LimitError

// Parsing is shared; only codesign decides whether native-invalid metadata
// permits discovery to retain the acquired raw plist URL. Limits and unsupported
// representations remain fatal before any signature mutation.
func decodeRemovalPlist(data []byte) (map[string]any, error) {
	value, err := plist.Decode(data)
	var limit *plist.LimitError
	if errors.As(err, &limit) || errors.Is(err, plist.ErrUnsupported) {
		return nil, plistOperationError{err}
	}
	if err != nil {
		return nil, nil
	}
	values, _ := value.(map[string]any)
	return values, nil
}

func decodeBundlePlist(data []byte) (map[string]any, error) {
	values, err := plist.DecodeDictionary(data)
	if err != nil {
		return nil, plistOperationError{err}
	}
	return values, nil
}

// Preserve codesign diagnostics and errors.Is while retaining the codec's
// classified cause, including errors.As for resource limits.
type plistOperationError struct{ cause error }

func (e plistOperationError) kind() error {
	if errors.Is(e.cause, plist.ErrUnsupported) {
		return ErrUnsupported
	}
	return ErrFormat
}
func (e plistOperationError) Error() string   { return e.kind().Error() + ": " + e.cause.Error() }
func (e plistOperationError) Unwrap() []error { return []error{e.kind(), e.cause} }
