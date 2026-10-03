// Package plist implements bounded Apple property-list parsing in pure Go.
// It has no filesystem, code-signing or platform-service dependencies. Callers
// retain ownership of source bytes and decide how parsing failures affect their
// operations. Native behavior is qualified by the repository's captured corpora.
package plist

import (
	"errors"
	"fmt"

	codec "howett.net/plist"
)

// The current qualified decoding profile bounds input, expanded data, nesting
// and expanded object references independently of the caller's acquisition limit.
const (
	MaxSize   = 8 << 20
	MaxDepth  = 32
	MaxValues = 100000
)

var (
	ErrFormat      = errors.New("invalid property list")
	ErrUnsupported = errors.New("unsupported property-list representation")
)

// Error preserves a parser diagnostic independently of its consumer's error
// namespace. errors.Is identifies ErrFormat or ErrUnsupported.
type Error struct {
	Kind   error
	Detail string
}

func (e *Error) Error() string { return e.Detail }
func (e *Error) Unwrap() error { return e.Kind }

// LimitError distinguishes exhausted resource budgets from syntax failures.
// A caller must not treat a limit as proof of an empty or malformed dictionary.
type LimitError struct{ error }

func (e *LimitError) Unwrap() error { return e.error }

func malformed(format string, args ...any) error {
	return &Error{ErrFormat, fmt.Sprintf(format, args...)}
}
func unsupported(reason string) error { return &Error{ErrUnsupported, reason} }
func plistLimit(reason string) error  { return &LimitError{malformed("bundle plist %s limit", reason)} }
func plistRestriction(native bool, reason string) error {
	if native {
		return unsupported(reason)
	}
	return malformed("%s", reason)
}

// Unmarshal retains the existing generic codec contract for consumers which
// already validate their own document size and value schema. Unlike Decode and
// DecodeDictionary, it does not impose this package's bounded native profile.
// It is kept separate so extraction does not change entitlement or CMS behavior.
func Unmarshal(data []byte, value any) (int, error) { return codec.Unmarshal(data, value) }
