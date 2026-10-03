package codesign

import (
	"errors"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/plist"
)

func TestPlistErrorNamespace(t *testing.T) {
	// Parser classification remains available without changing the public
	// codesign errors or diagnostic prefix used by CLI exit/status handling.
	for _, tc := range []struct {
		name            string
		data            []byte
		strict          bool
		kind, errorKind error
	}{
		{"strict-format", []byte("<plist><dict>"), true, ErrFormat, plist.ErrFormat},
		{"unsupported", []byte(`<?xml version="1.0" encoding="Shift_JIS"?><dict/>`), false, ErrUnsupported, plist.ErrUnsupported},
		{"limit", []byte(strings.Repeat(" ", maxBundlePlist+1)), false, ErrFormat, plist.ErrFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.strict {
				_, err = decodeBundlePlist(tc.data)
			} else {
				_, err = decodeRemovalPlist(tc.data)
			}
			var detail *plist.Error
			if !errors.Is(err, tc.kind) || !errors.Is(err, tc.errorKind) || !errors.As(err, &detail) {
				t.Fatal("lost error classification", err)
			}
			if err.Error() != tc.kind.Error()+": "+detail.Error() {
				t.Fatal("changed public diagnostic", err)
			}
			var limit *plist.LimitError
			if errors.As(err, &limit) != (tc.name == "limit") {
				t.Fatal("lost limit classification", err)
			}
		})
	}
	// A syntax failure is an operation-specific fallback; the generic parser
	// still reports it to other consumers.
	input := []byte("<dict>")
	if _, err := plist.Decode(input); !errors.Is(err, plist.ErrFormat) {
		t.Fatal(err)
	}
	if value, err := decodeRemovalPlist(input); err != nil || value != nil {
		t.Fatal(value, err)
	}
}
