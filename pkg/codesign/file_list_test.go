package codesign

import (
	"errors"
	"testing"
)

func TestSignatureFileSelectionErrors(t *testing.T) {
	if _, err := (&Report{}).SignatureFiles(""); err == nil {
		t.Fatal("empty report accepted")
	}
	r := &Report{Architectures: []Architecture{{Name: "x86_64"}, {Name: "arm64", Signature: &Signature{}}}}
	if _, err := r.SignatureFiles("x86_64"); !errors.Is(err, ErrUnsigned) {
		t.Fatal(err)
	}
	if _, err := r.SignatureFiles(""); !errors.Is(err, ErrUnsupported) {
		t.Fatal("byte-only report accepted", err)
	}
	if _, err := r.SignatureFiles("absent"); err == nil {
		t.Fatal("absent architecture accepted")
	}
}
