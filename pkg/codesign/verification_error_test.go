package codesign

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestVerificationErrorContext(t *testing.T) {
	ctx := context.Background()
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		data := fixture(t, "unsigned-"+arch)
		want := arch
		if arch == "universal" {
			want = "arm64"
		}
		r, err := VerifyBytes(ctx, data, VerifyOptions{})
		var detail *VerificationError
		if r == nil || r.Valid || !errors.Is(err, ErrUnsigned) || !errors.As(err, &detail) || detail.Architecture != want || detail.Error() != ErrUnsigned.Error() {
			t.Fatalf("%s: %#v %v", arch, detail, err)
		}
		signed, err := SignBytes(ctx, data, SignOptions{Identifier: "test"})
		if err != nil {
			t.Fatal(err)
		}
		r, err = InspectBytes(signed)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range r.Architectures {
			signed[a.Offset+4096] ^= 1
		}
		r, err = VerifyBytes(ctx, signed, VerifyOptions{})
		if r.Valid || !errors.Is(err, ErrInvalid) || !errors.As(err, &detail) || detail.Architecture != want || !strings.Contains(detail.Error(), "code page") {
			t.Fatal(detail, err)
		}
		if arch == "universal" && r.Architectures[0].Name != "x86_64" {
			t.Fatal("report reordered")
		}
		_, err = VerifyBytes(ctx, signed, VerifyOptions{Architecture: "absent"})
		if !errors.As(err, &detail) || detail.Architecture != "" || !strings.Contains(detail.Error(), "not present") {
			t.Fatal(detail, err)
		}
	}
}

func TestVerificationErrorPolicies(t *testing.T) {
	ctx := context.Background()
	for _, slot := range []uint32{SlotInfo, SlotResources} {
		opts := SignOptions{Identifier: "test"}
		if slot == SlotInfo {
			opts.InfoPlist = []byte("original")
		} else {
			opts.Resources = []byte("original")
		}
		data, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, missing := range []bool{true, false} {
			verify := VerifyOptions{}
			want := ErrUnsupported
			if !missing {
				want = ErrInvalid
				if slot == SlotInfo {
					verify.InfoPlist = []byte("changed")
				} else {
					verify.Resources = []byte("changed")
				}
			}
			_, err = VerifyBytes(ctx, data, verify)
			var detail *VerificationError
			if !errors.Is(err, want) || !errors.As(err, &detail) || (detail.Architecture == "") != (slot == SlotResources) {
				t.Fatal(slot, missing, detail, err)
			}
		}
	}
	base := verificationArchitecture(verificationFailure(signatureDiagnostic, invalid("code page")), "x86_64")
	child := nestedVerificationError("child", base)
	outer := nestedVerificationError("outer", child)
	var detail *VerificationError
	if !errors.As(outer, &detail) || detail.Subcomponent != "child" || detail.Architecture != "x86_64" || !errors.Is(outer, ErrInvalid) {
		t.Fatal(detail, outer)
	}
	if !errors.As(base, &detail) || detail.Subcomponent != "" {
		t.Fatal("mutated original context")
	}
	sealed := nestedVerificationError("child", ErrRequirement)
	if !errors.Is(sealed, ErrInvalid) || errors.Is(sealed, ErrRequirement) || !errors.As(sealed, &detail) || len(detail.ModifiedResources) != 1 || detail.Architecture != "" {
		t.Fatal(detail, sealed)
	}
	plain := fmt.Errorf("policy: %w", ErrUntrusted)
	if !errors.Is(verificationArchitecture(plain, "arm64"), plain) || !errors.Is(nestedVerificationError("child", plain), ErrUntrusted) {
		t.Fatal("policy replaced")
	}
	if !errors.Is(verificationArchitecture(base, "dmg"), base) {
		t.Fatal("DMG architecture introduced")
	}
	if len((&Report{}).verificationArchitectures()) != 0 {
		t.Fatal("empty selection")
	}
}
