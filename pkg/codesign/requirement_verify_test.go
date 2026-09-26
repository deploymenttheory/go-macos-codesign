package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRequirementVerificationPolicy(t *testing.T) {
	ctx := context.Background()
	for _, algorithm := range []string{"adhoc", "rsa", "p256", "p384", "p521"} {
		t.Run(algorithm, func(t *testing.T) {
			var id *Identity
			opts := VerifyOptions{}
			if algorithm != "adhoc" {
				id = testIdentity(t, algorithm)
				opts.TrustedCertificates = id.Certificates
			}
			signed, err := SignBytes(ctx, fixture(t, "unsigned-universal"), SignOptions{Identifier: "test", Identity: id, Requirements: mustRequirements(t, "host => never designated => never")})
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(signed)
			report, err := VerifyBytes(ctx, signed, opts)
			if err != nil || !report.Valid {
				t.Fatal("ordinary verification", err)
			}
			if err := report.CheckDesignatedRequirement(""); !errors.Is(err, ErrDesignatedRequirement) {
				t.Fatal("explicit self check", err)
			}
			for _, source := range []string{"always", `identifier "test"`} {
				if err := report.CheckRequirement(source, ""); err != nil {
					t.Fatal(err)
				}
			}
			if id != nil {
				if _, err := VerifyBytes(ctx, signed, VerifyOptions{}); !errors.Is(err, ErrUntrusted) {
					t.Fatal("trust bypass", err)
				}
				if err := report.CheckRequirement(`certificate leaf[subject.CN] = "Public codesign test identity `+algorithm+`"`, ""); err != nil {
					t.Fatal("verified certificate context", err)
				}
			}
			if err := report.CheckRequirement("never", ""); !errors.Is(err, ErrRequirement) {
				t.Fatal(err)
			}
			if !report.Valid {
				t.Fatal("separate check mutated verification result")
			}
			opts.CheckDesignatedRequirement = true
			rejected, err := VerifyBytes(ctx, signed, opts)
			if !errors.Is(err, ErrDesignatedRequirement) || rejected.Valid {
				t.Fatal("opt-in self policy", err)
			}
			opts.CheckDesignatedRequirement = false
			opts.Requirement = "never"
			rejected, err = VerifyBytes(ctx, signed, opts)
			if !errors.Is(err, ErrRequirement) || rejected.Valid {
				t.Fatal("caller requirement bypass", err)
			}
			if !bytes.Equal(before, signed) {
				t.Fatal("verification changed input")
			}
		})
	}
	for _, r := range []*Report{nil, {}, {Valid: true}} {
		if err := r.CheckDesignatedRequirement(""); !errors.Is(err, ErrInvalid) {
			t.Fatal("unverified report accepted", err)
		}
	}
	inspected, err := InspectBytes(fixture(t, "adhoc-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	if err := inspected.CheckRequirement("always", ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("inspection accepted", err)
	}
	r, err := VerifyBytes(ctx, fixture(t, "adhoc-universal"), VerifyOptions{Architecture: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"", "arm64"} {
		if err := r.CheckRequirement("always", arch); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"x86_64", "missing"} {
		if err := r.CheckDesignatedRequirement(arch); err == nil {
			t.Fatal("unverified/absent architecture accepted")
		}
	}
	if err := r.CheckRequirement("unknown", ""); err == nil {
		t.Fatal("unsupported predicate accepted")
	}
	// Binding and structural validation still precede any optional self check.
	req := mustRequirements(t, "designated => never")
	signed, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), SignOptions{Identifier: "test", Requirements: req})
	if err != nil {
		t.Fatal(err)
	}
	r, err = InspectBytes(signed)
	if err != nil {
		t.Fatal(err)
	}
	a := r.Architectures[0]
	set := a.Signature.find(SlotRequirements)
	off := bytes.Index(signed, set)
	malformed := bytes.Clone(signed)
	be.PutUint32(malformed[off+16:], 1)
	// First reject a changed component hash, then the same malformed structure
	// rebound into an ad-hoc CodeDirectory (no CMS or key-policy bypass involved).
	for _, rebind := range []bool{false, true} {
		if rebind {
			d := a.Signature.Directories[0]
			start := bytes.Index(malformed, d.Raw)
			sum := sha256.Sum256(malformed[off : off+len(set)])
			copy(malformed[start+int(d.HashOffset)-2*int(d.HashSize):], sum[:])
		}
		if _, err := VerifyBytes(ctx, malformed, VerifyOptions{}); err == nil {
			t.Fatal("malformed component accepted", rebind)
		}
	}
}

func TestRequirementVerificationAST(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-requirement-verification.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Driver  string `json:"driver_sha256"`
		Targets map[string]map[string]struct {
			Kinds map[string]int `json:"ast_kinds"`
			Refs  map[string]int `json:"references"`
		}
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	driver, err := os.ReadFile("../../scripts/extract-requirement-verification.go")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(driver)) != manifest.Driver || len(manifest.Targets) != 2 {
		t.Fatal("stale/incomplete AST")
	}
	for _, functions := range manifest.Targets {
		if len(functions) != 6 {
			t.Fatal("incomplete body count")
		}
		for name, f := range functions {
			if f.Kinds["CompoundStmt"] == 0 {
				t.Fatal("declaration-only body", name)
			}
			if strings.Contains(name, "staticValidateCore") && (f.Refs["validateRequirement"] != 1 || f.Refs["validateNonResourceComponents"] != 1 || f.Refs["designatedRequirement"] != 0) {
				t.Fatal("verification ordering", f)
			}
		}
	}
}
