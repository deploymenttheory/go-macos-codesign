package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDefaultRequirementMerging(t *testing.T) {
	id := testIdentity(t, "rsa")
	chain, err := linkedCertificates(id.Certificates[0], id.Certificates)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"", "host => never", "host => never guest => never library => never plugin => never", "host => never designated => always", "designated => never"} {
		for _, withCertificate := range []bool{false, true} {
			opts := SignOptions{Identifier: "test"}
			if source != "" {
				opts.Requirements, err = CompileRequirements(source)
				if err != nil {
					t.Fatal(err)
				}
			}
			original := bytes.Clone(opts.Requirements)
			provided := opts.Requirements
			var path []*certificate
			if withCertificate {
				path = chain
			}
			if err := prepareRequirements(&opts, path); err != nil {
				t.Fatal(err)
			}
			text, designated, err := requirementSetText(opts.Requirements)
			if err != nil || designated != (withCertificate || strings.Contains(source, "designated")) {
				t.Fatal(text, err)
			}
			if !bytes.Equal(provided, original) {
				t.Fatal("input changed")
			}
			if strings.Contains(source, "designated => never") && !strings.Contains(text, "designated => never") {
				t.Fatal("explicit false expression replaced")
			}
			if source == "" && !withCertificate && len(opts.Requirements) != 12 {
				t.Fatal("ad-hoc default invented")
			}
			first := bytes.Clone(opts.Requirements)
			if err := prepareRequirements(&opts, path); err != nil || !bytes.Equal(first, opts.Requirements) {
				t.Fatal("merge is not idempotent", err)
			}
			opts.Requirements[0] = 0
			if !bytes.Equal(provided, original) {
				t.Fatal("output aliases caller")
			}
		}
	}
	// Repack both the index and payload order, dropping unused padding without
	// re-encoding any expression. Caller input and backing capacity stay untouched.
	canonical := mustRequirements(t, "host => never designated => always plugin => never")
	unordered := append(bytes.Clone(canonical), bytes.Repeat([]byte{0x7f}, 16)...)
	be.PutUint32(unordered[4:], uint32(len(unordered)))
	first := bytes.Clone(unordered[12:20])
	copy(unordered[12:20], unordered[28:36])
	copy(unordered[28:36], first)
	before := bytes.Clone(unordered)
	opts := SignOptions{Identifier: "test", Requirements: unordered}
	if err := prepareRequirements(&opts, chain); err != nil || !bytes.Equal(opts.Requirements, canonical) || !bytes.Equal(before, unordered) {
		t.Fatal("canonicalization/ownership", err)
	}
	opts.Requirements[0] = 0
	if !bytes.Equal(before, unordered) {
		t.Fatal("aliased input")
	}
}

func TestRequirementDefaultAST(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-requirement-defaults.json")
	if err != nil {
		t.Fatal(err)
	}
	var evidence struct {
		Driver  string `json:"driver_sha256"`
		Targets map[string]map[string]struct {
			Kinds map[string]int `json:"ast_kinds"`
			Refs  map[string]int `json:"references"`
		}
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	driver, err := os.ReadFile("../../scripts/extract-requirement-defaults.go")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(driver)) != evidence.Driver || len(evidence.Targets) != 2 {
		t.Fatal("stale or incomplete AST evidence")
	}
	for _, functions := range evidence.Targets {
		if len(functions) != 6 {
			t.Fatal("incomplete function bodies")
		}
		for name, f := range functions {
			if f.Kinds["CompoundStmt"] == 0 {
				t.Fatal("declaration-only evidence", name)
			}
			if strings.Contains(name, "InternalRequirements") && (f.Refs["contains"] != 1 || f.Refs["add"] != 3) {
				t.Fatal("missing explicit/default ordering", f)
			}
		}
	}
}

func mustRequirements(t *testing.T, source string) []byte {
	t.Helper()
	b, err := CompileRequirements(source)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDefaultRequirementLimitsAndErrors(t *testing.T) {
	id := testIdentity(t, "rsa")
	chain, err := linkedCertificates(id.Certificates[0], id.Certificates)
	if err != nil {
		t.Fatal(err)
	}
	child, err := CompileRequirement("always")
	if err != nil {
		t.Fatal(err)
	}
	var entries []Blob
	for i := uint32(100); i < 164; i++ {
		entries = append(entries, Blob{Slot: i, Data: child})
	}
	maximum := superblob(MagicRequirements, entries)
	hugeChild := blob(MagicRequirement, (&requirementNode{op: 2, value: strings.Repeat("x", (1<<20)-40)}).encode(append32(nil, 1)))
	huge := superblob(MagicRequirements, []Blob{{Slot: 1, Data: hugeChild}})
	if len(huge) != 1<<20 {
		t.Fatal("incorrect boundary fixture", len(huge))
	}
	for _, data := range [][]byte{[]byte("bad"), append(bytes.Clone(maximum), 0), superblob(MagicRequirements, append(entries, Blob{Slot: 164, Data: child})), make([]byte, (1<<20)+1), maximum, huge} {
		before := bytes.Clone(data)
		opts := SignOptions{Identifier: "test", Requirements: data}
		if err := prepareRequirements(&opts, chain); err == nil {
			t.Fatal("invalid or oversized merge accepted")
		}
		if !bytes.Equal(data, before) || !bytes.Equal(opts.Requirements, before) {
			t.Fatal("failed merge mutated input")
		}
	}
	for _, data := range [][]byte{maximum, huge} {
		opts := SignOptions{Requirements: data}
		if err := prepareRequirements(&opts, nil); err != nil {
			t.Fatal("exact ad-hoc boundary", err)
		}
	}
	opts := SignOptions{Identifier: "test", Requirements: superblob(MagicRequirements, entries[:63])}
	if err := prepareRequirements(&opts, chain); err != nil || be.Uint32(opts.Requirements[8:]) != 64 {
		t.Fatal("exact merged boundary", err)
	}
	// Default generation is lazy. A malformed subject cannot silently suppress
	// an error, but an explicit designated requirement needs no default builder.
	bad := *chain[0]
	bad.tbs.Subject = asn1.RawValue{FullBytes: []byte{1}}
	opts = SignOptions{Identifier: "test"}
	if err := prepareRequirements(&opts, []*certificate{&bad}); err == nil {
		t.Fatal("default builder failure ignored")
	}
	opts.Requirements = mustRequirements(t, "designated => always")
	if err := prepareRequirements(&opts, []*certificate{&bad}); err != nil {
		t.Fatal("unneeded default builder invoked", err)
	}
	// SignBytes prepares all architectures before returning any result.
	input := fixture(t, "unsigned-universal")
	before := bytes.Clone(input)
	for _, identity := range []*Identity{nil, id} {
		out, err := SignBytes(context.Background(), input, SignOptions{Identifier: "test", Identity: identity, Requirements: []byte("bad")})
		if err == nil || out != nil || !bytes.Equal(before, input) {
			t.Fatal("signing failure ownership", err)
		}
	}
	if !errors.Is(prepareRequirements(&SignOptions{Requirements: make([]byte, (1<<20)+1)}, nil), ErrUnsupported) {
		t.Fatal("limit classification")
	}
}
