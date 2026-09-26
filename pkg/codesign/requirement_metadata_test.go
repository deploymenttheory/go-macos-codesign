package codesign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func requirementReport(t *testing.T, requirements []byte) *Report {
	t.Helper()
	data, e := SignBytes(context.Background(), fixture(t, "unsigned-universal"), SignOptions{Identifier: "test", Requirements: requirements})
	if e != nil {
		t.Fatal(e)
	}
	r, e := InspectBytes(data)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestRequirementMetadata(t *testing.T) {
	req, _ := CompileRequirements(`always and ! never`)
	r := requirementReport(t, req)
	text, e := r.RequirementText("")
	if e != nil || string(text) != "designated => always and ! never\n" || r.Valid {
		t.Fatal(string(text), e)
	}
	text[0] = 0
	again, e := r.RequirementText("")
	if e != nil || again[0] != 'd' {
		t.Fatal("unowned result", e)
	}
	empty := superblob(MagicRequirements, nil)
	r = requirementReport(t, empty)
	text, e = r.RequirementText("")
	if e != nil || strings.Count(string(text), "cdhash") != 2 || !strings.HasPrefix(string(text), "# designated => ") {
		t.Fatal(string(text), e)
	}
	text, e = r.RequirementText("x86_64")
	if e != nil || strings.Count(string(text), "cdhash") != 1 {
		t.Fatal(string(text), e)
	}
	if _, e = r.RequirementText("missing"); e == nil {
		t.Fatal("missing architecture")
	}
	if (Directory{}).specialSlotHash(0) != nil {
		t.Fatal("slot zero")
	}
	child, _ := CompileRequirement("always")
	set := superblob(MagicRequirements, []Blob{{Slot: 1, Data: child}, {Slot: 2, Data: child}})
	text, e = requirementReport(t, set).RequirementText("")
	if e != nil || !bytes.HasPrefix(text, []byte("host => always\nguest => always\n# designated => ")) {
		t.Fatal(string(text), e)
	}
}

func TestRequirementMetadataErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Report)
		want   error
	}{
		{"unsigned", func(r *Report) { r.Architectures[1].Signature = nil }, ErrUnsigned},
		{"alternate", func(r *Report) {
			s := r.Architectures[1].Signature
			s.Directories = append(s.Directories, s.Directories[0])
		}, ErrUnsupported},
		{"directory", func(r *Report) { r.Architectures[1].Signature.find(SlotDirectory)[0] = 0 }, ErrFormat},
		{"other-unsigned", func(r *Report) { r.Architectures[0].Signature = nil }, ErrUnsigned},
		{"hash", func(r *Report) {
			s := r.Architectures[1].Signature
			d := s.find(SlotDirectory)
			d[be.Uint32(d[16:])-64] ^= 1
		}, ErrInvalid},
		{"missing", func(r *Report) {
			s := r.Architectures[1].Signature
			for i := range s.Blobs {
				if s.Blobs[i].Slot == SlotRequirements {
					s.Blobs[i].Slot = 99
				}
			}
		}, ErrInvalid},
		{"no-certificate", func(r *Report) { s := r.Architectures[1].Signature; be.PutUint32(s.find(SlotDirectory)[12:], 0) }, ErrUnsupported},
		{"bad-cms", func(r *Report) {
			s := r.Architectures[1].Signature
			be.PutUint32(s.find(SlotDirectory)[12:], 0)
			for i := range s.Blobs {
				if s.Blobs[i].Slot == SlotCMS {
					s.Blobs[i].Data = make([]byte, 10)
				}
			}
		}, ErrFormat},
		{"bad-set", func(r *Report) {
			s := r.Architectures[1].Signature
			data := s.find(SlotRequirements)
			data[8] = 1
			sum, _ := digest(2, data)
			d := s.find(SlotDirectory)
			copy(d[be.Uint32(d[16:])-64:], sum)
		}, ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := requirementReport(t, superblob(MagicRequirements, nil))
			tc.change(r)
			if _, e := r.RequirementText(""); !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
		})
	}
	if _, e := requirementDirectory(nil); !errors.Is(e, ErrUnsigned) {
		t.Fatal(e)
	}
	if _, _, e := requirementSetText(make([]byte, (1<<20)+1)); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	if _, _, e := requirementSetText([]byte("bad")); !errors.Is(e, ErrFormat) {
		t.Fatal(e)
	}
	child, _ := CompileRequirement("always")
	set := superblob(MagicRequirements, []Blob{{Slot: 1, Data: child}, {Slot: 3, Data: child}})
	be.PutUint32(set[24:], be.Uint32(set[16:]))
	if _, _, e := requirementSetText(set); !errors.Is(e, ErrFormat) {
		t.Fatal("overlapping children accepted", e)
	}
}

func TestRequirementExtractionAST(t *testing.T) {
	data, e := os.ReadFile("../../spec/apple-requirement-extraction.json")
	if e != nil {
		t.Fatal(e)
	}
	var record struct {
		Excerpts map[string]string `json:"excerpt_sha256"`
		Targets  map[string]map[string]struct {
			Kinds map[string]int `json:"ast_kinds"`
			Refs  map[string]int `json:"references"`
		} `json:"targets"`
	}
	if e = json.Unmarshal(data, &record); e != nil {
		t.Fatal(e)
	}
	if len(record.Targets) != 2 || len(record.Excerpts) != 6 {
		t.Fatal("missing AST targets/bodies")
	}
	for target, functions := range record.Targets {
		if len(functions) != 6 {
			t.Fatal(target)
		}
		for name, f := range functions {
			if f.Kinds["CompoundStmt"] == 0 {
				t.Fatal("declaration only", name)
			}
			if strings.Contains(name, "defaultDesignatedRequirement") {
				if f.Kinds["BlockExpr"] != 1 || f.Refs["cdHashes"] != 2 || f.Refs["validateDirectory"] != 1 {
					t.Fatal("incomplete default body", f)
				}
			}
		}
	}
}

func FuzzRequirementSet(f *testing.F) {
	pem, err := os.ReadFile("../../testdata/identities/rsa-identity.pem")
	if err != nil {
		f.Fatal(err)
	}
	id, err := LoadIdentityPEM(pem, nil)
	if err != nil {
		f.Fatal(err)
	}
	chain, err := linkedCertificates(id.Certificates[0], id.Certificates)
	if err != nil {
		f.Fatal(err)
	}
	child, _ := CompileRequirement(`identifier "test" and ! never`)
	for _, data := range [][]byte{nil, superblob(MagicRequirements, nil), superblob(MagicRequirements, []Blob{{Slot: 3, Data: child}}), superblob(MagicRequirements, []Blob{{Slot: 1, Data: child}, {Slot: 3, Data: child}}), []byte("bad")} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		before := bytes.Clone(data)
		for _, path := range [][]*certificate{nil, chain} {
			opts := SignOptions{Identifier: "fuzz", Requirements: data}
			if err := prepareRequirements(&opts, path); err == nil {
				first := bytes.Clone(opts.Requirements)
				if err := prepareRequirements(&opts, path); err != nil || !bytes.Equal(first, opts.Requirements) {
					t.Fatal("unstable default merge", err)
				}
			}
			if !bytes.Equal(before, data) {
				t.Fatal("merge mutated input")
			}
		}
		text, designated, e := requirementSetText(data)
		if !bytes.Equal(data, before) {
			t.Fatal("input mutated")
		}
		if e == nil {
			again, d, e2 := requirementSetText(data)
			if e2 != nil || text != again || d != designated {
				t.Fatal("unstable extraction")
			}
		}
	})
}
