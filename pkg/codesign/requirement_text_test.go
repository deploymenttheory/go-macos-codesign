package codesign

import (
	"bytes"
	"strings"
	"testing"
)

func TestCanonicalRequirementText(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`true`, `always`}, {`false`, `never`},
		{`identifier "abc123"`, `identifier abc123`},
		{`identifier "true"`, `identifier "true"`},
		{`identifier "a.b"`, `identifier "a.b"`},
		{`identifier "1abc"`, `identifier "1abc"`},
		{`identifier "a\"b\\c"`, `identifier "a\"b\\c"`},
		{`identifier "é"`, `identifier 0xc3a9`},
		{`identifier "\x01"`, `identifier 0x01`},
		{`not (always or never)`, `! (always or never)`},
		{`always and (never or always)`, `always and (never or always)`},
		{`(always and never) or always`, `always and never or always`},
		{`anchor apple generic`, `anchor apple generic`},
		{`certificate leaf[subject.CN] = "Example"`, `certificate leaf[subject.CN] = Example`},
		{`certificate root[subject.O] = "Test CA"`, `certificate root[subject.O] = "Test CA"`},
		{`certificate 1[subject.OU] = "ABC"`, `certificate 1[subject.OU] = ABC`},
		{`certificate 1[field.1.2.840.113635.100.6.2.6] exists`, `certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */`},
		{`certificate 1[field.1.2.3] and always`, `certificate 1[field.1.2.3] /* exists */ and always`},
		{`certificate root = H"0000000000000000000000000000000000000000"`, `certificate root = H"0000000000000000000000000000000000000000"`},
		{`cdhash H"0000000000000000000000000000000000000000"`, `cdhash H"0000000000000000000000000000000000000000"`},
	} {
		t.Run(tc.input, func(t *testing.T) {
			encoded, err := CompileRequirement(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			n, err := decodeRequirement(encoded)
			if err != nil {
				t.Fatal(err)
			}
			text := n.text(3)
			if text != tc.want {
				t.Fatalf("%q != %q", text, tc.want)
			}
			again, err := CompileRequirement(text)
			if err != nil || !bytes.Equal(encoded, again) {
				t.Fatal("round trip", err)
			}
		})
	}
	for _, bad := range []string{`identifier 17`, `identifier 0xz1`, `identifier 0x1`, `identifier true`, `certificate leaf[subject.CN] = 1`, `certificate leaf[field.1.2.3] = abc`} {
		if _, err := CompileRequirement(bad); err == nil {
			t.Fatal("invalid syntax accepted", bad)
		}
	}
	// Literal newlines in native quoted text are deliberately outside the
	// parser subset; nested sealing must reject them before modifying files.
	reqs, err := CompileRequirements(`identifier "a\nb"`)
	if err != nil {
		t.Fatal(err)
	}
	data := signedNested(t, "arm64", SignOptions{Requirements: reqs})
	if _, err := nestedSeal(data); err == nil {
		t.Fatal("unsupported canonical text accepted")
	}
	for _, data := range [][]byte{nil, superblob(MagicRequirements, nil), []byte("bad")} {
		sig := &Signature{Blobs: []Blob{{Slot: SlotRequirements, Data: data}}}
		_, err := designatedRequirement(sig)
		if string(data) == "bad" && err == nil {
			t.Fatal("malformed requirements accepted")
		}
	}
}

func FuzzRequirementText(f *testing.F) {
	for _, s := range []string{"host => always; designated => never", "# comment\nhost => certificate leaf[field.1.2.3] guest => always", "4294967295 => always 08 => never host => always host => never"} {
		f.Add(s)
	}
	for _, s := range []string{`always`, `identifier helper`, `identifier 0xc3a9`, `certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and ! never`, `certificate root = H"0000000000000000000000000000000000000000"`, strings.Repeat("! ", 130) + "always"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<16 {
			return
		}
		if set, err := CompileRequirements(s); err == nil {
			// Compilation is deterministic even with duplicate labels and map
			// iteration. The binary decoder can have stricter depth limits.
			again, err := CompileRequirements(s)
			if err != nil || !bytes.Equal(set, again) {
				t.Fatal("unstable requirement set compilation")
			}
			_, _ = RequirementsBytes(set)
			_, _, _ = requirementSetText(set)
		}
		data, err := CompileRequirement(s)
		if err != nil {
			return
		}
		n, err := decodeRequirement(data)
		if err != nil {
			return
		} // decoder depth can be stricter
		canonical := n.text(3)
		again, err := CompileRequirement(canonical)
		if err != nil {
			return
		} // native literal whitespace subset
		other, err := decodeRequirement(again)
		if err != nil {
			t.Fatal(err)
		}
		// The native dumper flattens associative AND/OR nodes, so equivalent
		// trees need not encode identically; canonical text must be stable.
		if other.text(3) != canonical {
			t.Fatal("unstable canonical requirement")
		}
	})
}
