package codesign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRequirementSetsNativeReference(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-requirement-sets.json")
	if err != nil {
		t.Fatal(err)
	}
	var evidence struct {
		Driver  string `json:"driver_sha256"`
		Targets map[string]map[string]any
		Native  struct {
			Cases map[string]struct {
				Source string
				Exit   int
				Hex    string `json:"compiled_hex"`
				Hash   string `json:"compiled_sha256"`
			}
		}
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	driver, err := os.ReadFile("../../scripts/extract-requirement-sets.go")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(driver)) != evidence.Driver {
		t.Fatal("research driver changed without refreshed evidence")
	}
	if len(evidence.Targets) != 2 || len(evidence.Native.Cases) != 33 {
		t.Fatal("incomplete native/AST evidence")
	}
	for _, functions := range evidence.Targets {
		if len(functions) != 6 {
			t.Fatal("incomplete Apple function AST")
		}
	}
	for name, record := range evidence.Native.Cases {
		t.Run(name, func(t *testing.T) {
			got, err := CompileRequirements(record.Source)
			if record.Exit != 0 {
				if err == nil {
					t.Fatal("native rejection accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(record.Hex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) || fmt.Sprintf("%x", sha256.Sum256(got)) != record.Hash {
				t.Fatalf("native requirement bytes differ: %x != %x", got, want)
			}
			if err := validateRequirements(got); err != nil {
				t.Fatal(err)
			}
			viaText, err := RequirementsBytes([]byte(record.Source))
			if err != nil || !bytes.Equal(viaText, want) {
				t.Fatal("text input", err)
			}
			owned, err := RequirementsBytes(got)
			if err != nil || !bytes.Equal(owned, want) {
				t.Fatal("binary input", err)
			}
			owned[len(owned)-1] ^= 1
			if !bytes.Equal(got, want) {
				t.Fatal("binary input aliased")
			}
		})
	}
}

func TestRequirementSetLimits(t *testing.T) {
	for _, source := range []string{
		strings.Repeat(" ", 1<<20+1), strings.Repeat("host => always ", 65),
		"4294967296 => always", "9223372036854775808 => always", "1_0 => always", "0b11 => always", "0o3 => always", "0X3 => always",
		"host => " + strings.Repeat("!", 130) + "always", "host => " + strings.Repeat("always or ", 4097) + "always",
		"host => always designated => identifier \"bad\\q\"", "host => always designated => identifier \"unterminated",
		"host => always /* missing", "host => certificate leaf[field.1.2.3] nonsense",
		"host => always unknown => never", "host => always 4294967296 => never",
	} {
		if _, err := CompileRequirements(source); err == nil {
			t.Fatalf("accepted %.100q", source)
		}
	}
	for _, source := range []string{strings.Repeat("host => always ", 64), "host => certificate 09[field.1.2.3] designated => always", "always; # bare expression extension", "# comment\nalways;", "host => always # one\n# two\ndesignated => always"} {
		if _, err := CompileRequirements(source); err != nil {
			t.Fatalf("rejected %q: %v", source, err)
		}
	}
	// A standalone requirement must still reject a second named expression.
	if _, err := CompileRequirement("certificate leaf[field.1.2.3] host => always"); err == nil {
		t.Fatal("standalone parser accepted a set")
	}
	// Entry boundaries reset the expression budget, without bypassing the set cap.
	if _, err := CompileRequirements("host => " + strings.Repeat("always and ", 2500) + "always guest => " + strings.Repeat("always or ", 2500) + "always"); err != nil {
		t.Fatal(err)
	}
}
