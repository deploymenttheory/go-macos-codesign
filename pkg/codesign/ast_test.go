package codesign

import (
	"encoding/json"
	"os"
	"testing"
)

// This checks the independent Clang extraction, not a Go-generated expectation.
func TestConstantsMatchAppleAST(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-sdk.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		Targets map[string]struct{ Enums map[string]uint32 }
	}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	if len(facts.Targets) != 2 {
		t.Fatal("both target ASTs are required")
	}
	for target, values := range facts.Targets {
		for name, got := range map[string]uint32{
			"CSMAGIC_CODEDIRECTORY":             MagicDirectory,
			"CSMAGIC_EMBEDDED_SIGNATURE":        MagicSignature,
			"CSMAGIC_REQUIREMENTS":              MagicRequirements,
			"CSMAGIC_REQUIREMENT":               MagicRequirement,
			"CSMAGIC_EMBEDDED_ENTITLEMENTS":     MagicEntitlements,
			"CSMAGIC_EMBEDDED_DER_ENTITLEMENTS": MagicDEREntitlements,
			"CSMAGIC_BLOBWRAPPER":               MagicCMS,
			"CSSLOT_CODEDIRECTORY":              SlotDirectory,
			"CSSLOT_INFOSLOT":                   SlotInfo,
			"CSSLOT_REQUIREMENTS":               SlotRequirements,
			"CSSLOT_RESOURCEDIR":                SlotResources,
			"CSSLOT_ENTITLEMENTS":               SlotEntitlements,
			"CSSLOT_DER_ENTITLEMENTS":           SlotDEREntitlements,
			"CSSLOT_SIGNATURESLOT":              SlotCMS,
		} {
			want, ok := values.Enums[name]
			if !ok || got != want {
				t.Errorf("%s %s: Go=%#x Clang=%#x present=%t", target, name, got, want, ok)
			}
		}
	}
}

func TestCMSAndCertificateRequirementAST(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-cms.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		Targets map[string]struct {
			CMS          map[string]int    `json:"cms_enums"`
			Requirements map[string]int    `json:"requirement_enums"`
			Functions    map[string]string `json:"cms_functions"`
		}
	}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	if len(facts.Targets) != 2 {
		t.Fatal("both target ASTs are required")
	}
	for target, values := range facts.Targets {
		for name, want := range map[string]int{"kCMSAttrSigningTime": 8, "kCMSAttrAppleCodesigningHashAgility": 16, "kCMSAttrAppleCodesigningHashAgilityV2": 32} {
			if values.CMS[name] != want {
				t.Errorf("%s %s: %d", target, name, values.CMS[name])
			}
		}
		if values.Functions["CMSEncoderSetHasDetachedContent"] == "" {
			t.Fatal("missing detached CMS declaration")
		}
		for expression, name := range map[string]string{`true`: "opTrue", `false`: "opFalse", `identifier "test"`: "opIdent", `certificate leaf = H"0000000000000000000000000000000000000000"`: "opAnchorHash"} {
			compiled, err := CompileRequirement(expression)
			if err != nil {
				t.Fatal(err)
			}
			want, present := values.Requirements[name]
			if !present || int(be.Uint32(compiled[12:])) != want {
				t.Errorf("%s %s differs from Clang", target, expression)
			}
		}
	}
}
