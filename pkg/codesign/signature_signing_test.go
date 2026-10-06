package codesign

import (
	"bytes"
	"testing"
)

func TestSigningSignatureViewParity(t *testing.T) {
	for _, name := range []string{"unsigned-arm64", "unsigned-universal", "adhoc-arm64", "runtime-universal", "entitlements-x86_64"} {
		t.Run(name, func(t *testing.T) {
			data := fixture(t, name)
			ctx, _, _ := signatureTestStorage(t, transferBufferSize)
			source := codeSource{ctx, byteOutput(data)}
			c, err := source.container()
			if err != nil {
				t.Fatal(err)
			}
			states, err := source.signingSignatures(c)
			if err != nil {
				t.Fatal(err)
			}
			report, err := InspectBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			for i, a := range report.Architectures {
				if states[i].present != (a.Signature != nil) || a.Signature != nil && states[i].flags != a.Signature.Directories[0].Flags {
					t.Fatal(states[i], a)
				}
			}
			if len(c.slices) > 1 && states[0].present {
				last := c.slices[len(c.slices)-1]
				data[last.offset+uint64(last.image.sigOffset)] = 0
				if states, err = source.signingSignatures(c); err == nil || states != nil {
					t.Fatal("later malformed architecture admitted partial notices", states, err)
				}
			}
		})
	}
	// The first indexed directory determines the notice, even when the primary
	// slot appears later. Sorting slots inside the view would change admission.
	parsed, err := ParseSignature(signatureFixtureBytes(t, "adhoc-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	alternate := bytes.Clone(parsed.find(0))
	be.PutUint32(alternate[12:], 0x20000)
	sig := superblob(MagicSignature, []Blob{{Slot: 0, Data: parsed.find(0)}, {Slot: 0x1000, Data: alternate}})
	first := bytes.Clone(sig[12:20])
	copy(sig[12:20], sig[20:28])
	copy(sig[20:28], first)
	ctx, _, _ := signatureTestStorage(t, transferBufferSize)
	c := &container{slices: []slice{{image: &image{sigCommand: 0, sigSize: uint32(len(sig))}}}}
	state, err := (codeSource{ctx, byteOutput(sig)}).signingSignatures(c)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ParseSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	if state[0].flags != 0x20000 || state[0].flags != expected.Directories[0].Flags {
		t.Fatal(state, expected)
	}
}

func TestDMGSigningSignatureViewParity(t *testing.T) {
	unsigned := testDMG(t)
	signed, err := SignBytes(t.Context(), unsigned, SignOptions{Identifier: "signature-view"})
	if err != nil {
		t.Fatal(err)
	}
	// A native-style dry-run SuperBlob has components but no CodeDirectory.
	m, err := parseDMG(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	drySignature := superblob(MagicSignature, []Blob{{Slot: SlotRequirements, Data: superblob(MagicRequirements, nil)}})
	m.footer.CodeSignatureLength = uint64(len(drySignature))
	dry := append(bytes.Clone(unsigned[:len(unsigned)-dmgFooterSize]), drySignature...)
	dry = append(dry, m.trailer()...)
	for _, data := range [][]byte{unsigned, signed, dry} {
		ctx, _, _ := signatureTestStorage(t, transferBufferSize)
		got, err := parseDMGSigningSource(codeSource{ctx, byteOutput(data)}, data[len(data)-dmgFooterSize:])
		if err != nil {
			t.Fatal(err)
		}
		want, err := parseDMG(data)
		if err != nil {
			t.Fatal(err)
		}
		if got.footer != want.footer || got.signed != (want.signature != nil) || got.signature != nil {
			t.Fatal("DMG borrowed state drift", got, want)
		}
		if want.signature != nil && got.priorFlags != want.signature.Directories[0].Flags {
			t.Fatal(got, want)
		}
	}
	bad := bytes.Clone(signed)
	m, err = parseDMG(signed)
	if err != nil {
		t.Fatal(err)
	}
	bad[m.footer.CodeSignatureOffset] = 0
	ctx, _, _ := signatureTestStorage(t, transferBufferSize)
	if _, err := parseDMGSigningSource(codeSource{ctx, byteOutput(bad)}, bad[len(bad)-dmgFooterSize:]); err == nil {
		t.Fatal("malformed DMG signature accepted")
	}
	if _, err := parseDMGSigningSource(codeSource{ctx, byteOutput(unsigned[:8])}, unsigned[len(unsigned)-dmgFooterSize:]); err == nil || err.Error() != malformed("UDIF image size or trailer").Error() {
		t.Fatal("short DMG source", err)
	}
	// The SuperBlob must fill the complete extent declared by the footer.
	m.footer.CodeSignatureLength = uint64(len(signed)-dmgFooterSize) - m.footer.CodeSignatureOffset + 1
	padded := append(bytes.Clone(signed[:len(signed)-dmgFooterSize]), 0)
	padded = append(padded, m.trailer()...)
	if _, err := parseDMGSigningSource(codeSource{ctx, byteOutput(padded)}, padded[len(padded)-dmgFooterSize:]); err == nil || err.Error() != malformed("UDIF signature padding").Error() {
		t.Fatal("padded DMG signature", err)
	}
}
