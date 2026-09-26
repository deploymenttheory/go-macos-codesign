package codesign

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestMalformedContainers(t *testing.T) {
	base := fixture(t, "adhoc-arm64")
	le := binary.LittleEndian
	for _, tc := range []struct {
		name string
		f    func([]byte) []byte
	}{
		{"short32", func(b []byte) []byte { return b[:27] }}, {"short64", func(b []byte) []byte { return b[:30] }}, {"magic", func(b []byte) []byte { b[0] = 0; return b }},
		{"commands bounds", func(b []byte) []byte { le.PutUint32(b[20:], 0xffffffff); return b }},
		{"commands count", func(b []byte) []byte { le.PutUint32(b[16:], 0xffffffff); return b }},
		{"command size", func(b []byte) []byte { le.PutUint32(b[36:], 4); return b }},
		{"command end", func(b []byte) []byte { le.PutUint32(b[20:], le.Uint32(b[20:])-4); return b }},
		{"segment short", func(b []byte) []byte { le.PutUint32(b[36:], 8); return b }},
		{"segment bounds", func(b []byte) []byte { le.PutUint64(b[104+48:], 0xffffffffffffffff); return b }},
		{"section overlap", func(b []byte) []byte { le.PutUint32(b[104+72+48:], 1); return b }},
		{"duplicate linkedit", func(b []byte) []byte { copy(b[40:], "__LINKEDIT\x00\x00\x00\x00\x00\x00"); return b }},
		{"bad signature command", func(b []byte) []byte { le.PutUint32(b[32:], 0x1d); return b }},
		{"bad signature range", func(b []byte) []byte { im, _ := parseImage(base); le.PutUint32(b[im.sigCommand+8:], 1); return b }},
		{"count mismatch", func(b []byte) []byte { le.PutUint32(b[16:], 0); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := InspectBytes(tc.f(bytes.Clone(base))); err == nil {
				t.Fatal("accepted malformed image")
			}
		})
	}
	fat := fixture(t, "adhoc-universal")
	for _, tc := range []struct {
		name string
		f    func([]byte) []byte
	}{
		{"shortfat", func(b []byte) []byte { return b[:7] }}, {"fat count", func(b []byte) []byte { be.PutUint32(b[4:], 0); return b }},
		{"fat alignment", func(b []byte) []byte { be.PutUint32(b[24:], 32); return b }},
		{"fat offset", func(b []byte) []byte { be.PutUint32(b[16:], 1); return b }},
		{"fat overlap", func(b []byte) []byte { be.PutUint32(b[36:], be.Uint32(b[16:])); return b }},
		{"fat cpu", func(b []byte) []byte { be.PutUint32(b[8:], 99); return b }},
		{"duplicate cpu", func(b []byte) []byte { copy(b[28:36], b[8:16]); return b }},
		{"bad fat image", func(b []byte) []byte { b[be.Uint32(b[16:])] = 0; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := InspectBytes(tc.f(bytes.Clone(fat))); err == nil {
				t.Fatal("accepted malformed universal image")
			}
		})
	}
	for _, order := range []binary.ByteOrder{be, binary.LittleEndian} {
		for _, fat64 := range []bool{false, true} {
			b := make([]byte, 16384+len(base))
			magic := uint32(0xcafebabe)
			if fat64 {
				magic = 0xcafebabf
			}
			order.PutUint32(b, magic)
			order.PutUint32(b[4:], 1)
			order.PutUint32(b[8:], 0x100000c)
			order.PutUint32(b[12:], 0)
			if fat64 {
				order.PutUint64(b[16:], 16384)
				order.PutUint64(b[24:], uint64(len(base)))
				order.PutUint32(b[32:], 14)
			} else {
				order.PutUint32(b[16:], 16384)
				order.PutUint32(b[20:], uint32(len(base)))
				order.PutUint32(b[24:], 14)
			}
			copy(b[16384:], base)
			if _, err := InspectBytes(b); err != nil {
				t.Fatal(err)
			}
			out, err := SignBytes(context.Background(), b, SignOptions{Identifier: "fat", Force: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyBytes(context.Background(), out, VerifyOptions{}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSigningPreconditions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := fixture(t, "unsigned-arm64")
	if _, err := SignBytes(ctx, b, SignOptions{Identifier: "x"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := RemoveSignatureBytes(ctx, b); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, o := range []SignOptions{{}, {Identifier: "x\x00y"}, {Identifier: "x", Identity: &Identity{}}, {Identifier: "x", Flags: 0xffffffff}, {Identifier: "x", PageSize: 3}, {Identifier: "x", Requirements: []byte("bad")}, {Identifier: "x", Entitlements: []byte("bad")}} {
		if _, err := SignBytes(context.Background(), b, o); err == nil {
			t.Fatal("invalid signing options accepted", o)
		}
	}
	badType := bytes.Clone(b)
	binary.LittleEndian.PutUint32(badType[12:], 1)
	if _, err := SignBytes(context.Background(), badType, SignOptions{Identifier: "x"}); err == nil {
		t.Fatal("object signed")
	}
	noLinkedit := bytes.Clone(b)
	im, _ := parseImage(noLinkedit)
	copy(noLinkedit[im.linkedit+8:], []byte("__OTHER___"))
	if _, err := SignBytes(context.Background(), noLinkedit, SignOptions{Identifier: "x"}); err == nil {
		t.Fatal("missing LINKEDIT accepted")
	}
	noSpace := bytes.Clone(b)
	pos := 32 + int(binary.LittleEndian.Uint32(b[20:]))
	noSpace[pos] = 1
	if _, err := SignBytes(context.Background(), noSpace, SignOptions{Identifier: "x"}); err == nil {
		t.Fatal("occupied load-command space overwritten")
	}
	trailing := append(fixture(t, "adhoc-arm64"), 0)
	if _, err := SignBytes(context.Background(), trailing, SignOptions{Identifier: "x", Force: true}); err == nil {
		t.Fatal("nonterminal signature overwritten")
	}
	if _, err := RemoveSignatureBytes(context.Background(), append(trailing, make([]byte, 7)...)); err == nil {
		t.Fatal("nonterminal signature removed")
	}
	for _, force := range []bool{false, true} {
		lib := bytes.Clone(b)
		binary.LittleEndian.PutUint32(lib[12:], 6)
		if _, err := SignBytes(context.Background(), lib, SignOptions{Identifier: "lib", Entitlements: []byte(`<plist version="1.0"><dict/></plist>`), ForceLibraryEntitlements: force}); err != nil {
			t.Fatal(err)
		}
	}
	minimal := syntheticMachO(be, true)
	if _, err := SignBytes(context.Background(), minimal, SignOptions{Identifier: "runtime", Flags: FlagRuntime}); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationFailures(t *testing.T) {
	b := fixture(t, "adhoc-arm64")
	r, err := InspectBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	a := r.Architectures[0]
	cd := int(a.SignatureOffset) + int(be.Uint32(b[int(a.SignatureOffset)+16:]))
	for _, tc := range []struct {
		name string
		f    func([]byte)
	}{
		{"code limit", func(b []byte) { be.PutUint32(b[cd+32:], 1) }},
		{"code slots", func(b []byte) { be.PutUint32(b[cd+28:], 1) }},
		{"external info", func(b []byte) { hashOff := int(be.Uint32(b[cd+16:])); b[cd+hashOff-32] = 1 }},
		{"special hash", func(b []byte) { hashOff := int(be.Uint32(b[cd+16:])); b[cd+hashOff-64] ^= 1 }},
		{"missing requirement", func(b []byte) { be.PutUint32(b[int(a.SignatureOffset)+20:], 4) }},
		{"no CMS", func(b []byte) { be.PutUint32(b[cd+12:], 0) }},
		{"malformed signature", func(b []byte) { b[a.SignatureOffset] = 0 }},
		{"wrong CMS wrapper", func(b []byte) {
			offset := be.Uint32(b[int(a.SignatureOffset)+32:])
			b[a.SignatureOffset+uint64(offset)] ^= 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := bytes.Clone(b)
			tc.f(x)
			if _, err := VerifyBytes(context.Background(), x, VerifyOptions{}); err == nil {
				t.Fatal("invalid accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyBytes(ctx, b, VerifyOptions{}); err == nil {
		t.Fatal("cancellation ignored")
	}
	if _, err := VerifyBytes(context.Background(), b, VerifyOptions{Architecture: "missing"}); err == nil {
		t.Fatal("missing arch accepted")
	}
	if _, err := VerifyBytes(context.Background(), fixture(t, "adhoc-universal"), VerifyOptions{Architecture: "arm64"}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBytes(context.Background(), b, VerifyOptions{Requirement: "unknown"}); err == nil {
		t.Fatal("unknown requirement accepted")
	}
	req, err := CompileRequirements("never")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignBytes(context.Background(), fixture(t, "unsigned-arm64"), SignOptions{Identifier: "x", Requirements: req, InfoPlist: []byte("info"), Resources: []byte("resources")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBytes(context.Background(), signed, VerifyOptions{InfoPlist: []byte("info"), Resources: []byte("resources"), CheckDesignatedRequirement: true}); !errors.Is(err, ErrDesignatedRequirement) {
		t.Fatal(err)
	}
	if _, err := VerifyBytes(context.Background(), signed, VerifyOptions{InfoPlist: []byte("wrong"), Resources: []byte("resources")}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := VerifyBytes(context.Background(), signed, VerifyOptions{InfoPlist: []byte("info")}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestCompiledRequirementsRejectMalformed(t *testing.T) {
	good, err := CompileRequirement(`identifier "hello" and always`)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, good[:12], blob(MagicRequirement, append32(nil, 2)), blob(MagicRequirement, append32(append32(nil, 1), 99)), blob(MagicRequirement, append32(append32(nil, 1), 6)), blob(MagicRequirement, append32(append32(append32(nil, 1), 6), 1)), blob(MagicRequirement, append32(append32(nil, 1), 2)), blob(MagicRequirement, append32(append32(append32(nil, 1), 8), 0)), append(good, 0)} {
		if _, err := EvaluateRequirementBytes(data, Directory{}); err == nil {
			t.Fatal("malformed requirement accepted")
		}
	}
	b := append32(nil, 1)
	for range 130 {
		b = append32(b, 9)
	}
	b = append32(b, 1)
	if _, err := EvaluateRequirementBytes(blob(MagicRequirement, b), Directory{}); err == nil {
		t.Fatal("deep expression")
	}
	raw := superblob(MagicRequirements, []Blob{{Slot: 2, Data: good}})
	if err := checkDesignatedRequirement(raw, Directory{}); err != nil {
		t.Fatal(err)
	}
	if err := checkDesignatedRequirement([]byte("bad"), Directory{}); err == nil {
		t.Fatal("malformed set")
	}
}
