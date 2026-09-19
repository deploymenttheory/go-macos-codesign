package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestExtendedAppleFixtures(t *testing.T) {
	ent, err := os.ReadFile("../../testdata/entitlements.plist")
	if err != nil {
		t.Fatal(err)
	}
	req, err := CompileRequirements(`designated => identifier "org.example.fixture"`)
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, mode := range []string{"entitlements", "runtime", "requirement"} {
			t.Run(arch+"/"+mode, func(t *testing.T) {
				o := SignOptions{Identifier: "org.example.fixture"}
				switch mode {
				case "entitlements":
					o.Entitlements = ent
					t.Logf("testdata/entitlements.plist: length=%d sha256=%x LF=%d CRLF=%d",
						len(ent), sha256.Sum256(ent), bytes.Count(ent, []byte("\n")), bytes.Count(ent, []byte("\r\n")))
				case "runtime":
					o.Flags = FlagRuntime
				case "requirement":
					o.Requirements = req
				}
				got, err := SignBytes(context.Background(), fixture(t, "unsigned-"+arch), o)
				if err != nil {
					t.Fatal(err)
				}
				want := fixture(t, mode+"-"+arch)
				assertAppleBytes(t, got, want)
				if _, err := VerifyBytes(context.Background(), got, VerifyOptions{}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestSignatureRejectsMalformed(t *testing.T) {
	r, err := InspectBytes(fixture(t, "adhoc-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	a := r.Architectures[0]
	raw := fixture(t, "adhoc-arm64")[a.SignatureOffset:]
	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"short", func(b []byte) []byte { return b[:8] }}, {"magic", func(b []byte) []byte { b[0] ^= 1; return b }},
		{"length small", func(b []byte) []byte { be.PutUint32(b[4:], 4); return b }}, {"length large", func(b []byte) []byte { be.PutUint32(b[4:], 0xffffffff); return b }},
		{"count", func(b []byte) []byte { be.PutUint32(b[8:], 0xffffffff); return b }},
		{"duplicate", func(b []byte) []byte { be.PutUint32(b[20:], 0); return b }},
		{"index overlap", func(b []byte) []byte { be.PutUint32(b[16:], 12); return b }},
		{"bad blob size", func(b []byte) []byte { be.PutUint32(b[40:], 7); return b }},
		{"bad CD", func(b []byte) []byte { be.PutUint32(b[36:], 0); return b }},
		{"no primary", func(b []byte) []byte { be.PutUint32(b[12:], 123); return b }},
		{"overlap", func(b []byte) []byte { be.PutUint32(b[24:], 36); return b }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSignature(tc.mutate(bytes.Clone(raw))); err == nil {
				t.Fatal("accepted malformed signature")
			}
		})
	}
	cd := a.Signature.Directories[0].Raw
	for _, tc := range []struct {
		name string
		f    func([]byte) []byte
	}{
		{"header", func(b []byte) []byte { return b[:43] }}, {"version", func(b []byte) []byte { be.PutUint32(b[8:], 0x30000); return b }},
		{"truncated version", func(b []byte) []byte { be.PutUint32(b[8:], 0x20600); return b[:88] }},
		{"hash type", func(b []byte) []byte { b[37] = 255; return b }}, {"hash size", func(b []byte) []byte { b[36] = 31; return b }},
		{"page exponent", func(b []byte) []byte { b[39] = 32; return b }},
		{"scatter", func(b []byte) []byte { be.PutUint32(b[44:], 80); return b }},
		{"identifier header", func(b []byte) []byte { be.PutUint32(b[20:], 1); return b }},
		{"identifier offset", func(b []byte) []byte { be.PutUint32(b[20:], 0xffffffff); return b }},
		{"identifier terminator", func(b []byte) []byte { be.PutUint32(b[20:], uint32(len(b)-1)); b[len(b)-1] = 1; return b }},
		{"team offset", func(b []byte) []byte { be.PutUint32(b[48:], 0xffffffff); return b }},
		{"special hashes", func(b []byte) []byte { be.PutUint32(b[24:], 0xffffffff); return b }},
		{"code hashes", func(b []byte) []byte { be.PutUint32(b[28:], 0xffffffff); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseDirectory(tc.f(bytes.Clone(cd))); err == nil {
				t.Fatal("accepted invalid CodeDirectory")
			}
		})
	}
	for _, kind := range []uint8{1, 2, 3, 4} {
		h, err := digest(kind, []byte("hello"))
		if err != nil || len(h) == 0 {
			t.Fatal(err)
		}
	}
	b := bytes.Clone(cd)
	be.PutUint32(b[48:], 88)
	be.PutUint32(b[32:], 0)
	be.PutUint64(b[56:], 16512)
	d, err := parseDirectory(b)
	if err != nil || d.TeamID != "org.example.fixture" || d.CodeLimit != 16512 {
		t.Fatal(d, err)
	}
}

func TestEntitlementTypesAndBounds(t *testing.T) {
	values := map[string]any{"true": true, "false": false, "empty": "", "dict": map[string]any{}, "array": []any{}, "unicode": "a&<>☃", "negative": int64(-1), "long": strings.Repeat("x", 160), "nested": []any{map[string]any{"a": "b"}}}
	b, err := plist.Marshal(values, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	xml, der, err := EncodeEntitlements(b)
	if err != nil || !bytes.Contains(xml, []byte("<string></string>")) || !bytes.Contains(xml, []byte("&amp;&lt;&gt;")) || len(der) < 128 {
		t.Fatal(string(xml), err)
	}
	if _, _, err := EncodeEntitlements([]byte("no plist")); err == nil {
		t.Fatal("invalid plist accepted")
	}
	if _, _, err := EncodeEntitlements(make([]byte, 16<<20+1)); err == nil {
		t.Fatal("oversize accepted")
	}
	for _, v := range []any{float64(1.5), []byte{1}, time.Now(), uint64(1 << 63)} {
		if _, err := entitlementDER(v, 0); err == nil {
			t.Fatalf("unsupported type %T", v)
		}
	}
	if _, err := entitlementDER(true, 129); err == nil {
		t.Fatal("depth")
	}
	if _, err := entitlementDER([]any{1.0}, 0); err == nil {
		t.Fatal("nested unsupported")
	}
	if _, err := entitlementDER(map[string]any{"x": 1.0}, 0); err == nil {
		t.Fatal("dict unsupported")
	}
	b, err = plist.Marshal(map[string]any{"x": 1.2}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = EncodeEntitlements(b); err == nil {
		t.Fatal("real accepted")
	}
}

func TestRequirements(t *testing.T) {
	d := Directory{Identifier: "hello", CDHash: strings.Repeat("ab", 20)}
	for _, tc := range []struct {
		text string
		want bool
	}{
		{`identifier "hello"`, true}, {`identifier "no"`, false}, {`cdhash H"` + d.CDHash + `"`, true}, {`never`, false}, {`always`, true}, {`not always`, false}, {`always and (false or true)`, true}, {`!false or false`, true},
	} {
		raw, err := CompileRequirement(tc.text)
		if err != nil {
			t.Fatal(err)
		}
		got, err := EvaluateRequirementBytes(raw, d)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %v %v", tc.text, got, err)
		}
		textResult, err := EvaluateRequirement(tc.text, d)
		if err != nil || textResult != got {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"", `identifier 4`, `cdhash "a"`, `cdhash H"ff"`, `cdhash H"zz"`, `identifier "unfinished`, `always never`, `(always`, `always and ???`, `always or ???`, `not ???`, `anchor apple`, strings.Repeat("(", 130) + "true" + strings.Repeat(")", 130), strings.Repeat("!", 130) + "true", strings.Repeat("a", 1<<20+1), "designated x"} {
		if _, err := CompileRequirements(bad); err == nil {
			t.Fatalf("accepted %q", bad[:min(len(bad), 100)])
		}
	}
	if _, err := CompileRequirement(strings.Repeat("always or ", 4097) + "always"); err == nil {
		t.Fatal("too many nodes")
	}
	raw, err := CompileRequirements(`designated => identifier "hello"`)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRequirements(raw); err != nil {
		t.Fatal(err)
	}
	got, err := RequirementsBytes(raw)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal(err)
	}
	if _, err := RequirementsBytes([]byte(`identifier "hello"`)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(raw); i++ {
		if err := validateRequirements(raw[:i]); err == nil {
			t.Fatalf("accepted truncated requirements length %d", i)
		}
	}
	for _, off := range []int{0, 8, 16, 20, 24, 28, 32, 36} {
		b := bytes.Clone(raw)
		be.PutUint32(b[off:], 0xffffffff)
		if err := validateRequirements(b); err == nil {
			t.Fatal("invalid requirement accepted", off)
		}
	}
	if err := checkDesignatedRequirement(nil, d); err != nil {
		t.Fatal(err)
	}
	if err := checkDesignatedRequirement(raw, d); err != nil {
		t.Fatal(err)
	}
	if err := checkDesignatedRequirement(raw, Directory{}); !errors.Is(err, ErrDesignatedRequirement) {
		t.Fatal(err)
	}
	if _, err := EvaluateRequirement(`bogus`, d); err == nil {
		t.Fatal("unsupported expression")
	}
	if _, err := hex.DecodeString(d.CDHash); err != nil {
		t.Fatal(err)
	}
}

func syntheticMachO(order binary.ByteOrder, is64 bool) []byte {
	header, segment, magic := 28, 56, uint32(0xfeedface)
	if is64 {
		header, segment, magic = 32, 72, 0xfeedfacf
	}
	b := make([]byte, 4200)
	order.PutUint32(b, magic)
	order.PutUint32(b[4:], 7)
	order.PutUint32(b[8:], 3)
	order.PutUint32(b[12:], 2)
	order.PutUint32(b[16:], 2)
	order.PutUint32(b[20:], uint32(2*segment))
	for i, name := range []string{"__TEXT", "__LINKEDIT"} {
		p := header + i*segment
		cmd := uint32(1)
		if is64 {
			cmd = 0x19
		}
		order.PutUint32(b[p:], cmd)
		order.PutUint32(b[p+4:], uint32(segment))
		copy(b[p+8:], name)
		off, size := uint64(0), uint64(4096)
		if i == 1 {
			off, size = 4096, 104
		}
		if is64 {
			order.PutUint64(b[p+40:], off)
			order.PutUint64(b[p+48:], size)
		} else {
			order.PutUint32(b[p+32:], uint32(off))
			order.PutUint32(b[p+36:], uint32(size))
		}
	}
	return b
}

func TestEndianAnd32Bit(t *testing.T) {
	for _, order := range []binary.ByteOrder{be, binary.LittleEndian} {
		for _, is64 := range []bool{false, true} {
			b := syntheticMachO(order, is64)
			out, err := SignBytes(context.Background(), b, SignOptions{Identifier: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyBytes(context.Background(), out, VerifyOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := RemoveSignatureBytes(context.Background(), out); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, cpu := range []uint32{7, 12, 18, 0x1000007, 0x100000c, 0x1000012, 999} {
		for _, sub := range []uint32{0, 2, 8} {
			if archName(cpu, sub) == "" {
				t.Fatal("empty arch")
			}
		}
	}
}

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestFileErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	missing := filepath.Join(t.TempDir(), "missing")
	for _, call := range []func() error{func() error { _, e := Inspect(ctx, missing); return e }, func() error { _, e := Inspect(context.Background(), missing); return e }, func() error { return Sign(ctx, missing, SignOptions{}) }, func() error { return RemoveSignature(ctx, missing) }, func() error { _, e := Verify(ctx, missing, VerifyOptions{}); return e }, func() error { return replaceFile(ctx, missing, nil) }, func() error { _, e := readFile(filepath.Dir(missing)); return e }, func() error { return replaceFile(ctx, filepath.Dir(missing), nil) }} {
		if call() == nil {
			t.Fatal("error expected")
		}
	}
	if _, err := readBounded(badReader{}, 1); err == nil {
		t.Fatal("reader error ignored")
	}
	if _, err := readBounded(strings.NewReader("large"), 2); err == nil {
		t.Fatal("limit ignored")
	}
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Sign(context.Background(), path, SignOptions{}); err == nil {
		t.Fatal("bad file signed")
	}
	if err := RemoveSignature(context.Background(), path); err == nil {
		t.Fatal("bad file stripped")
	}
	if err := replaceFile(ctx, path, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "large"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxFileSize + 1); err != nil {
		f.Close()
		t.Skip("sparse files unavailable")
	}
	f.Close()
	if _, err := readFile(f.Name()); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
