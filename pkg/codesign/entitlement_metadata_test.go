package codesign

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func entitlementSignature(t *testing.T) *Signature {
	t.Helper()
	out, err := SignBytes(context.Background(), fixture(t, "unsigned-arm64"), SignOptions{Identifier: "org.example.test", Entitlements: []byte(`<plist><dict><key>test</key><string>one</string></dict></plist>`)})
	if err != nil {
		t.Fatal(err)
	}
	report, err := InspectBytes(out)
	if err != nil {
		t.Fatal(err)
	}
	return report.Architectures[0].Signature
}
func TestEntitlementMetadata(t *testing.T) {
	s := entitlementSignature(t)
	m, err := InspectEntitlements(s)
	wantText := "[Dict]\n\t[Key] test\n\t[Value]\n\t\t[String] one\n"
	if err != nil || !m.TextValid || string(m.Text) != wantText || !bytes.HasSuffix(m.XML, []byte("<dict><key>test</key><string>one</string></dict></plist>\n")) {
		t.Fatal(m, err)
	}
	// Results are owned, and changing the unused original XML has no effect.
	m.XML[0] = 0
	m.Text[0] = 0
	xml := s.find(SlotEntitlements)
	copy(xml[bytes.Index(xml, []byte("one")):], "two")
	m, err = InspectEntitlements(s)
	if err != nil || string(m.Text) != wantText {
		t.Fatal(m, err)
	}
	for _, b := range s.Blobs {
		if b.Slot == SlotEntitlements {
			copy(b.Data, entitlementSignature(t).find(SlotEntitlements))
		}
	}
	for i := range s.Blobs {
		if s.Blobs[i].Slot == SlotDEREntitlements {
			s.Blobs[i].Slot = 0x7777
		}
	}
	be.PutUint32(s.find(SlotDirectory)[24:], 5)
	m, err = InspectEntitlements(s)
	if err != nil || string(m.Text) != wantText {
		t.Fatal(m, err)
	}
}
func TestEntitlementMetadataErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Signature)
		want   error
	}{
		{"alternate", func(s *Signature) { s.Directories = append(s.Directories, s.Directories[0]) }, ErrUnsupported},
		{"directory", func(s *Signature) { s.find(SlotDirectory)[0] = 0 }, ErrFormat},
		{"blob-header", func(s *Signature) { s.find(SlotDEREntitlements)[0] = 0 }, ErrFormat},
		{"blob-length", func(s *Signature) { s.find(SlotDEREntitlements)[7]++ }, ErrFormat},
		{"hash", func(s *Signature) { s.find(SlotDEREntitlements)[10] ^= 1 }, ErrInvalid},
		{"xml-malformed", func(s *Signature) {
			for i := range s.Blobs {
				if s.Blobs[i].Slot == SlotDEREntitlements {
					s.Blobs[i].Slot = 0x7777
				}
			}
			be.PutUint32(s.find(SlotDirectory)[24:], 5)
			s.find(SlotEntitlements)[8] = 0
		}, ErrFormat},
		{"xml-unsupported", func(s *Signature) {
			for i := range s.Blobs {
				if s.Blobs[i].Slot == SlotDEREntitlements {
					s.Blobs[i].Slot = 0x7777
				}
				if s.Blobs[i].Slot == SlotEntitlements {
					s.Blobs[i].Data = blob(MagicEntitlements, []byte(`<plist><dict><key>test</key><real>1.0</real></dict></plist>`))
				}
			}
			be.PutUint32(s.find(SlotDirectory)[24:], 5)
		}, ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := entitlementSignature(t)
			tc.mutate(s)
			if strings.HasPrefix(tc.name, "xml-") {
				d := s.find(SlotDirectory)
				sum, _ := digest(d[37], s.find(SlotEntitlements))
				off := be.Uint32(d[16:]) - 5*uint32(d[36])
				copy(d[off:], sum)
			}
			m, err := InspectEntitlements(s)
			if m != nil || !errors.Is(err, tc.want) {
				t.Fatal(m, err)
			}
		})
	}
	if _, err := InspectEntitlements(nil); !errors.Is(err, ErrUnsigned) {
		t.Fatal(err)
	}
	if m, err := InspectEntitlements(&Signature{}); m != nil || err != nil {
		t.Fatal(m, err)
	}
	s := entitlementSignature(t)
	d := s.find(SlotDirectory)
	off := be.Uint32(d[16:])
	size := uint32(d[36])
	clear(d[off-7*size : off-6*size])
	if _, err := InspectEntitlements(s); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
func TestEntitlementDERInvalid(t *testing.T) {
	wrap := func(v []byte) []byte { return derWrap(0x70, append([]byte{2, 1, 1}, v...)) }
	pair := func(k, v []byte) []byte { return derWrap(0x30, append(k, v...)) }
	dict := func(v []byte) []byte { return wrap(derWrap(0xb0, v)) }
	key := []byte{12, 1, 'a'}
	entry := pair(key, []byte{1, 1, 0})
	for name, data := range map[string][]byte{
		"empty": nil, "large": make([]byte, maxBundlePlist+1), "outer-trailing": {0x70, 0, 0}, "outer-type": {0x30, 0}, "empty-version": {0x70, 0}, "version": derWrap(0x70, []byte{2, 1, 2}),
		"no-root": derWrap(0x70, []byte{2, 1, 1}), "non-dictionary": wrap([]byte{1, 1, 0}), "root-trailing": wrap([]byte{0xb0, 0, 0}),
		"bad-bool": dict(pair(key, []byte{1, 1, 1})), "bad-int": dict(pair(key, []byte{2, 2, 0, 1})), "bad-string": dict(pair(key, []byte{12, 1, 255})), "nul-string": dict(pair(key, []byte{12, 1, 0})),
		"unsupported": dict(pair(key, []byte{5, 0})), "broken-pair": dict([]byte{0x30}), "pair-type": dict([]byte{0x31, 0}), "pair-key-error": dict(pair([]byte{12}, nil)), "pair-key-type": dict(pair([]byte{1, 1, 0}, []byte{1, 1, 0})),
		"duplicate": dict(append(bytes.Clone(entry), entry...)), "pair-no-value": dict(pair(key, nil)), "pair-extra": dict(pair(key, []byte{1, 1, 0, 1, 1, 0})), "array-broken": dict(pair(key, []byte{0x30, 1, 1})),
	} {
		t.Run(name, func(t *testing.T) {
			if m, err := decodeEntitlementMetadata(data); m != nil || err == nil {
				t.Fatal(m, err)
			}
		})
	}
	nested := []byte{0x30, 0}
	for i := 0; i < maxBundlePlistDepth+1; i++ {
		nested = derWrap(0x30, nested)
	}
	if _, err := decodeEntitlementMetadata(dict(pair(key, nested))); err == nil {
		t.Fatal("depth accepted")
	}
	large := derWrap(0x30, bytes.Repeat([]byte{1, 1, 0}, maxBundlePlistValues))
	if _, err := decodeEntitlementMetadata(dict(pair(key, large))); err == nil {
		t.Fatal("value count accepted")
	}
	// Constructed containers do not count as array primitive types.
	_, der, err := EncodeEntitlements([]byte(`<plist><dict><key>test</key><array><string>one</string><dict/></array></dict></plist>`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodeEntitlementMetadata(der)
	if err != nil || !m.TextValid {
		t.Fatal(m, err)
	}
	_, der, err = EncodeEntitlements([]byte(`<plist><dict><key>test</key><array><string>one</string><true/></array></dict></plist>`))
	if err != nil {
		t.Fatal(err)
	}
	m, err = decodeEntitlementMetadata(der)
	if err != nil || m.TextValid || m.Text != nil || !strings.Contains(string(m.XML), "<true/>") {
		t.Fatal(m, err)
	}
}

func FuzzEntitlementMetadata(f *testing.F) {
	for _, xml := range []string{`<plist><dict/></plist>`, `<plist><dict><key>a</key><array><true/><string>b</string></array></dict></plist>`} {
		_, der, err := EncodeEntitlements([]byte(xml))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = decodeEntitlementMetadata(data) })
}
