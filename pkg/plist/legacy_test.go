package plist_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/plist"
)

func TestLegacyExpansionBudget(t *testing.T) {
	const prefix = `<?xml encoding="windows-1252"?><string>`
	const suffix = `</string>`
	// A euro byte expands to three UTF-8 bytes, before XML interpretation. Include
	// the declaration in the conversion budget, exactly as for wide codecs.
	n := (plist.MaxSize - len(prefix) - len(suffix)) / 3
	padding := (plist.MaxSize - len(prefix) - len(suffix)) % 3
	data := append([]byte(prefix), bytes.Repeat([]byte{0x80}, n)...)
	data = append(data, bytes.Repeat([]byte{'x'}, padding)...)
	data = append(data, suffix...)
	before := bytes.Clone(data)
	got, err := plist.Decode(data)
	if err != nil || len(got.(string)) != n*3+padding || !bytes.Equal(before, data) {
		t.Fatal("exact conversion limit", err)
	}
	// Even an ignored suffix must be converted and bounded for legacy codecs.
	data = append(data, 'x')
	before = bytes.Clone(data)
	_, err = plist.Decode(data)
	var limit *plist.LimitError
	if !errors.As(err, &limit) || !errors.Is(err, plist.ErrFormat) || !bytes.Equal(before, data) {
		t.Fatal("expansion authorized interpretation or changed bytes", err)
	}
}

func TestLegacyUnqualifiedNames(t *testing.T) {
	for _, name := range []string{"Shift_JIS", "ISO-2022-JP", "GB18030", "not-a-codec", "", "KOI8-R", "Koi8-u", "\xff"} {
		data := []byte(`<?xml encoding="` + name + `"?><dict/>`)
		before := bytes.Clone(data)
		_, err := plist.Decode(data)
		if !errors.Is(err, plist.ErrUnsupported) || !bytes.Equal(data, before) {
			t.Fatal("unqualified codec became malformed fallback", name, err)
		}
	}
}

func TestLegacyIncompleteDeclarations(t *testing.T) {
	for _, s := range []string{`<?xml`, `<?xml encoding=`, `<?xml encoding=x`, `<?xml encoding="windows-1252`, `<?xml encoding="windows-1252"`, `<?xml >`, `<?xml ?`} {
		_, err := plist.Decode([]byte(s))
		if !errors.Is(err, plist.ErrFormat) {
			t.Fatal(s, err)
		}
	}
}
