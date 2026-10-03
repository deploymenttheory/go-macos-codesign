package codesign

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemovalPlistNativeReplay(t *testing.T) {
	states := []string{"xml-valid", "xml-duplicate", "xml-no-wrapper", "xml-trailing", "xml-second-root", "xml-array", "xml-string", "xml-broken", "xml-unknown", "xml-integer-overflow", "xml-missing-value", "openstep", "openstep-duplicate", "openstep-comments", "openstep-no-semicolon", "openstep-trailing", "openstep-array", "openstep-strings", "openstep-escape", "openstep-unicode", "random", "spaces", "binary-truncated", "binary-dict", "binary-array", "binary-string", "binary-uid", "binary-duplicate", "binary-cycle", "binary-uid-overflow"}
	wanted := map[string]bool{}
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, location := range []string{"ordinary", "platform"} {
			for _, state := range states {
				wanted[shape+"/"+location+"-"+state] = true
			}
		}
	}
	replayRemovalPlists(t, "plist-interpretation.json", "probe-removal-plist-interpretation.go", wanted)
}

func TestRemovalPlistLimitsRemainFatal(t *testing.T) {
	objectCount := scalarBundlePlist([]byte{9})
	binary.BigEndian.PutUint64(objectCount[len(objectCount)-24:], maxBundlePlistValues+1)
	graph := [][]byte{{0xd1, 1, 2}, {0x51, 'k'}}
	for i := 2; i < 21; i++ {
		graph = append(graph, []byte{0xa2, byte(i + 1), byte(i + 1)})
	}
	graph = append(graph, []byte{9})
	deep := [][]byte{{0xd1, 1, 2}, {0x51, 'k'}}
	for i := 2; i < 35; i++ {
		deep = append(deep, []byte{0xa1, byte(i + 1)})
	}
	deep = append(deep, []byte{9})
	for name, data := range map[string][]byte{
		"bytes":          bytes.Repeat([]byte("x"), maxBundlePlist+1),
		"xml-depth":      []byte(`<plist>` + strings.Repeat(`<array>`, 33) + strings.Repeat(`</array>`, 33) + `</plist>`),
		"xml-values":     []byte(`<plist><array>` + strings.Repeat(`<true/>`, maxBundlePlistValues) + `</array></plist>`),
		"text-depth":     []byte(strings.Repeat("(", 33) + strings.Repeat(")", 33)),
		"text-values":    []byte("(" + strings.Repeat("x,", maxBundlePlistValues) + "x)"),
		"binary-objects": objectCount, "binary-expansion": rawBundlePlist(graph, 2, 1), "binary-depth": rawBundlePlist(deep, 2, 1),
		"binary-bytes":      scalarBundlePlist(append([]byte{0x4f, 0x13}, bytes.Repeat([]byte{0xff}, 8)...)),
		"binary-dictionary": scalarBundlePlist(append([]byte{0xdf, 0x13}, bytes.Repeat([]byte{0xff}, 8)...)),
	} {
		t.Run(name, func(t *testing.T) {
			var limit *bundlePlistLimitError
			if _, err := decodeRemovalPlist(data); !errors.As(err, &limit) || !errors.Is(err, ErrFormat) {
				t.Fatal("limit became removal fallback", err)
			}
		})
	}
}

func TestRemovalPlistInterpretationBoundaries(t *testing.T) {
	for _, data := range [][]byte{[]byte(`<?xml version="1.0" encoding="ISO-2022-JP-1"?><plist><dict/></plist>`), scalarBundlePlist([]byte{0xf0})} {
		if _, err := decodeRemovalPlist(data); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unsupported input became fallback", err)
		}
	}
	for _, data := range [][]byte{nil, []byte(""), []byte(" \n"), []byte("{\x00}"), []byte("/*bad"), []byte("\"bad\\"), []byte("{} trailing"), []byte("<plist/>"), scalarBundlePlist([]byte{0x88})} {
		values, err := decodeRemovalPlist(data)
		if err != nil || len(values) != 0 {
			t.Fatal("invalid/non-dictionary interpretation", values, err)
		}
	}
	// Quoted delimiters, comments and data cannot consume the nesting budget.
	data := []byte("// comment\r\n{CFBundleExecutable=\"second\";ignored=\"" + strings.Repeat("{(", 50) + "\";data=<000102>;array=(one,two);/*{}*/}")
	values, err := decodeRemovalPlist(data)
	if err != nil || values["CFBundleExecutable"] != "second" {
		t.Fatal(values, err)
	}
	values, err = decodeRemovalPlist(append([]byte{0xef, 0xbb, 0xbf}, []byte(`<plist><dict><key>CFBundleExecutable</key><string>second</string></dict></plist>`)...))
	if err != nil || values["CFBundleExecutable"] != "second" {
		t.Fatal(values, err)
	}
	// The existing signing/verification parser still rejects ambiguous duplicates.
	if _, err := decodeBundlePlist([]byte(`<plist><dict><key>k</key><true/><key>k</key><false/></dict></plist>`)); err == nil {
		t.Fatal("strict parser weakened")
	}
}

func FuzzRemovalPlist(f *testing.F) {
	f.Add([]byte("<?xml encoding=\"shift_jis\"?><dict><key>CFBundleExecutable</key><string>\x82\xa0</string></dict>\xfc"))
	f.Add([]byte("<?xml encoding=\"cp932\"?><string>\x81\x7f</string>"))
	f.Add([]byte(`<?xml encoding="ISO-8859-1"?>{CFBundleExecutable=second;}`))
	f.Add([]byte("<?xml encoding=\"windows-1252\"?><dict/>\x81"))
	f.Add([]byte("\xef\xbb\xbf<?xml encoding=\"macintosh\"?><dict/>"))
	f.Add(removalUTF16(`x<dict><key>CFBundleExecutable</key><string>second</string></dict>`)[2:])
	f.Add(removalUTF32(`{CFBundleExecutable=second;}`)[4:])
	f.Add([]byte("<dict><key>a\x00b</key><string><![CDATA[\x01]]>&#0;&#x10FFFF;</string></dict>"))
	f.Add([]byte(`<dict><key>&#xD800;</key><string/></dict>`))
	f.Add(removalUTF32(`<plist><dict><key>CFBundleExecutable</key><string>😀</string></dict></plist>`))
	f.Add([]byte{0, 0, 0xfe, 0xff, 0, 0x11, 0, 0})
	f.Add(removalUTF16(`<plist><dict><key>CFBundleExecutable</key><string>😀</string></dict></plist>`))
	f.Add([]byte{0xfe, 0xff, 0, '{', 0xd8, 0, 0, '}'})
	for _, s := range []string{`{CFBundleExecutable=second;}`, `<plist><dict/></plist>`, `<plist><array/></plist>`, "bplist00", `/*comment*/ {k=("quoted",<0102>);}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxBundlePlist {
			return
		}
		_, _ = decodeRemovalPlist(data)
	})
}

func TestRemovalPlistRestrictionsDoNotRedirect(t *testing.T) {
	wideOffset := rawBundlePlist([][]byte{{0xd1, 1, 2}, {0x51, 'k'}, {9}}, 16, 1)
	wideDict := make([]byte, 33)
	wideDict[0], wideDict[16], wideDict[32] = 0xd1, 1, 2
	wideReference := rawBundlePlist([][]byte{wideDict, {0x51, 'k'}, {9}}, 1, 16)
	for name, data := range map[string][]byte{
		"offset-width": wideOffset, "reference-width": wideReference,
		"length-width":   scalarBundlePlist(append([]byte{0x4f, 0x14}, make([]byte, 16)...)),
		"date-range":     scalarBundlePlist([]byte{0x33, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0}),
		"surrogate":      scalarBundlePlist([]byte{0x61, 0xdc, 0}),
		"non-string-key": rawBundlePlist([][]byte{{0xd1, 1, 2}, {9}, {0x51, 'v'}}, 1, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRemovalPlist(data); !errors.Is(err, ErrUnsupported) {
				t.Fatal("restriction became fallback", err)
			}
			if _, err := decodeBundlePlist(data); !errors.Is(err, ErrFormat) {
				t.Fatal("strict rejection changed", err)
			}
			app := testBundle(t)
			main := readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))
			bundleFile(t, app, "Contents/Info.plist", data)
			bundleFile(t, app, bundleResourcesPath, []byte("unchanged envelope"))
			if err := RemoveSignature(context.Background(), app); !errors.Is(err, ErrUnsupported) {
				t.Fatal("restriction authorized removal", err)
			}
			if !bytes.Equal(main, readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))) || !bytes.Equal(data, readTestFile(t, filepath.Join(app, "Contents/Info.plist"))) || string(readTestFile(t, filepath.Join(app, bundleResourcesPath))) != "unchanged envelope" {
				t.Fatal("restriction mutated bundle")
			}
		})
	}
	// A native frame can contain an unused header offset. Reject the unqualified
	// profile explicitly instead of losing a valid dictionary's executable name.
	unusedHeader := rawBundlePlist([][]byte{{0xd1, 1, 2}, {0x51, 'k'}, {9}, {9}}, 1, 1)
	table := int(binary.BigEndian.Uint64(unusedHeader[len(unusedHeader)-8:]))
	unusedHeader[table+3] = 0
	if _, err := decodeRemovalPlist(unusedHeader); !errors.Is(err, ErrUnsupported) {
		t.Fatal("unused entry became fallback", err)
	}
}
