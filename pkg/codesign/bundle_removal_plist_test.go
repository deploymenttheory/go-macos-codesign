package codesign

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestRemovalPlistNativeReplay(t *testing.T) {
	states := []string{"xml-valid", "xml-duplicate", "xml-no-wrapper", "xml-trailing", "xml-second-root", "xml-array", "xml-string", "xml-broken", "xml-unknown", "xml-integer-overflow", "xml-missing-value", "openstep", "openstep-duplicate", "openstep-comments", "openstep-no-semicolon", "openstep-trailing", "openstep-array", "openstep-strings", "openstep-escape", "openstep-unicode", "random", "spaces", "binary-truncated", "binary-dict", "binary-array", "binary-string", "binary-uid", "binary-duplicate", "binary-cycle"}
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
	for _, data := range [][]byte{{0xff, 0xfe, '{', 0}, []byte("{\x00}"), []byte(`<?xml version="1.0" encoding="ISO-8859-1"?><plist><dict/></plist>`), scalarBundlePlist([]byte{0xf0})} {
		if _, err := decodeRemovalPlist(data); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unsupported input became fallback", err)
		}
	}
	for _, data := range [][]byte{nil, []byte(""), []byte(" \n"), []byte("/*bad"), []byte("\"bad\\"), []byte("{} trailing"), []byte("<plist/>"), scalarBundlePlist([]byte{0x88})} {
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
