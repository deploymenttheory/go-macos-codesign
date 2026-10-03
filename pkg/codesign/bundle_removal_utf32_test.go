package codesign

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRemovalPlistUTF32NativeReplay(t *testing.T) {
	var states []string
	for _, endian := range []string{"le", "be"} {
		for _, kind := range []string{"xml", "xml-trailing-controls", "openstep", "openstep-controls", "declared", "mismatch", "scalar-boundaries", "bom-only", "truncated"} {
			states = append(states, kind+"-"+endian)
		}
		for n := 1; n <= 3; n++ {
			states = append(states, fmt.Sprintf("partial-%d-%s", n, endian), fmt.Sprintf("partial-only-%d-%s", n, endian))
		}
		for _, scalar := range []uint32{0xd800, 0xdc00, 0x110000, 0xffffffff} {
			for _, position := range []string{"inside", "tail"} {
				states = append(states, fmt.Sprintf("invalid-%x-%s-%s", scalar, position, endian))
			}
		}
	}
	wanted := map[string]bool{}
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, location := range []string{"ordinary", "platform"} {
			for _, state := range states {
				wanted[shape+"/"+location+"-"+state] = true
			}
		}
	}
	replayRemovalPlists(t, "plist-utf32.json", "probe-removal-plist-interpretation.go", wanted)
}

func TestRemovalXMLGrammarNativeReplay(t *testing.T) {
	wanted := map[string]bool{}
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, location := range []string{"ordinary", "platform"} {
			for _, kind := range []string{"controls", "noncharacters", "nul"} {
				for _, endian := range []string{"le", "be"} {
					wanted[shape+"/"+location+"-"+kind+"-"+endian] = true
				}
			}
		}
	}
	replayRemovalPlists(t, "plist-utf32-grammar.json", "probe-removal-plist-interpretation.go", wanted)
}

func removalUTF32(s string) []byte {
	b := []byte{0xff, 0xfe, 0, 0}
	for _, r := range s {
		b = binary.LittleEndian.AppendUint32(b, uint32(r))
	}
	return b
}

func TestRemovalPlistUTF32Boundaries(t *testing.T) {
	const value = "\u007f\u0080\u07ff\u0800\ud7ff\ue000\ufffd\U00010000\U0010ffff"
	text := `<plist><dict><key>CFBundleExecutable</key><string>` + value + `</string></dict></plist>`
	data := removalUTF32(text)
	before := bytes.Clone(data)
	values, err := decodeRemovalPlist(data)
	if err != nil || values["CFBundleExecutable"] != value || !bytes.Equal(data, before) {
		t.Fatal("scalar fidelity or input preservation", values, err)
	}
	if _, err := decodeBundlePlist(data); err == nil {
		t.Fatal("strict parser weakened")
	}
	if got, err := decodeRemovalPlist(data[4:]); err != nil || len(got) != 0 {
		t.Fatal("unmarked XML native fallback", got, err)
	}
	for _, invalid := range [][]byte{removalUTF32("a\x00b")} {
		if _, err := decodeRemovalPlist(invalid); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unqualified text redirected removal", err)
		}
	}
	for _, bom := range [][]byte{{0xff, 0xfe, 0, 0}, {0, 0, 0xfe, 0xff}} {
		if values, err := decodeRemovalPlist(bom); err != nil || len(values) != 0 {
			t.Fatal("empty native dictionary", values, err)
		}
	}
	// UTF-32 cannot expand beyond its input size, but conversion must still
	// preserve input, nesting and value-count limits before any mutation.
	for name, text := range map[string]string{
		"input":  strings.Repeat("a", maxBundlePlist/4),
		"depth":  strings.Repeat("(", 33) + strings.Repeat(")", 33),
		"values": `(` + strings.Repeat(`x,`, maxBundlePlistValues) + `x)`,
	} {
		t.Run(name, func(t *testing.T) {
			var limit *bundlePlistLimitError
			if _, err := decodeRemovalPlist(removalUTF32(text)); !errors.As(err, &limit) || !errors.Is(err, ErrFormat) {
				t.Fatal("encoded limit became fallback", err)
			}
		})
	}
}
