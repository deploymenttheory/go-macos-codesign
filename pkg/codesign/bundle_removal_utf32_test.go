package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
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

func TestRemovalNativeXMLGrammarLimits(t *testing.T) {
	var corpus struct {
		Schema int
		MacOS  string
		Driver string `json:"source_sha256"`
		Native string `json:"codesign_sha256"`
		Cases  []struct {
			Shape, State, Info, Platform, Selected, Output string
			Status                                         int
			Envelope                                       bool
			Files                                          map[string][]byte
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../testdata/bundle-removal/plist-utf32-grammar.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(readTestFile(t, "../../scripts/probe-removal-plist-interpretation.go"))
	if corpus.Schema != 1 || corpus.MacOS == "" || len(corpus.Native) != 64 || corpus.Driver != hex.EncodeToString(h[:]) || len(corpus.Cases) != 36 {
		t.Fatal("stale grammar evidence")
	}
	if _, err := hex.DecodeString(corpus.Native); err != nil {
		t.Fatal(err)
	}
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
	for _, tc := range corpus.Cases {
		name := tc.Shape + "/" + tc.State
		if !wanted[name] || tc.Status != 0 || tc.Output != "" || tc.Envelope || !strings.HasSuffix(tc.Selected, "second") {
			t.Fatal("unexpected native grammar observation", name)
		}
		delete(wanted, name)
		info := tc.Info
		if strings.HasPrefix(tc.State, "platform-") {
			info = tc.Platform
		}
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRemovalPlist(tc.Files[info]); !errors.Is(err, ErrUnsupported) {
				t.Fatal("native-valid grammar became empty dictionary", err)
			}
		})
	}
}

func TestRemovalXMLGrammarPreservesBundle(t *testing.T) {
	for _, chars := range []string{"\x01\x08\x0b\x0c\x0e\x1f", "\ufffe\uffff", "a\x00b"} {
		text := `<plist><dict><key>CFBundleExecutable</key><string>hello</string><key>Ignored</key><string>` + chars + `</string></dict></plist>`
		for _, data := range [][]byte{[]byte(text), removalUTF16(text), removalUTF32(text)} {
			app := testBundle(t)
			main := readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))
			bundleFile(t, app, "Contents/Info.plist", data)
			bundleFile(t, app, bundleResourcesPath, []byte("unchanged envelope"))
			if err := RemoveSignature(context.Background(), app); !errors.Is(err, ErrUnsupported) {
				t.Fatal("grammar limit authorized removal", err)
			}
			if !bytes.Equal(data, readTestFile(t, filepath.Join(app, "Contents/Info.plist"))) || !bytes.Equal(main, readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))) || string(readTestFile(t, filepath.Join(app, bundleResourcesPath))) != "unchanged envelope" {
				t.Fatal("grammar limit mutated bundle")
			}
		}
	}
	const chars = "\x01\x08\x0b\x0c\x0e\x1f\ufffe\uffff"
	values, err := decodeRemovalPlist(removalUTF32("{CFBundleExecutable=second;Ignored=\"" + chars + "\";}"))
	if err != nil || values["CFBundleExecutable"] != "second" || values["Ignored"] != chars {
		t.Fatal("OpenStep grammar restricted", values, err)
	}
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
	for _, invalid := range [][]byte{removalUTF32("a\x00b"), data[4:]} {
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
