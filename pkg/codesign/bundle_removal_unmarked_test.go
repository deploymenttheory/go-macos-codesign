package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemovalPlistUnmarkedNativeReplay(t *testing.T) {
	states := []string{"openstep-xml-literal-utf8"}
	for _, codec := range []string{"16le", "16be", "32le", "32be"} {
		for _, kind := range []string{"xml", "openstep-xml-literal", "openstep", "padded-xml", "prefixed-xml", "strings", "comments", "nul-prefix", "double-bom", "declared", "mismatch", "odd-tail", "surrogate-tail", "short"} {
			states = append(states, kind+"-"+codec)
		}
	}
	for _, prefix := range [][]byte{{'x', 0}, {0, 'x'}, {0, 0}, {0xff, 0}, {0, 0xff}} {
		states = append(states, fmt.Sprintf("prefix-%x", prefix))
	}
	for _, data := range [][]byte{{0}, {'x', 0}, {0, 'x'}, {0, 0}, {'x', 0, 0}, {'{', 0, '}'}} {
		states = append(states, fmt.Sprintf("short-bytes-%x", data))
	}
	wanted := map[string]bool{}
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, location := range []string{"ordinary", "platform"} {
			for _, state := range states {
				wanted[shape+"/"+location+"-"+state] = true
			}
		}
	}
	replayRemovalPlists(t, "plist-unmarked.json", "probe-removal-plist-interpretation.go", wanted)
}

func TestRemovalPlistUnmarkedBoundaries(t *testing.T) {
	const text = `<dict><key>CFBundleExecutable</key><string>second</string><key>Ignored</key><string>é水😀</string></dict>`
	data := removalUTF16("x" + text)[2:]
	before := bytes.Clone(data)
	values, err := decodeRemovalPlist(data)
	if err != nil || values["CFBundleExecutable"] != "second" || values["Ignored"] != "é水😀" || !bytes.Equal(data, before) {
		t.Fatal("unmarked conversion or preservation", values, err)
	}
	if _, err := decodeBundlePlist(data); err == nil {
		t.Fatal("strict parser weakened")
	}
	// Do not guess UTF-32 or infer big-endian UTF-16 from the zero byte's position.
	for _, data := range [][]byte{removalUTF16(text)[2:], removalUTF32(text)[4:]} {
		got, err := decodeRemovalPlist(data)
		if err != nil || len(got) != 0 {
			t.Fatal("native invalid dictionary", got, err)
		}
	}
	// NUL inside quoted OpenStep text and legacy encodings are separate, still
	// unqualified contexts. Detecting an encoding cannot silently authorize them.
	for _, data := range [][]byte{removalUTF16(`x{CFBundleExecutable=second;Ignored="a` + "\x00" + `b";}`)[2:], []byte{0xff}, []byte(`<?xml version="1.0" encoding="ISO-8859-1"?><dict/>`)} {
		if _, err := decodeRemovalPlist(data); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unqualified representation became fallback", err)
		}
	}
	for name, text := range map[string]string{
		"input":                strings.Repeat("a", maxBundlePlist/2+1),
		"decoded":              strings.Repeat("水", maxBundlePlist/3+1),
		"depth":                strings.Repeat(`<array>`, 33) + strings.Repeat(`</array>`, 33),
		"invalid-prefix-depth": ";" + strings.Repeat("{", 33),
		"values":               `<array>` + strings.Repeat(`<true/>`, maxBundlePlistValues) + `</array>`,
	} {
		t.Run(name, func(t *testing.T) {
			data := removalUTF16("x" + text)[2:]
			var limit *bundlePlistLimitError
			if _, err := decodeRemovalPlist(data); !errors.As(err, &limit) || !errors.Is(err, ErrFormat) {
				t.Fatal("conversion lost resource bound", err)
			}
			app := testBundle(t)
			main := readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))
			bundleFile(t, app, "Contents/Info.plist", data)
			bundleFile(t, app, bundleResourcesPath, []byte("unchanged envelope"))
			err := RemoveSignature(context.Background(), app)
			if name == "input" {
				if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "input exceeds memory limit") {
					t.Fatal("acquisition size limit", err)
				}
			} else if !errors.As(err, &limit) {
				t.Fatal("interpretation limit authorized removal", err)
			}
			if !bytes.Equal(data, readTestFile(t, filepath.Join(app, "Contents/Info.plist"))) || !bytes.Equal(main, readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))) || string(readTestFile(t, filepath.Join(app, bundleResourcesPath))) != "unchanged envelope" {
				t.Fatal("limit mutated bundle")
			}
		})
	}
}
