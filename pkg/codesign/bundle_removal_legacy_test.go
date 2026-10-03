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

func TestRemovalPlistLegacyNativeReplay(t *testing.T) {
	names := []string{"us-ascii", "ascii", "ansi_x3.4-1968", "iso-8859-1", "iso_8859-1", "latin1", "latin-1", "iso_8859-1:1987", "l1", "koi8-r", "koi8-u", "x-mac-cyrillic"}
	invalid := []string{"iso-8859-3", "iso-8859-6", "iso-8859-7", "iso-8859-8", "iso-8859-11"}
	for _, n := range []int{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16} {
		names = append(names, fmt.Sprintf("iso-8859-%d", n))
	}
	for _, n := range []int{874, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258} {
		for _, prefix := range []string{"windows-", "cp"} {
			name := fmt.Sprintf("%s%d", prefix, n)
			names = append(names, name)
			invalid = append(invalid, name)
		}
	}
	for _, n := range []int{437, 850, 852, 855, 860, 862, 863, 865, 866} {
		names = append(names, fmt.Sprintf("ibm%d", n))
	}
	states := []string{"single-quote", "uppercase-name", "substring-attribute", "space-before-equals", "space-after-equals", "uppercase-keyword", "leading-space", "first-declaration", "utf8-alias", "utf8-invalid-body", "utf8-invalid-tail", "utf8-no-declaration-tail", "ignored-invalid-body", "bom-legacy", "bom-unknown", "bom-macroman", "bom-multibyte", "macintosh", "mac", "macroman", "x-mac-roman"}
	for _, name := range names {
		states = append(states, "valid-"+strings.ReplaceAll(name, ":", "%3a"))
	}
	for _, name := range invalid {
		states = append(states, "invalid-body-"+name, "invalid-tail-"+name)
	}
	if len(names) != 55 || len(states) != 126 {
		t.Fatal("incomplete native inventory")
	}
	wanted := map[string]bool{}
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, location := range []string{"ordinary", "platform"} {
			for _, state := range states {
				wanted[shape+"/"+location+"-"+state] = true
			}
		}
	}
	replayRemovalPlists(t, "plist-legacy.json", "probe-removal-plist-interpretation.go", wanted)
}

func TestRemovalLegacyLimitsDoNotMutate(t *testing.T) {
	data := append([]byte(`<?xml encoding="windows-1252"?><string>`), bytes.Repeat([]byte{0x80}, maxBundlePlist/3)...)
	data = append(data, []byte(`</string>`)...)
	app := testBundle(t)
	main := readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))
	bundleFile(t, app, "Contents/Info.plist", data)
	bundleFile(t, app, bundleResourcesPath, []byte("unchanged envelope"))
	err := RemoveSignature(context.Background(), app)
	var limit *bundlePlistLimitError
	if !errors.As(err, &limit) {
		t.Fatal("conversion limit authorized removal", err)
	}
	if !bytes.Equal(data, readTestFile(t, filepath.Join(app, "Contents/Info.plist"))) || !bytes.Equal(main, readTestFile(t, filepath.Join(app, "Contents/MacOS/hello"))) || string(readTestFile(t, filepath.Join(app, bundleResourcesPath))) != "unchanged envelope" {
		t.Fatal("conversion limit mutated bundle")
	}
}
