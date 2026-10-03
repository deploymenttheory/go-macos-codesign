package codesign

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRemovalEUCJPNativeReplay(t *testing.T) {
	names := []string{"euc-jp", "euc_jp", "eucjp", "cseucpkdfmtjapanese", "extended_unix_code_packed_format_for_japanese", "x-euc-jp", "cp51932", "windows-51932"}
	states := []string{"all-defined", "variant-mappings", "halfwidth-composition", "extension-mappings", "low-trail-body", "low-trail-tail", "invalid-single-body", "invalid-single-tail", "undefined-pair-body", "undefined-pair-tail", "invalid-trail-body", "invalid-trail-tail", "triple-body", "triple-tail", "incomplete-pair-tail", "incomplete-kana-tail", "incomplete-triple-tail", "lead-at-markup", "valid-pair-tail", "bom-scalar-only", "bom-scalar-leading", "bom-scalar-interior", "bom-scalar-repeated", "unicode-executable", "bom-entity", "bom-cdata-joined", "bom-key", "bom-executable", "declared-openstep", "bom-priority", "mixed-case"}
	wanted := map[string]bool{}
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, location := range []string{"ordinary", "platform"} {
			for _, name := range names {
				for _, state := range states {
					wanted[shape+"/"+location+"-"+state+"-"+name] = true
				}
			}
		}
	}
	if len(wanted) != 1488 {
		t.Fatal("incomplete native inventory")
	}
	replayRemovalPlists(t, "plist-euc-jp.json", "probe-removal-plist-interpretation.go", wanted)
}

func TestRemovalEUCJPLimitsDoNotMutate(t *testing.T) {
	for _, name := range []string{"euc-jp", "windows-51932"} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(`<?xml encoding="`+name+`"?><string>`), bytes.Repeat([]byte{0xa4, 0xa2}, maxBundlePlist/3)...)
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
		})
	}
}
