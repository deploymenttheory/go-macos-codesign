package codesign

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRemovalShiftJISNativeReplay(t *testing.T) {
	names := []string{"shift_jis", "shift-jis", "sjis", "ms_kanji", "csshiftjis", "cp932", "windows-31j", "windows-932"}
	states := []string{"all-defined", "variant-mappings", "halfwidth-composition", "invalid-single-body", "invalid-single-tail", "accepted-del-trail-body", "accepted-del-trail-tail", "invalid-trail-body", "invalid-trail-tail", "undefined-pair-body", "undefined-pair-tail", "incomplete-tail-low", "incomplete-tail-high", "lead-at-markup", "valid-pair-tail", "unicode-executable", "declared-openstep", "bom-priority", "mixed-case"}
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
	if len(wanted) != 912 {
		t.Fatal("incomplete native inventory")
	}
	replayRemovalPlists(t, "plist-shift-jis.json", "probe-removal-plist-interpretation.go", wanted)
}

func TestRemovalShiftJISLimitsDoNotMutate(t *testing.T) {
	for _, name := range []string{"shift_jis", "cp932"} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(`<?xml encoding="`+name+`"?><string>`), bytes.Repeat([]byte{0xa1}, maxBundlePlist/3)...)
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

// Unicode removal does not relax signing/resource paths or portable path safety.
func TestRemovalUnicodeNameValidation(t *testing.T) {
	for _, name := range []string{"あ", "日本語", "é", "😀"} {
		if err := bundleRelativePathProfile(name, true); err != nil {
			t.Fatal(name, err)
		}
		if err := bundleRelativePath(name); !errors.Is(err, ErrUnsupported) {
			t.Fatal("strict path profile changed", name, err)
		}
	}
	for _, name := range []string{"../あ", "/あ", "a\\あ", "a:あ", "あ\x00", "あ\x7f", "あ.", "あ ", "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³", "\xff"} {
		if err := bundleRelativePathProfile(name, true); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unsafe removal path accepted", name, err)
		}
	}
}
