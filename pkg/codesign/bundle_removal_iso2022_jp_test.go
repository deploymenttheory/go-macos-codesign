package codesign

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRemovalISO2022JPNativeReplay(t *testing.T) {
	names := []string{"iso-2022-jp", "iso_2022_jp", "iso2022jp", "csiso2022jp", "cp50221", "windows-50221"}
	states := []string{"all-defined-ascii", "all-defined-roman", "all-defined-kana", "all-defined-jis0208", "all-defined-jis0212", "terminal-state-ascii", "terminal-state-roman", "terminal-state-kana", "terminal-state-jis0208", "terminal-state-jis0212", "buffer-ascii-503", "buffer-jis-503", "buffer-ascii-504", "buffer-jis-504", "buffer-ascii-505", "buffer-jis-505", "all-transitions", "eof-state-ascii", "eof-state-roman", "eof-state-kana", "eof-state-jis0208", "eof-state-jis0212", "eof-state-ascii-b", "eof-state-ascii-h", "eof-state-kana-right", "eof-state-jis1978", "eof-state-jis-d", "high-bytes", "unknown-escapes", "literal-escape-eof", "literal-prefix-eof", "invalid-kana-body", "invalid-kana-tail", "invalid-jis-body", "invalid-jis-tail", "low-0212-body", "low-0212-tail", "undefined-jis-body", "undefined-jis-tail", "incomplete-jis-tail", "escape-mid-pair", "jis-newline", "unreset-jis-tail", "unreset-0212-tail", "shift-controls", "state-at-markup", "unicode-executable", "declared-openstep", "bom-priority", "mixed-case", "boundary-transitions"}
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
	if len(wanted) != 1836 {
		t.Fatal("incomplete native inventory")
	}
	replayRemovalPlists(t, "plist-iso2022-jp.json", "probe-removal-plist-interpretation.go", wanted)
}

func TestRemovalISO2022JPLimitsDoNotMutate(t *testing.T) {
	for _, name := range []string{"iso-2022-jp", "windows-50221"} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(`<?xml encoding="`+name+`"?><string>`), bytes.Repeat([]byte{0xff}, maxBundlePlist/2)...)
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
