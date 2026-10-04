package codesign

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRemovalISO2022ExtensionsNativeReplay(t *testing.T) {
	names := []string{"iso-2022-jp-1", "iso_2022_jp_1", "iso2022jp1", "iso-2022-jp-2", "iso_2022_jp_2", "iso2022jp2", "csiso2022jp2"}
	states := []string{"all-defined-ascii", "all-defined-roman", "all-defined-kana", "all-defined-jis0208", "all-defined-jis0212", "all-defined-gb2312", "all-defined-ksc5601", "all-defined-latin", "all-defined-greek", "eof-state-ascii", "eof-state-roman", "eof-state-kana", "eof-state-jis0208", "eof-state-jis0212", "eof-state-gb2312", "eof-state-ksc5601", "eof-state-latin", "eof-state-greek", "eof-state-roman-h", "eof-state-jis1978", "eof-state-jis1990", "eof-state-ascii-b", "eof-state-latin-designated", "eof-state-greek-designated", "control-ascii-nul-body", "control-ascii-si-body", "control-ascii-so-tail", "control-jis0208-cr-body", "control-jis0212-lf-body", "control-roman-cr-roman-body", "control-roman-lf-roman-body", "control-ascii-high80-body", "control-ascii-highff-tail", "control-jis0208-mid-pair-body", "control-latin-ss2-return-body", "control-greek-ss2-repeat-body", "control-latin-ss2-redesignate-body", "control-greek-newline-clears-g2-body", "control-latin-ss2-g0-switch-body", "buffer-ascii-503-ascii-b", "buffer-ascii-504-ascii-b", "buffer-ascii-505-ascii-b", "buffer-jis0208-503-ascii-b", "buffer-jis0208-504-ascii-b", "buffer-jis0208-505-ascii-b", "unicode-executable", "declared-openstep", "bom-priority", "mixed-case", "boundary-transitions"}
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
	if len(wanted) != 2100 {
		t.Fatal("incomplete native inventory")
	}
	replayRemovalPlists(t, "plist-iso2022-extensions.json", "probe-removal-plist-interpretation.go", wanted)
}

func TestRemovalISO2022ExtensionsLimitsDoNotMutate(t *testing.T) {
	for _, name := range []string{"iso-2022-jp-1", "iso-2022-jp-2"} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(`<?xml encoding="`+name+`"?><string>`+"\x1b$B"), bytes.Repeat([]byte{0x24, 0x22}, maxBundlePlist/3)...)
			data = append(data, []byte("\x1b(B</string>")...)
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
