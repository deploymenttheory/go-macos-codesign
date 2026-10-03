package codesign

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestRemovalPlistEncodingNativeReplay(t *testing.T) {
	states := []string{"bom-only-le", "bom-only-be"}
	for _, endian := range []string{"le", "be"} {
		for _, kind := range []string{"xml", "openstep", "declared", "mismatch"} {
			states = append(states, kind+"-"+endian+"-bom")
		}
		for _, kind := range []string{"odd", "surrogate-tail", "surrogate-d800", "surrogate-dc00", "truncated"} {
			states = append(states, kind+"-"+endian)
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
	replayRemovalPlists(t, "plist-encodings.json", "probe-removal-plist-interpretation.go", wanted)
}

func removalUTF16(s string) []byte {
	b := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func TestRemovalPlistEncodingBoundaries(t *testing.T) {
	text := `<plist><dict><key>CFBundleExecutable</key><string>é水😀</string></dict></plist>`
	values, err := decodeRemovalPlist(removalUTF16(text))
	if err != nil || values["CFBundleExecutable"] != "é水😀" {
		t.Fatal(values, err)
	}
	if _, err := decodeBundlePlist(removalUTF16(text)); err == nil {
		t.Fatal("strict parser changed")
	}
	if got, err := decodeRemovalPlist(removalUTF16(text)[2:]); err != nil || len(got) != 0 {
		t.Fatal("unmarked XML native fallback", got, err)
	}
	for _, data := range [][]byte{{0xff}, removalUTF16("a\x00b")} {
		if _, err := decodeRemovalPlist(data); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unqualified representation redirected removal", err)
		}
	}
	var limit *bundlePlistLimitError
	if _, err := decodeRemovalPlist(removalUTF16(strings.Repeat("水", maxBundlePlist/3+1))); !errors.As(err, &limit) {
		t.Fatal("expanded text escaped resource limit", err)
	}
	// Encoding cannot bypass the existing structural budgets.
	for _, text := range []string{strings.Repeat("(", 33) + strings.Repeat(")", 33), `<plist><array>` + strings.Repeat(`<true/>`, maxBundlePlistValues) + `</array></plist>`} {
		if _, err := decodeRemovalPlist(removalUTF16(text)); !errors.As(err, &limit) {
			t.Fatal("encoded complexity escaped resource limit", err)
		}
	}
	data := removalUTF16(text)
	before := bytes.Clone(data)
	_, _ = decodeRemovalPlist(data)
	if !bytes.Equal(data, before) {
		t.Fatal("interpretation mutated original bytes")
	}
}
