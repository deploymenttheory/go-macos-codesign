package plist_test

import (
	"bytes"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/plist"
)

// Keep codesign's removal-policy fuzz target too: callers have different error
// contracts. This target checks both public bounded parsers and input ownership.
func FuzzDecode(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`<plist><dict><key>x</key><string>y</string></dict></plist>`),
		[]byte(`<array><false/><string>&#0;</string></array>`),
		[]byte("<?xml encoding=\"windows-1252\"?><string>\x80</string>\x81"),
		[]byte("<?xml xencoding=\"ISO-8859-1\"?><string>\xff</string>"),
		[]byte(`{x=(a,b);}`), []byte("bplist00"),
		{0xff, 0xfe, '{', 0, '}', 0}, {0, 0, 0xfe, 0xff, 0, 0, 0, 0},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > plist.MaxSize {
			return
		}
		before := bytes.Clone(data)
		_, _ = plist.Decode(data)
		_, _ = plist.DecodeDictionary(data)
		if !bytes.Equal(before, data) {
			t.Fatal("parser changed its input")
		}
	})
}
