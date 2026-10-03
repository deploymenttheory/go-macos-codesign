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
		[]byte(`<?xml encoding="ISO-8859-1"?>{CFBundleExecutable=second;}`),
		[]byte("<?xml encoding=\"shift_jis\"?><string>\x81\x7f\x82\xa0</string>\xfc"),
		[]byte("<?xml encoding=\"cp932\"?><string>\x81\xad</string>"),
		[]byte(`{x=(a,b);}`), []byte("bplist00"),
		{0xff, 0xfe, '{', 0, '}', 0}, {0, 0, 0xfe, 0xff, 0, 0, 0, 0},
	} {
		f.Add(seed)
	}
	f.Add([]byte("<?xml encoding=\"euc-jp\"?><string>\xa4\x22\x8e\x3f</string>"))
	f.Add([]byte("<?xml encoding=\"euc-jp\"?><string>ok</string>\x8f\xa2\xaf"))

	f.Add([]byte("<?xml encoding=\"iso-2022-jp\"?><string>\x1b$B\x24\x22\x1b(B</string>"))
	f.Add([]byte("<?xml encoding=\"iso-2022-jp\"?><string>ok</string>\x1b$(D\xa2"))

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
