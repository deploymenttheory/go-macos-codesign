//go:build ignore

// Research-only native plist inputs; never use the production decoder as oracle.
package main

import (
	"encoding/binary"
	"howett.net/plist"
	"strings"
)

type input struct {
	name       string
	data       []byte
	executable bool
}

func inputs() []input {
	var result []input
	add := func(name, data string, executable bool) {
		result = append(result, input{name, []byte(data), executable})
	}
	valid := `<plist><dict><key>CFBundleExecutable</key><string>second</string></dict></plist>`
	add("xml-valid", valid, true)
	add("xml-duplicate", strings.Replace(valid, "<dict>", "<dict><key>CFBundleExecutable</key><string>first</string>", 1), true)
	add("xml-no-wrapper", strings.TrimSuffix(strings.TrimPrefix(valid, "<plist>"), "</plist>"), true)
	add("xml-trailing", valid+"garbage", true)
	add("xml-second-root", valid+"<plist><dict/></plist>", true)
	add("xml-array", `<plist><array><string>first</string></array></plist>`, false)
	add("xml-string", `<plist><string>first</string></plist>`, false)
	add("xml-broken", strings.TrimSuffix(valid, "</dict></plist>"), false)
	add("xml-unknown", strings.Replace(valid, "<dict>", "<dict><key>Ignored</key><unknown/>", 1), false)
	add("xml-integer-overflow", strings.Replace(valid, "<dict>", "<dict><key>Ignored</key><integer>999999999999999999999999999999999</integer>", 1), false)
	add("xml-missing-value", `<plist><dict><key>CFBundleExecutable</key></dict></plist>`, false)
	add("openstep", `{CFBundleExecutable=second;}`, true)
	add("openstep-duplicate", `{CFBundleExecutable=first;CFBundleExecutable=second;}`, true)
	add("openstep-comments", `/*head*/ {CFBundleExecutable /*key*/ = "second"; Ignored = (one,two);}`, true)
	add("openstep-no-semicolon", `{CFBundleExecutable=second}`, false)
	add("openstep-trailing", `{CFBundleExecutable=second;}trailing`, false)
	add("openstep-array", `(first,second)`, false)
	add("openstep-strings", `CFBundleExecutable=second;`, true)
	add("openstep-escape", `{CFBundleExecutable="seco\156d";}`, true)
	add("openstep-unicode", `{CFBundleExecutable="seco\U006ed";}`, true)
	add("random", "not a plist", false)
	add("spaces", " \n\t", false)
	add("binary-truncated", "bplist00garbage", false)
	for _, item := range []struct {
		name       string
		value      any
		executable bool
	}{
		{"binary-dict", map[string]any{"CFBundleExecutable": "second"}, true},
		{"binary-array", []any{"first"}, false}, {"binary-string", "first", false},
		{"binary-uid", map[string]any{"CFBundleExecutable": "second", "Ignored": plist.UID(1)}, true},
		{"binary-uid-overflow", map[string]any{"CFBundleExecutable": "second", "Ignored": plist.UID(1 << 32)}, false},
	} {
		b, e := plist.Marshal(item.value, plist.BinaryFormat)
		must(e)
		result = append(result, input{item.name, b, item.executable})
	}
	str := func(s string) []byte {
		if len(s) < 15 {
			return append([]byte{0x50 | byte(len(s))}, s...)
		}
		return append([]byte{0x5f, 0x10, byte(len(s))}, s...)
	}
	result = append(result, input{"binary-duplicate", rawBinary([][]byte{{0xd2, 1, 1, 2, 3}, str("CFBundleExecutable"), str("first"), str("second")}), true})
	result = append(result, input{"binary-cycle", rawBinary([][]byte{{0xd1, 1, 2}, str("CFBundleExecutable"), {0xa1, 2}}), false})
	return result
}

func rawBinary(objects [][]byte) []byte {
	b := []byte("bplist00")
	var offsets []byte
	for _, o := range objects {
		offsets = append(offsets, byte(len(b)))
		b = append(b, o...)
	}
	table := len(b)
	b = append(b, offsets...)
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 1, 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[24:], uint64(table))
	return append(b, trailer...)
}
