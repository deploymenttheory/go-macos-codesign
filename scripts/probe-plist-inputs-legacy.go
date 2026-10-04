//go:build ignore

// Research-only native plist inputs; never use the production decoder as oracle.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

func legacyInputs() []input {
	var corpus struct {
		Codecs []struct {
			Name    string
			Scalars []int32
		}
	}
	must(json.Unmarshal(read("testdata/bundle-removal/plist-legacy-values.json"), &corpus))
	const body = `<dict><key>CFBundleExecutable</key><string>second</string><key>value</key><string><![CDATA[%s]]></string></dict>`
	decl := func(name string) string { return `<?xml version="1.0" encoding="` + name + `"?>` }
	var cases []input
	for _, c := range corpus.Codecs {
		var valid []byte
		invalid := -1
		for b, r := range c.Scalars {
			if r >= 0 {
				valid = append(valid, byte(b))
			} else if invalid == -1 {
				invalid = b
			}
		}
		label := strings.ReplaceAll(c.Name, ":", "%3a")
		cases = append(cases, input{"valid-" + label, []byte(decl(c.Name) + fmt.Sprintf(body, string(valid)) + string(valid)), true})
		if invalid >= 0 {
			cases = append(cases,
				input{"invalid-body-" + label, []byte(decl(c.Name) + fmt.Sprintf(body, string([]byte{byte(invalid)}))), false},
				input{"invalid-tail-" + label, []byte(decl(c.Name) + fmt.Sprintf(body, "ASCII") + string([]byte{byte(invalid)})), false})
		}
	}
	for _, tc := range []struct {
		name, header, value, tail string
		valid                     bool
	}{
		{"single-quote", `<?xml encoding='ISO-8859-1'?>`, "\xe9", "", true},
		{"uppercase-name", decl("WiNdOwS-1252"), "\x80", "", true},
		{"substring-attribute", `<?xml xencoding="ISO-8859-1"?>`, "\xe9", "", true},
		{"space-before-equals", `<?xml encoding ="ISO-8859-1"?>`, "é水😀", "", true},
		{"space-after-equals", `<?xml encoding= "ISO-8859-1"?>`, "é水😀", "", true},
		{"uppercase-keyword", `<?xml ENCODING="ISO-8859-1"?>`, "é水😀", "", true},
		{"leading-space", " \n" + decl("ISO-8859-1"), "é水😀", "", true},
		{"first-declaration", `<?xml encoding="ISO-8859-1" encoding="windows-1252"?>`, "\x80", "", true},
		{"utf8-alias", decl("utf8"), "é水😀", "", true},
		{"utf8-invalid-body", decl("UTF-8"), "\xff", "", false},
		{"utf8-invalid-tail", decl("UTF-8"), "é水😀", "\xff", true},
		{"utf8-no-declaration-tail", "", "é水😀", "\xff", true},
		{"ignored-invalid-body", `<?xml encoding ="ISO-8859-1"?>`, "\xe9", "", false},
		{"bom-legacy", "\xef\xbb\xbf" + decl("ISO-8859-1"), "é水😀", "", true},
		{"bom-unknown", "\xef\xbb\xbf" + decl("not-a-codec"), "é水😀", "", true},
		{"bom-macroman", "\xef\xbb\xbf" + decl("macintosh"), "é水😀", "", true},
		{"bom-multibyte", "\xef\xbb\xbf" + decl("Shift_JIS"), "é水😀", "", true},
		{"macintosh", decl("macintosh"), "ASCII", "", false},
		{"mac", decl("mac"), "ASCII", "", false},
		{"macroman", decl("macroman"), "ASCII", "", false},
		{"x-mac-roman", decl("x-mac-roman"), "ASCII", "", false},
	} {
		cases = append(cases, input{tc.name, []byte(tc.header + fmt.Sprintf(body, tc.value) + tc.tail), tc.valid})
	}
	// A declaration keeps the native parser in XML even if the following bytes
	// are a valid OpenStep dictionary or scalar. Conversion must retain dispatch.
	const openstep = `{CFBundleExecutable=second;}`
	for _, tc := range []struct{ name, text string }{
		{"declared-openstep-utf8", decl("UTF-8") + openstep},
		{"declared-openstep-legacy", decl("ISO-8859-1") + openstep},
		{"declared-openstep-bom", "\xef\xbb\xbf" + decl("ISO-8859-1") + openstep},
		{"declared-openstep-quoted", decl("UTF-8") + `"` + openstep + `"`},
	} {
		cases = append(cases, input{tc.name, []byte(tc.text), false})
	}
	for _, width := range []int{2, 4} {
		data := []byte{0xff, 0xfe}
		if width == 4 {
			data = append(data, 0, 0)
		}
		for _, r := range decl("ISO-8859-1") + openstep {
			if width == 2 {
				data = binary.LittleEndian.AppendUint16(data, uint16(r))
			} else {
				data = binary.LittleEndian.AppendUint32(data, uint32(r))
			}
		}
		cases = append(cases, input{fmt.Sprintf("declared-openstep-utf%d", width*8), data, false})
	}
	return cases
}
