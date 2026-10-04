//go:build ignore

// Research-only native plist inputs; never use the production decoder as oracle.
package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

func unmarkedInputs() []input {
	xml := `<plist><dict><key>CFBundleExecutable</key><string>second</string><key>Ignored</key><string>é水😀</string></dict></plist>`
	text := `{CFBundleExecutable=second;Ignored="é水😀";}`
	literalXML := `{CFBundleExecutable=second;Ignored="<dict><key>CFBundleExecutable</key><string>first</string></dict>";}`
	var result []input
	for _, codec := range []string{"16le", "16be", "32le", "32be"} {
		var order binary.AppendByteOrder = binary.LittleEndian
		if strings.HasSuffix(codec, "be") {
			order = binary.BigEndian
		}
		encode := func(s string) []byte {
			var data []byte
			if strings.HasPrefix(codec, "16") {
				for _, u := range utf16.Encode([]rune(s)) {
					data = order.AppendUint16(data, u)
				}
			} else {
				for _, r := range s {
					data = order.AppendUint32(data, uint32(r))
				}
			}
			return data
		}
		for _, item := range []struct {
			name, text string
			executable bool
		}{
			{"xml", xml, false}, {"openstep", text, true}, {"padded-xml", " " + xml, true},
			{"prefixed-xml", "x" + xml, true}, {"strings", "xCFBundleExecutable=second;", true},
			{"comments", "x/*head*/" + text, true}, {"nul-prefix", "\x00" + text, true},
			{"double-bom", "x\ufeff" + xml, false},
			{"openstep-xml-literal", "x" + literalXML, true},
			{"declared", `x<?xml version="1.0" encoding="UTF-16"?>` + xml, true},
			{"mismatch", `x<?xml version="1.0" encoding="ISO-8859-1"?>` + xml, true},
		} {
			result = append(result, input{item.name + "-" + codec, encode(item.text), item.executable && codec == "16le"})
		}
		result = append(result, input{"odd-tail-" + codec, append(encode("x"+xml), 0xff), codec == "16le"})
		data := encode("x" + xml)
		if strings.HasPrefix(codec, "16") {
			data = order.AppendUint16(data, 0xd800)
		} else {
			data = order.AppendUint32(data, 0xd800)
		}
		result = append(result, input{"surrogate-tail-" + codec, data, codec == "16le"})
		result = append(result, input{"short-" + codec, encode(text)[:3], false})
	}
	for _, prefix := range [][]byte{{'x', 0}, {0, 'x'}, {0, 0}, {0xff, 0}, {0, 0xff}} {
		data := append([]byte{}, prefix...)
		for _, u := range utf16.Encode([]rune(xml)) {
			data = binary.LittleEndian.AppendUint16(data, u)
		}
		result = append(result, input{fmt.Sprintf("prefix-%x", prefix), data, true})
	}
	for _, data := range [][]byte{{0}, {'x', 0}, {0, 'x'}, {0, 0}, {'x', 0, 0}, {'{', 0, '}'}} {
		result = append(result, input{fmt.Sprintf("short-bytes-%x", data), data, false})
	}
	result = append(result, input{"openstep-xml-literal-utf8", []byte(literalXML), true})
	return result
}

func xmlCharacterInputs() []input {
	var result []input
	prefix := `<plist><dict><key>CFBundleExecutable</key><string>second</string><key>Ignored</key><string>`
	suffix := `</string></dict></plist>`
	for _, item := range []struct {
		name, value string
		valid       bool
	}{
		{"literal-controls", "\x00\x01\x08\x0b\x0c\x0e\x1f", true},
		{"literal-noncharacters", "\ufffe\uffff", true},
		{"literal-newlines", "a\rb\r\nc\nd", true},
		{"cdata", "<![CDATA[<>&\x00\x01\ufffe\uffff\r\n]]>", true},
		{"mixed", "a&amp;<![CDATA[<\x01]]>&#0;b", true},
		{"named", "&lt;&gt;&amp;&apos;&quot;", true},
		{"decimal", "&#0;&#1;&#8;&#11;&#12;&#14;&#31;", true},
		{"hex", "&#x0;&#x1;&#xFFFE;&#xffff;", true},
		{"supplementary", "&#x10000;&#128512;&#x10FFFF;", true},
		{"empty-entity", "&#;&#x;", true},
		{"surrogate-high", "&#xD800;", false},
		{"surrogate-low", "&#xDFFF;", false},
		{"scalar-overflow", "&#x110000;", false},
		{"integer-overflow", "&#4294967296;", false},
		{"unknown-entity", "&unknown;", false},
		{"uppercase-x", "&#X6e;", false},
		{"bad-digit", "&#xg;", false},
		{"missing-semicolon", "&#1", false},
		{"cdata-unclosed", "<![CDATA[bad", false},
		{"string-comment", "a<!--comment-->b", false},
		{"string-pi", "a<?instruction?>b", false},
		{"string-child", "a<string>b</string>", false},
	} {
		result = append(result, input{item.name, []byte(prefix + item.value + suffix), item.valid})
	}
	for _, item := range []struct {
		name, value string
		valid       bool
	}{
		{"key-entity", `<key>CFBundleExecu&#x74;able</key><string>second</string>`, true},
		{"key-cdata", `<key>CFBundle<![CDATA[Executable]]></key><string>second</string>`, true},
		{"key-controls", `<key>CFBundleExecutable</key><string>second</string><key>CFBundleExecutable` + "\x00\x01\ufffe" + `</key><string>first</string>`, true},
		{"duplicate-escaped-key", `<key>CFBundleExecutable</key><string>first</string><key>CFBundleExecu&#116;able</key><string>second</string>`, true},
		{"nested-strings", `<key>CFBundleExecutable</key><string>second</string><key>Ignored</key><array><string>` + "\x00\uffff" + `</string><dict><key>` + "\x01" + `</key><string><![CDATA[` + "\x0b" + `]]></string></dict></array>`, true},
		{"empty-strings", `<key>CFBundleExecutable</key><string>second</string><key/><string/><key>Ignored</key><string></string>`, true},
		{"mismatched-close", `<key>CFBundleExecutable</key><string>second</key>`, false},
		{"container-text", `<key>CFBundleExecutable</key><string>second</string>bad`, false},
	} {
		result = append(result, input{item.name, []byte(`<plist><dict>` + item.value + `</dict></plist>`), item.valid})
	}
	for _, endian := range []string{"le", "be"} {
		var order binary.AppendByteOrder = binary.LittleEndian
		bom := []byte{0xff, 0xfe}
		if endian == "be" {
			order, bom = binary.BigEndian, []byte{0xfe, 0xff}
		}
		data := append([]byte{}, bom...)
		for _, u := range utf16.Encode([]rune(prefix + "\x00\x01\ufffe\uffff\r\n" + suffix)) {
			data = order.AppendUint16(data, u)
		}
		result = append(result, input{"utf16-" + endian, data, true})
	}

	return result
}

func encodingInputs() []input {
	xml := `<plist><dict><key>CFBundleExecutable</key><string>second</string><key>Ignored</key><string>é水😀</string></dict></plist>`
	text := `{CFBundleExecutable=second;Ignored="é水😀";}`
	var result []input
	for _, endian := range []string{"le", "be"} {
		var order binary.AppendByteOrder = binary.LittleEndian
		bom := []byte{0xff, 0xfe}
		if endian == "be" {
			order, bom = binary.BigEndian, []byte{0xfe, 0xff}
		}
		encode := func(s string, mark bool) []byte {
			var data []byte
			if mark {
				data = append(data, bom...)
			}
			for _, u := range utf16.Encode([]rune(s)) {
				data = order.AppendUint16(data, u)
			}
			return data
		}
		for _, item := range []struct{ name, text string }{
			{"xml", xml}, {"openstep", text},
			{"declared", `<?xml version="1.0" encoding="UTF-16"?>` + xml},
			{"mismatch", `<?xml version="1.0" encoding="ISO-8859-1"?>` + xml},
		} {
			result = append(result, input{item.name + "-" + endian + "-bom", encode(item.text, true), true})
		}
		result = append(result, input{"odd-" + endian, append(encode(xml, true), 0xff), true})
		bad := encode(strings.Replace(xml, "é水😀", "", 1), true)
		bad = append(bad, order.AppendUint16(nil, 0xd800)...)
		result = append(result, input{"surrogate-tail-" + endian, bad, true})
		for _, unit := range []uint16{0xd800, 0xdc00} {
			prefix := encode(`<plist><dict><key>Ignored</key><string>`, true)
			prefix = order.AppendUint16(prefix, unit)
			prefix = append(prefix, encode(`</string><key>CFBundleExecutable</key><string>second</string></dict></plist>`, false)...)
			result = append(result, input{fmt.Sprintf("surrogate-%x-%s", unit, endian), prefix, false})
		}
		result = append(result, input{"truncated-" + endian, encode(`<plist><dict>`, true), false})
	}
	result = append(result, input{"bom-only-le", []byte{0xff, 0xfe}, false}, input{"bom-only-be", []byte{0xfe, 0xff}, false})
	return result
}

func utf32Inputs(grammar bool) []input {
	xml := `<plist><dict><key>CFBundleExecutable</key><string>second</string><key>Ignored</key><string>é水😀</string></dict></plist>`
	var result []input
	for _, endian := range []string{"le", "be"} {
		var order binary.AppendByteOrder = binary.LittleEndian
		bom := []byte{0xff, 0xfe, 0, 0}
		if endian == "be" {
			order, bom = binary.BigEndian, []byte{0, 0, 0xfe, 0xff}
		}
		encode := func(s string) []byte {
			data := append([]byte{}, bom...)
			for _, r := range s {
				data = order.AppendUint32(data, uint32(r))
			}
			return data
		}
		if grammar {
			for _, item := range []struct{ name, value string }{{"controls", "\x01\x08\x0b\x0c\x0e\x1f"}, {"noncharacters", "\ufffe\uffff"}, {"nul", "a\x00b"}} {
				result = append(result, input{item.name + "-" + endian, encode(strings.Replace(xml, "é水😀", item.value, 1)), true})
			}
			continue
		}
		for _, item := range []struct{ name, text string }{
			{"xml", xml}, {"openstep", `{CFBundleExecutable=second;Ignored="é水😀";}`},
			{"declared", `<?xml version="1.0" encoding="UTF-32"?>` + xml},
			{"mismatch", `<?xml version="1.0" encoding="ISO-8859-1"?>` + xml},
		} {
			result = append(result, input{item.name + "-" + endian, encode(item.text), true})
		}
		for n := 1; n <= 3; n++ {
			result = append(result, input{fmt.Sprintf("partial-%d-%s", n, endian), append(encode(xml), []byte{0xff, 0xff, 0xff}[:n]...), true})
			result = append(result, input{fmt.Sprintf("partial-only-%d-%s", n, endian), append(encode(""), []byte{0xff, 0xff, 0xff}[:n]...), false})
		}
		result = append(result, input{"scalar-boundaries-" + endian, encode(strings.Replace(xml, "é水😀", "\u007f\u0080\u07ff\u0800\ud7ff\ue000\ufffd\U00010000\U0010ffff", 1)), true})
		result = append(result, input{"openstep-controls-" + endian, encode("{CFBundleExecutable=second;Ignored=\"\x01\x08\x0b\x0c\x0e\x1f\ufffe\uffff\";}"), true})
		result = append(result, input{"xml-trailing-controls-" + endian, encode(xml + "\x01\x08\x0b\x0c\x0e\x1f\ufffe\uffff"), true})
		for _, scalar := range []uint32{0xd800, 0xdc00, 0x110000, 0xffffffff} {
			for _, tail := range []bool{false, true} {
				data := encode(`<plist><dict><key>Ignored</key><string>`)
				position := "inside"
				if tail {
					data = encode(xml)
					position = "tail"
				}
				data = order.AppendUint32(data, scalar)
				if !tail {
					data = append(data, encode(`</string><key>CFBundleExecutable</key><string>second</string></dict></plist>`)[4:]...)
				}
				result = append(result, input{fmt.Sprintf("invalid-%x-%s-%s", scalar, position, endian), data, false})
			}
		}
		result = append(result, input{"bom-only-" + endian, bom, false}, input{"truncated-" + endian, encode(`<plist><dict>`), false})
	}
	return result
}
