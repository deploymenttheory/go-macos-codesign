//go:build ignore

// Capture removal selection independently with the host's codesign binary.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"howett.net/plist"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func run(name string, args ...string) []byte {
	b, e := exec.Command(name, args...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s %v: %v: %s", name, args, e, b))
	}
	return b
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }

type observation struct {
	SHA256    string
	SameInode bool `json:"same_inode"`
	Signature bool
}
type record struct {
	Shape, State, Base, Info, Platform, Selected string
	Files                                        map[string][]byte
	Directories                                  []string
	Links                                        map[string]string
	Status                                       int
	Output                                       string
	Envelope                                     bool
	After                                        map[string]observation
}

func main() {
	out := flag.String("out", "testdata/bundle-removal/plist-interpretation.json", "capture output")
	profile := flag.String("profile", "interpretation", "interpretation, encodings, utf32, utf32-grammar, xml-characters, unmarked or legacy")
	flag.Parse()
	selectedInputs := inputs()
	if *profile == "encodings" {
		selectedInputs = encodingInputs()
	} else if *profile == "utf32" {
		selectedInputs = utf32Inputs(false)
	} else if *profile == "utf32-grammar" {
		selectedInputs = utf32Inputs(true)
	} else if *profile == "xml-characters" {
		selectedInputs = xmlCharacterInputs()
	} else if *profile == "unmarked" {
		selectedInputs = unmarkedInputs()
	} else if *profile == "legacy" {
		selectedInputs = legacyInputs()
	} else if *profile != "interpretation" {
		panic("unknown profile")
	}
	d, e := os.MkdirTemp("", "plist-interpretation-")
	must(e)
	defer os.RemoveAll(d)
	var cases []record
	for _, shape := range []string{"app", "flat-framework", "framework"} {
		for _, input := range selectedInputs {
			for _, location := range []string{"ordinary", "platform"} {
				state := location + "-" + input.name
				func() {
					p := filepath.Join(d, "A.app")
					base := "Contents/"
					info := base + "Info.plist"
					main := base + "MacOS/"
					if shape != "app" {
						p = filepath.Join(d, "A.framework")
						base = ""
						if shape == "framework" {
							base = "Versions/A/"
						}
						info = base + "Resources/Info.plist"
						main = base
					}
					platform := strings.TrimSuffix(info, ".plist") + "-macos.plist"
					tc := record{Shape: shape, State: state, Base: base, Info: info, Platform: platform, Directories: []string{filepath.ToSlash(filepath.Dir(info)), main, base + "_CodeSignature"}, Links: map[string]string{}, After: map[string]observation{}}
					plist := func(n string) []byte {
						return []byte("<plist><dict><key>CFBundleExecutable</key><string>" + n + "</string></dict></plist>")
					}
					tc.Files = map[string][]byte{info: plist("normal"), main + "normal": []byte("normal"), main + "first": []byte("first"), main + "second": []byte("second")}
					selectedInfo := info
					if location == "platform" {
						selectedInfo = platform
					}
					tc.Files[selectedInfo] = input.data
					tc.Selected = selectedInfo
					if input.executable {
						tc.Selected = main + "second"
					}
					if input.name == "binary-duplicate" {
						tc.Selected = main + "first"
					}
					for _, dir := range tc.Directories {
						must(os.MkdirAll(filepath.Join(p, dir), 0755))
					}
					if shape == "framework" {
						tc.Links = map[string]string{"Versions/Current": "A", "Resources": "Versions/Current/Resources", "A": "Versions/Current/A"}
						for n, v := range tc.Links {
							must(os.Symlink(v, filepath.Join(p, n)))
						}
					}
					before := map[string]os.FileInfo{}
					for n, b := range tc.Files {
						f := filepath.Join(p, n)
						must(os.WriteFile(f, b, 0755))
						run("/usr/bin/xattr", "-w", "com.apple.cs.CodeDirectory", "attached signature", f)
						run("/usr/bin/xattr", "-w", "user.codesign-control", "unchanged", f)
						before[n], e = os.Stat(f)
						must(e)
					}
					envelope := filepath.Join(p, base+"_CodeSignature/CodeResources")
					must(os.WriteFile(envelope, []byte("envelope"), 0644))
					output, err := exec.Command("/usr/bin/codesign", "--remove-signature", p).CombinedOutput()
					if err != nil || len(output) != 0 {
						panic(fmt.Sprintf("%s/%s: %v: %s", shape, state, err, output))
					}
					for n, b := range tc.Files {
						f := filepath.Join(p, n)
						attrs := strings.Fields(string(run("/usr/bin/xattr", f)))
						present := false
						for _, attr := range attrs {
							if attr == "com.apple.cs.CodeDirectory" {
								present = true
							}
						}
						after, e := os.Stat(f)
						must(e)
						tc.After[n] = observation{hash(read(f)), os.SameFile(before[n], after), present}
						if tc.After[n].SHA256 != hash(b) || !tc.After[n].SameInode || present != (n != tc.Selected) {
							panic(fmt.Sprintf("%s/%s unexpected mutation: %s %#v", shape, state, n, tc.After[n]))
						}
						if string(run("/usr/bin/xattr", "-p", "user.codesign-control", f)) != "unchanged\n" {
							panic("control attribute changed")
						}
					}
					_, e = os.Stat(envelope)
					if !os.IsNotExist(e) {
						panic(fmt.Sprintf("envelope retained: %v", e))
					}
					cases = append(cases, tc)
					must(os.RemoveAll(p))
				}()
			}
		}
	}
	result := map[string]any{"schema": 1, "macos": string(run("/usr/bin/sw_vers")), "codesign_sha256": hash(read("/usr/bin/codesign")), "source_sha256": hash(read("scripts/probe-removal-plist-interpretation.go")), "cases": cases}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	must(os.WriteFile(*out, append(b, '\n'), 0644))
	fmt.Println("Captured and checked", len(cases), "native plist-interpretation cases")
}

// Inputs use the independent native byte corpus, never the production decoder.
// Native codesign must confirm each predicted target and every mutation invariant.
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
	return cases
}

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
