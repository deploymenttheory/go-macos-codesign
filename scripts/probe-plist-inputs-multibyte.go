//go:build ignore

// Research-only native plist inputs; never use the production decoder as oracle.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func eucJPInputs() []input {
	var corpus struct {
		Codecs []struct {
			Name  string
			Table int
		}
		Tables []struct{ Singles, Pairs []*string }
	}
	must(json.Unmarshal(read("testdata/bundle-removal/plist-euc-jp-values.json"), &corpus))
	const body = `<dict><key>CFBundleExecutable</key><string>second</string><key>value</key><string><![CDATA[%s]]></string></dict>`
	var result []input
	for _, c := range corpus.Codecs {
		decl := `<?xml version="1.0" encoding="` + c.Name + `"?>`
		var valid []byte
		for b, v := range corpus.Tables[c.Table].Singles {
			if v != nil {
				valid = append(valid, byte(b), '|')
			}
		}
		for pair, v := range corpus.Tables[c.Table].Pairs {
			if pair>>8 >= 128 && v != nil {
				valid = append(valid, byte(pair>>8), byte(pair), '|')
			}
		}
		result = append(result, input{"all-defined-" + c.Name, []byte(decl + fmt.Sprintf(body, string(valid)) + string(valid)), true})
		for _, tc := range []struct {
			name, value, tail string
			valid             bool
		}{
			{"variant-mappings", "\\~\xa1\xc1\xa1\xdd\xa1\xef\xa1\xf1\xa1\xf2\xa2\xcc", "", true},
			{"halfwidth-composition", "\x8e\xb6\x8e\xde\x8e\xca\x8e\xdf", "", true},
			{"extension-mappings", "\xa0\x00\xa0\xff\xad\xa1\xf5\x32", "", true},
			{"low-trail-body", "\xa4\x22\x8e\x00", "", true},
			{"low-trail-tail", "ok", "\xa4\x22\x8e\x00", true},
			{"invalid-single-body", "\x80", "", false},
			{"invalid-single-tail", "ok", "\x80", false},
			{"undefined-pair-body", "\xf5\xa1", "", false},
			{"undefined-pair-tail", "ok", "\xf5\xa1", false},
			{"invalid-trail-body", "\xa1\xff", "", false},
			{"invalid-trail-tail", "ok", "\xa1\xff", false},
			{"triple-body", "\x8f\xa2\xaf", "", false},
			{"triple-tail", "ok", "\x8f\xa2\xaf", false},
			{"incomplete-pair-tail", "ok", "\xa4", false},
			{"incomplete-kana-tail", "ok", "\x8e", false},
			{"incomplete-triple-tail", "ok", "\x8f\xa2", false},
			{"lead-at-markup", "\xa4", "", false},
			{"valid-pair-tail", "ok", "\xa4\xa2", true},
			{"bom-scalar-only", "\x8e\x3f", "", true},
			{"bom-scalar-leading", "\x8e\x3fx", "", true},
			{"bom-scalar-interior", "x\x8e\x3fy", "", true},
			{"bom-scalar-repeated", "\x8e\x3f\x8e\x3f", "", true},
		} {
			result = append(result, input{tc.name + "-" + c.Name, []byte(decl + fmt.Sprintf(body, tc.value) + tc.tail), tc.valid})
		}
		result = append(result, input{"unicode-executable-" + c.Name, []byte(decl + strings.Replace(fmt.Sprintf(body, "ok"), "second", "\xa4\xa2", 1)), true})
		result = append(result, input{"bom-entity-" + c.Name, []byte(decl + strings.Replace(fmt.Sprintf(body, "ok"), "second", "&#xfeff;second", 1)), true})
		result = append(result, input{"bom-cdata-joined-" + c.Name, []byte(decl + strings.Replace(fmt.Sprintf(body, "ok"), "second", "<![CDATA[\x8e\x3f]]>second", 1)), true})
		result = append(result, input{"bom-key-" + c.Name, []byte(decl + strings.Replace(fmt.Sprintf(body, "ok"), "CFBundleExecutable", "\x8e\x3fCFBundleExecutable", 1)), true})
		result = append(result, input{"bom-executable-" + c.Name, []byte(decl + strings.Replace(fmt.Sprintf(body, "ok"), "second", "\x8e\x3fsecond", 1)), true})
		result = append(result, input{"declared-openstep-" + c.Name, []byte(decl + `{CFBundleExecutable=second;}`), false})
		result = append(result, input{"bom-priority-" + c.Name, []byte("\xef\xbb\xbf" + decl + fmt.Sprintf(body, "あ😀")), true})
		result = append(result, input{"mixed-case-" + c.Name, []byte(strings.Replace(decl, c.Name, strings.ToUpper(c.Name), 1) + fmt.Sprintf(body, "\xa4\xa2")), true})
	}
	return result
}

func shiftJISInputs() []input {
	var corpus struct {
		Codecs []struct {
			Name  string
			Table int
		}
		Tables []struct{ Singles, Pairs []*string }
	}
	must(json.Unmarshal(read("testdata/bundle-removal/plist-shift-jis-values.json"), &corpus))
	const body = `<dict><key>CFBundleExecutable</key><string>second</string><key>value</key><string><![CDATA[%s]]></string></dict>`
	var result []input
	for _, c := range corpus.Codecs {
		decl := `<?xml version="1.0" encoding="` + c.Name + `"?>`
		var valid []byte
		for b, v := range corpus.Tables[c.Table].Singles {
			if v != nil {
				valid = append(valid, byte(b), '|')
			}
		}
		for pair, v := range corpus.Tables[c.Table].Pairs {
			lead := pair >> 8
			if (lead >= 0x81 && lead <= 0x9f || lead >= 0xe0 && lead <= 0xfc) && v != nil {
				valid = append(valid, byte(lead), byte(pair), '|')
			}
		}
		result = append(result, input{"all-defined-" + c.Name, []byte(decl + fmt.Sprintf(body, string(valid)) + string(valid)), true})
		for _, tc := range []struct {
			name, value, tail string
			valid             bool
		}{
			{"variant-mappings", "\\~\x81\x60\x81\x61\x81\x7c\x81\x91\x81\x92\x81\xca", "", true},
			{"halfwidth-composition", "\xb6\xde\xca\xdf", "", true},
			{"invalid-single-body", "\x80", "", false},
			{"invalid-single-tail", "ok", "\x80", false},
			{"accepted-del-trail-body", "\x81\x7f", "", true},
			{"accepted-del-trail-tail", "ok", "\x81\x7f", true},
			{"invalid-trail-body", "\x81\x3f", "", false},
			{"invalid-trail-tail", "ok", "\x81\x3f", false},
			{"undefined-pair-body", "\x81\xad", "", false},
			{"undefined-pair-tail", "ok", "\x81\xad", false},
			{"incomplete-tail-low", "ok", "\x81", false},
			{"incomplete-tail-high", "ok", "\xfc", false},
			{"lead-at-markup", "\x81", "", false},
			{"valid-pair-tail", "ok", "\x82\xa0", true},
		} {
			result = append(result, input{tc.name + "-" + c.Name, []byte(decl + fmt.Sprintf(body, tc.value) + tc.tail), tc.valid})
		}
		result = append(result, input{"unicode-executable-" + c.Name, []byte(decl + strings.Replace(fmt.Sprintf(body, "ok"), "second", "\x82\xa0", 1)), true})
		result = append(result, input{"declared-openstep-" + c.Name, []byte(decl + `{CFBundleExecutable=second;}`), false})
		result = append(result, input{"bom-priority-" + c.Name, []byte("\xef\xbb\xbf" + decl + fmt.Sprintf(body, "あ😀")), true})
		result = append(result, input{"mixed-case-" + c.Name, []byte(strings.Replace(decl, c.Name, strings.ToUpper(c.Name), 1) + fmt.Sprintf(body, "\x82\xa0")), true})
	}
	return result
}
