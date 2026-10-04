//go:build ignore

// Research-only native plist inputs; never use the production decoder as oracle.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func iso2022ExtensionInputs() []input {
	var corpus struct {
		Codecs []struct {
			Name  string
			Table int
		}
		Tables []struct {
			States []struct {
				Name    string
				Prefix  []byte
				Mapping int
			}
			Mappings []struct{ Values []*string }
		}
	}
	must(json.Unmarshal(read("testdata/bundle-removal/plist-iso2022-extensions-values.json"), &corpus))
	var streams struct {
		Cases []struct {
			Name   string
			Input  []byte
			Status int
		}
	}
	must(json.Unmarshal(read("testdata/bundle-removal/plist-iso2022-extension-streams.json"), &streams))
	observed := map[string]input{}
	for _, c := range streams.Cases {
		observed[c.Name] = input{c.Name, c.Input, c.Status == 0}
	}
	const body = `<dict><key>CFBundleExecutable</key><string>second</string><key>value</key><string><![CDATA[%s]]></string></dict>`
	var result []input
	for _, c := range corpus.Codecs {
		decl := `<?xml version="1.0" encoding="` + c.Name + `"?>`
		table := corpus.Tables[c.Table]
		for i, st := range table.States[:9] {
			v := append([]byte{}, st.Prefix...)
			if i < 3 || i > 6 {
				for b := 0x21; b < 0x7f; b++ {
					if table.Mappings[st.Mapping].Values[b] != nil {
						if i > 6 {
							v = append(v, 0x1b, 'N')
						}
						v = append(v, byte(b))
					}
				}
			} else {
				for a := 0x21; a < 0x7f; a++ {
					for b := 0x21; b < 0x7f; b++ {
						if table.Mappings[st.Mapping].Values[256+a*256+b] != nil {
							v = append(v, byte(a), byte(b))
						}
					}
				}
			}
			v = append(v, []byte("\x1b(Bx")...)
			result = append(result, input{"all-defined-" + st.Name + "-" + c.Name, []byte(decl + fmt.Sprintf(body, string(v)) + string(v)), c.Table == 1 || i < 5})
		}
		for i, st := range table.States {
			valid := c.Table == 1 || i < 5 || (i >= 9 && i <= 12)
			result = append(result, input{"eof-state-" + st.Name + "-" + c.Name, []byte(decl + fmt.Sprintf(body, "ok") + string(st.Prefix)), valid})
		}
		for _, key := range []string{
			"control/ascii/nul/body", "control/ascii/si/body", "control/ascii/so/tail",
			"control/jis0208/cr/body", "control/jis0212/lf/body", "control/roman/cr-roman/body", "control/roman/lf-roman/body",
			"control/ascii/high80/body", "control/ascii/highff/tail", "control/jis0208/mid-pair/body",
			"control/latin/ss2-return/body", "control/greek/ss2-repeat/body", "control/latin/ss2-redesignate/body",
			"control/greek/newline-clears-g2/body", "control/latin/ss2-g0-switch/body",
		} {
			tc, ok := observed[c.Name+"/"+key]
			if !ok {
				panic(key)
			}
			tc.name = strings.ReplaceAll(key, "/", "-") + "-" + c.Name
			result = append(result, tc)
		}
		for _, state := range []string{"ascii", "jis0208"} {
			for _, units := range []int{503, 504, 505} {
				key := fmt.Sprintf("buffer/%s/%d/ascii-b", state, units)
				tc, ok := observed[c.Name+"/"+key]
				if !ok {
					panic(key)
				}
				tc.name = strings.ReplaceAll(key, "/", "-") + "-" + c.Name
				result = append(result, tc)
			}
		}
		result = append(result, input{"unicode-executable-" + c.Name, []byte(decl + strings.Replace(fmt.Sprintf(body, "ok"), "second", "\x1b$B\x24\x22\x1b(B", 1)), true})
		result = append(result, input{"declared-openstep-" + c.Name, []byte(decl + `{CFBundleExecutable=second;}`), false})
		result = append(result, input{"bom-priority-" + c.Name, []byte("\xef\xbb\xbf" + decl + fmt.Sprintf(body, "あ😀")), true})
		result = append(result, input{"mixed-case-" + c.Name, []byte(strings.Replace(decl, c.Name, strings.ToUpper(c.Name), 1) + fmt.Sprintf(body, "\x1b$(D\x22\x2f\x1b(B")), true})
		var boundary strings.Builder
		for _, n := range []int{998, 999, 1000, 1001, 1023, 1024, 4095, 4096} {
			boundary.WriteString(strings.Repeat("a", n))
			boundary.WriteString("\x1b$B\x24\x22\x1b(J\\\x1b(I\x21\x1b$(D\x22\x2f\x1b(B")
			if c.Table == 1 {
				boundary.WriteString("\x1b$A!!\x1b$(C!!\x1b.A\x1bN!\x1b.F\x1bNa\x1b(B")
			}
		}
		result = append(result, input{"boundary-transitions-" + c.Name, []byte(decl + fmt.Sprintf(body, boundary.String())), true})
	}
	if len(result) != 350 {
		panic(fmt.Sprint("extension input inventory: ", len(result)))
	}
	return result
}

func iso2022JPInputs() []input {
	var corpus struct {
		Codecs []struct {
			Name  string
			Table int
		}
		Tables []struct {
			States []struct {
				Name    string
				Prefix  []byte
				Mapping int
			}
			Mappings []struct{ Values []*string }
		}
	}
	must(json.Unmarshal(read("testdata/bundle-removal/plist-iso2022-jp-values.json"), &corpus))
	const body = `<dict><key>CFBundleExecutable</key><string>second</string><key>value</key><string><![CDATA[%s]]></string></dict>`
	var result []input
	for _, c := range corpus.Codecs {
		decl := `<?xml version="1.0" encoding="` + c.Name + `"?>`
		table := corpus.Tables[c.Table]
		for i, st := range table.States[:5] {
			valid := append([]byte{}, st.Prefix...)
			if i < 3 {
				for b, v := range table.Mappings[st.Mapping].Values[:256] {
					if v != nil {
						valid = append(valid, byte(b))
					}
				}
			} else {
				for pair, v := range table.Mappings[st.Mapping].Values[256:65792] {
					if v != nil {
						valid = append(valid, byte(pair>>8), byte(pair))
					}
				}
			}
			valid = append(valid, []byte("\x1b(B")...)
			result = append(result, input{"all-defined-" + st.Name + "-" + c.Name, []byte(decl + fmt.Sprintf(body, string(valid)) + string(valid) + "x"), true})
			result = append(result, input{"terminal-state-" + st.Name + "-" + c.Name, []byte(decl + fmt.Sprintf(body, string(valid)) + string(valid)), i != 0})
		}
		for _, units := range []int{503, 504, 505} {
			for _, kind := range []string{"ascii", "jis"} {
				base := decl + fmt.Sprintf(body, "ok")
				count := units - len(base)
				tail := strings.Repeat("a", count)
				if kind == "jis" {
					tail = "\x1b$B" + strings.Repeat("\x24\x22", count)
				}
				tail += "\x1b(B"
				result = append(result, input{fmt.Sprintf("buffer-%s-%d-%s", kind, units, c.Name), []byte(base + tail), units < 504 || kind == "jis"})
			}
		}

		var transitions []byte
		for _, from := range table.States {
			for _, to := range table.States {
				transitions = append(transitions, []byte("\x1b(B")...)
				transitions = append(transitions, from.Prefix...)
				if from.Mapping == 4 {
					transitions = append(transitions, 0xa2, 0xaf)
				} else {
					transitions = append(transitions, 0x5c, 0x22)
				}
				// An empty prefix is the initial state, not a reset instruction.
				if len(to.Prefix) == 0 {
					transitions = append(transitions, []byte("\x1b(B")...)
				} else {
					transitions = append(transitions, to.Prefix...)
				}
				if to.Mapping == 4 {
					transitions = append(transitions, 0xa2, 0xaf)
				} else {
					transitions = append(transitions, 0x5c, 0x22)
				}
			}
		}
		transitions = append(transitions, []byte("\x1b(B")...)
		result = append(result, input{"all-transitions-" + c.Name, []byte(decl + fmt.Sprintf(body, string(transitions))), true})
		for _, st := range table.States {
			result = append(result, input{"eof-state-" + st.Name + "-" + c.Name, []byte(decl + fmt.Sprintf(body, "ok") + string(st.Prefix)), true})
		}
		for _, tc := range []struct {
			name, value, tail string
			valid             bool
		}{
			{"high-bytes", "\x80\xff\x1b(J\x80\xff\\~\x1b(B", "", true},
			{"unknown-escapes", "\x1b(X\x1b%G\x1b&@\x1b$(B", "", true},
			{"literal-escape-eof", "ok", "\x1b", true},
			{"literal-prefix-eof", "ok", "\x1b(", true},
			{"invalid-kana-body", "\x1b(I \x1b(B", "", false},
			{"invalid-kana-tail", "ok", "\x1b(I ", false},
			{"invalid-jis-body", "\x1b$B\x80\x80\x1b(B", "", false},
			{"invalid-jis-tail", "ok", "\x1b$B\x80\x80", false},
			{"low-0212-body", "\x1b$(D\x22\x2f\x1b(B", "", false},
			{"low-0212-tail", "ok", "\x1b$(D\x22\x2f", false},
			{"undefined-jis-body", "\x1b$B\x22\x2f\x1b(B", "", false},
			{"undefined-jis-tail", "ok", "\x1b$B\x22\x2f", false},
			{"incomplete-jis-tail", "ok", "\x1b$B\x24", false},
			{"escape-mid-pair", "\x1b$B\x24\x1b(B", "", false},
			{"jis-newline", "\x1b$B\x24\x22\n\x1b(B", "", false},
			{"unreset-jis-tail", "ok", "\x1b$B\x24\x22", true},
			{"unreset-0212-tail", "ok", "\x1b$(D\xa2\xaf", true},
			{"shift-controls", "\x0e\x24\x22\x0f\x1b(J\x0e\\\x0f~\x1b(B", "", true},
			{"state-at-markup", "\x1b$B\x24\x22", "", false},
		} {
			result = append(result, input{tc.name + "-" + c.Name, []byte(decl + fmt.Sprintf(body, tc.value) + tc.tail), tc.valid})
		}
		result = append(result, input{"unicode-executable-" + c.Name, []byte(decl + strings.Replace(fmt.Sprintf(body, "ok"), "second", "\x1b$B\x24\x22\x1b(B", 1)), true})
		result = append(result, input{"declared-openstep-" + c.Name, []byte(decl + `{CFBundleExecutable=second;}`), false})
		result = append(result, input{"bom-priority-" + c.Name, []byte("\xef\xbb\xbf" + decl + fmt.Sprintf(body, "あ😀")), true})
		result = append(result, input{"mixed-case-" + c.Name, []byte(strings.Replace(decl, c.Name, strings.ToUpper(c.Name), 1) + fmt.Sprintf(body, "\x1b$B\x24\x22\x1b(B")), true})
		var boundary strings.Builder
		for _, n := range []int{998, 999, 1000, 1001, 1023, 1024, 4095, 4096} {
			boundary.WriteString(strings.Repeat("a", n))
			boundary.WriteString("\x1b$B\x24\x22\x1b(J\\\x1b(I\x21\x1b$(D\xa2\xaf\x1b(B")
		}
		result = append(result, input{"boundary-transitions-" + c.Name, []byte(decl + fmt.Sprintf(body, boundary.String())), true})
	}
	return result
}
