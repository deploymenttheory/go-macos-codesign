package codesign

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"howett.net/plist"
)

const maxBundlePlist = 8 << 20
const maxBundleEntries = 10000

// These fixed dictionaries describe Apple's non-flat V2 bundle profile. Other
// rule sets are rejected on verification instead of weakening resource checks.
func bundleRules(legacy bool) map[string]any {
	rule := func(weight float64, flag string) any {
		m := map[string]any{"weight": weight}
		if flag != "" {
			m[flag] = true
		}
		return m
	}
	m := map[string]any{
		`^Resources/`:                            true,
		`^Resources/.*\.lproj/`:                  rule(1000, "optional"),
		`^Resources/Base\.lproj/`:                rule(1010, ""),
		`^Resources/.*\.lproj/locversion.plist$`: rule(1100, "omit"),
	}
	if legacy {
		m[`^version.plist$`] = true
		return m
	}
	m[`^Resources/`] = rule(20, "")
	m[`^.*`] = true
	m[`^[^/]+$`] = rule(10, "nested")
	m[`^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/`] = rule(10, "nested")
	m[`.*\.dSYM($|/)`] = rule(11, "")
	m[`^(.*/)?\.DS_Store$`] = rule(2000, "omit")
	m[`^Info\.plist$`] = rule(20, "omit")
	m[`^PkgInfo$`] = rule(20, "omit")
	m[`^version\.plist$`] = rule(20, "")
	m[`^embedded\.provisionprofile$`] = rule(20, "")
	return m
}

type resourceRule struct {
	pattern        *regexp.Regexp
	weight         float64
	omit, optional bool
}

func compileBundleRules(legacy bool) []resourceRule {
	var rules []resourceRule
	for pattern, v := range bundleRules(legacy) {
		r := resourceRule{pattern: regexp.MustCompile(pattern), weight: 1}
		if m, ok := v.(map[string]any); ok {
			r.weight = m["weight"].(float64)
			r.omit, _ = m["omit"].(bool)
			r.optional, _ = m["optional"].(bool)
		}
		rules = append(rules, r)
	}
	return rules
}

var bundleRulesV1 = compileBundleRules(true)
var bundleRulesV2 = compileBundleRules(false)

func resourcePolicy(name string, legacy bool) (include, optional bool) {
	rules := bundleRulesV2
	if legacy {
		rules = bundleRulesV1
	}
	var weight float64
	for _, r := range rules {
		if r.weight > weight && r.pattern.MatchString(name) {
			weight = r.weight
			include = !r.omit
			optional = r.optional
		}
	}
	return
}

func decodeBundlePlist(data []byte) (map[string]any, error) {
	if len(data) == 0 || len(data) > maxBundlePlist {
		return nil, malformed("bundle plist size")
	}
	// The initial profile uses XML plists. Preflight nesting, element count and
	// dictionary keys before the generic plist decoder allocates its object graph.
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth, count := 0, 0
	type dictionary struct {
		depth int
		keys  map[string]bool
	}
	var dicts []dictionary
	var key strings.Builder
	inKey, rootSeen := false, false
	for {
		tok, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, malformed("bundle XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if inKey || depth == 0 && (rootSeen || t.Name.Local != "plist") {
				return nil, malformed("bundle plist XML structure")
			}
			rootSeen = true
			depth++
			count++
			if depth > 32 || count > 100000 {
				return nil, malformed("bundle plist complexity limit")
			}
			if t.Name.Local == "dict" {
				dicts = append(dicts, dictionary{depth, map[string]bool{}})
			}
			if t.Name.Local == "key" {
				if len(dicts) == 0 || dicts[len(dicts)-1].depth != depth-1 {
					return nil, malformed("misplaced bundle plist key")
				}
				inKey = true
				key.Reset()
			}
		case xml.CharData:
			if inKey {
				key.Write(t)
			} else if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return nil, malformed("text outside bundle plist")
			}
		case xml.EndElement:
			depth--
			if t.Name.Local == "key" {
				keys := dicts[len(dicts)-1].keys
				if keys[key.String()] {
					return nil, malformed("duplicate bundle plist key")
				}
				keys[key.String()] = true
				inKey = false
			}
			if t.Name.Local == "dict" && len(dicts) > 0 {
				dicts = dicts[:len(dicts)-1]
			}
		}
	}
	var m map[string]any
	if _, err := plist.Unmarshal(data, &m); err != nil {
		return nil, malformed("bundle plist: %v", err)
	}
	if m == nil {
		return nil, malformed("bundle plist must be a dictionary")
	}
	return m, nil
}

func encodeBundleResources(files, files2 map[string]any) []byte {
	var out strings.Builder
	out.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n")
	entitlementXML(&out, map[string]any{"files": files, "files2": files2, "rules": bundleRules(true), "rules2": bundleRules(false)}, 0)
	out.WriteString("</plist>\n")
	return []byte(out.String())
}

func resourceSeal(sum []byte, optional, legacy bool) any {
	if legacy && !optional {
		return sum
	}
	key := "hash2"
	if legacy {
		key = "hash"
	}
	m := map[string]any{key: sum}
	if optional {
		m["optional"] = true
	}
	return m
}

func verifyBundleResources(data []byte, actual map[string]any) (int, error) {
	m, err := decodeBundlePlist(data)
	if err != nil {
		return 0, err
	}
	files, ok := m["files2"].(map[string]any)
	_, legacy := m["files"].(map[string]any)
	if !ok || !legacy || len(m) != 4 || len(files) > maxBundleEntries || !reflect.DeepEqual(m["rules"], bundleRules(true)) || !reflect.DeepEqual(m["rules2"], bundleRules(false)) {
		return 0, unsupported("bundle resource envelope profile")
	}
	for name, v := range files {
		if err := bundleRelativePath(name); err != nil {
			return 0, err
		}
		include, optional := resourcePolicy(name, false)
		seal, ok := v.(map[string]any)
		hash, hashOK := seal["hash2"].([]byte)
		if !include || !ok || !hashOK || len(hash) != 32 || !reflect.DeepEqual(v, resourceSeal(hash, optional, false)) {
			return 0, invalid("resource seal for %s", name)
		}
		if got, present := actual[name]; present {
			if !reflect.DeepEqual(got, v) {
				return 0, invalid("altered resource: %s", name)
			}
		} else if !optional {
			return 0, invalid("missing resource: %s", name)
		}
	}
	for name := range actual {
		if _, ok := files[name]; !ok {
			return 0, invalid("added resource: %s", name)
		}
	}
	return len(files), nil
}

// Only 20- and 32-byte resource hashes reach this writer, each on one line.
func resourceDataXML(out *strings.Builder, data []byte, indent string) {
	fmt.Fprintf(out, "%s<data>\n%s%s\n%s</data>\n", indent, indent, base64.StdEncoding.EncodeToString(data), indent)
}
