package codesign

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-macos-codesign/pkg/plist"
)

const maxBundlePlist = plist.MaxSize
const maxBundleEntries = 10000
const maxBundlePlistDepth = plist.MaxDepth
const maxBundlePlistValues = plist.MaxValues

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
	return verifyBundleResourcesWithOptions(context.Background(), data, actual, VerifyOptions{})
}

func verifyBundleResourcesWithOptions(ctx context.Context, data []byte, actual map[string]any, opts VerifyOptions) (int, error) {
	m, err := decodeBundlePlist(data)
	if err != nil {
		return 0, err
	}
	files, ok := m["files2"].(map[string]any)
	_, legacy := m["files"].(map[string]any)
	if !ok || !legacy || len(m) != 4 || len(files) > maxBundleEntries || !reflect.DeepEqual(m["rules"], bundleRules(true)) || !reflect.DeepEqual(m["rules2"], bundleRules(false)) {
		return 0, unsupported("bundle resource envelope profile")
	}
	// Validate present entries before missing entries, as Apple's resource scan
	// precedes its optional-resource pass. Map iteration must not choose errors.
	names := slices.Sorted(maps.Keys(actual))
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if _, present := actual[name]; !present {
			names = append(names, name)
		}
	}
	var failures resourceFailures
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := bundleRelativePath(name); err != nil {
			return 0, err
		}
		if _, exempt := actual[name].(xattrResourceExemption); exempt {
			continue
		}
		var err error
		if _, present := actual[name]; present {
			if err := verifyResourceSideband(ctx, name, opts); err != nil && !failures.collect(err) {
				return 0, err
			}
		}
		if seal, sealed := files[name]; sealed {
			value, present := actual[name]
			err = verifyBundleResource(ctx, name, seal, value, present, opts)
		} else {
			err = resourceFailure("added", name, opts)
		}
		if err != nil && !failures.collect(err) {
			return 0, err
		}
	}
	if err := failures.err(); err != nil {
		return 0, err
	}
	return len(files), nil
}

// Only 20- and 32-byte resource hashes reach this writer, each on one line.
func resourceDataXML(out *strings.Builder, data []byte, indent string) {
	fmt.Fprintf(out, "%s<data>\n%s%s\n%s</data>\n", indent, indent, base64.StdEncoding.EncodeToString(data), indent)
}
