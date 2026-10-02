//go:build ignore

// Compile complete CoreFoundation executable-name and existence functions.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(input, name string, args ...string) []byte {
	c := exec.Command(name, args...)
	c.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, e := c.Output()
	if e != nil {
		panic(fmt.Sprintf("%v: %s", e, stderr.String()))
	}
	return b
}

type node struct {
	Kind, Name     string
	ReferencedDecl *node
	Inner          []node
}

func walk(n node, f func(node)) {
	f(n)
	for _, c := range n.Inner {
		walk(c, f)
	}
}
func main() {
	source := read(".research/apple/CFBundle.c")
	infoSource := read(".research/apple/CFBundle_InfoPlist.c")
	names := []string{"_urlExists", "_binaryLoadable", "_CFBundleCopyExecutableName", "_CFBundleCopyInfoDictionaryInDirectoryWithVersion", "CFBundleGetInfoDictionary", "_CFBundleCopyInfoPlistURL"}
	unit := `#include <CoreFoundation/CoreFoundation.h>
#define DEPLOYMENT_TARGET_EMBEDDED 0
#define DEPLOYMENT_TARGET_EMBEDDED_MINI 0
#define CF_PRIVATE
#define PLATFORM_PATH_STYLE kCFURLPOSIXPathStyle
struct __CFBundle { CFURLRef _url; CFDictionaryRef _infoDict; int _lock; uint8_t _version; };
extern const CFStringRef _kCFBundleOldExecutableKey;
extern const CFStringRef _kCFBundleInfoPlistURLKey, _kCFBundleRawInfoPlistURLKey;
void __CFLock(int*); void __CFUnlock(int*);
void _CFIterateDirectory(CFStringRef, Boolean (^)(CFStringRef, uint8_t));
void _CFBundleInfoPlistProcessInfoDictionary(CFMutableDictionaryRef);
void _CFBundleInfoPlistFixupInfoDictionary(CFBundleRef, CFMutableDictionaryRef);
void CFLog(int32_t, CFStringRef, ...);
extern const int32_t kCFLogLevelError;
int _CFGetFileProperties(CFAllocatorRef,CFURLRef,Boolean*,void*,void*,void*,void*,void*);
CFIndex _CFStartOfLastPathComponent2(CFStringRef);
CFIndex _CFLengthAfterDeletingPathExtension2(CFStringRef);
`
	hashes := map[string]string{}
	constants := regexp.MustCompile(`\b_CFBundle(?:PlatformInfoURLFromBase[0-3]|InfoURLFromBase[0-3]|ResourcesURLFromBase0|SupportFilesURLFromBase[12]|SupportFilesDirectoryName[12]|ResourcesDirectoryName|InfoPlistName|PlatformInfoPlistName)\b`).FindAll(infoSource, -1)
	seen := map[string]bool{}
	for _, c := range constants {
		if !seen[string(c)] {
			unit += "extern const CFStringRef " + string(c) + ";\n"
			seen[string(c)] = true
		}
	}
	for i, name := range names {
		data := source
		if i >= 3 {
			data = infoSource
		}
		body := regexp.MustCompile(`(?ms)^(?:static |CF_PRIVATE |CF_EXPORT )?(?:Boolean|CFStringRef|CFDictionaryRef|CFURLRef) ` + name + `\(.*?^}`).Find(data)
		if len(body) == 0 {
			panic(name)
		}
		unit += string(body) + "\n"
		hashes[name] = hash(body)
	}
	targets := map[string]any{}
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang", "-target", target, "-isysroot", sdk, "-std=c11", "-fblocks", "-x", "c", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"), &ast))
		facts := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "FunctionDecl" || hashes[n.Name] == "" {
				return
			}
			kinds, refs := map[string]int{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.ReferencedDecl != nil {
					refs[c.ReferencedDecl.Name]++
				}
			})
			if kinds["CompoundStmt"] > 0 {
				facts[n.Name] = map[string]any{"ast_kinds": kinds, "references": refs}
			}
		})
		if len(facts) != len(names) {
			panic("incomplete AST")
		}
		targets[target] = facts
	}
	result := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-removal-discovery.go")), "source_url": "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBundle.c", "source_sha256": hash(source), "info_source_url": "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBundle_InfoPlist.c", "info_source_sha256": hash(infoSource), "body_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets, "scope": "Six complete verbatim functions; private bundle layout, directory iteration, locks, keys and helper declarations are interface shims. The host SDK supplies real CoreFoundation interfaces. This AST establishes name fallback, existence queries, synthesized empty dictionaries and real/raw plist URL selection, not current macOS authorization or version-directory name behavior. Native corpora qualify those independently; platform-specific plist selection and malformed nonempty metadata remain separate implementation obligations."}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-removal-discovery.json", append(b, '\n'), 0644))
	fmt.Println("extracted six discovery bodies for two targets")
}
