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
	dictionarySource := read(".research/apple/CFDictionary.c")
	plistSource := read(".research/apple/CFPropertyList.c")
	unicodeSource := read(".research/apple/CFUniChar.h")
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
	unit += `
#define CFDictionary 1
#define CFSet 0
#define CFBag 0
typedef CFMutableDictionaryRef CFMutableHashRef;
typedef const void *const_any_pointer_t;
typedef struct __CFBasicHash *CFBasicHashRef;
Boolean CFBasicHashIsMutable(CFBasicHashRef);
void CFBasicHashAddValue(CFBasicHashRef, uintptr_t, uintptr_t);
void CFBasicHashSetValue(CFBasicHashRef, uintptr_t, uintptr_t);
#define CF_OBJC_FUNCDISPATCHV(...) ((void)0)
#define __CFGenericValidateType(...) ((void)0)
#define CFAssert2(condition, ...) ((void)(condition))
#define CF_OBJC_KVO_WILLCHANGE(...) ((void)0)
#define CF_OBJC_KVO_DIDCHANGE(...) ((void)0)
`
	for _, name := range []string{"CFDictionaryAddValue", "CFDictionarySetValue"} {
		body := regexp.MustCompile(`(?ms)^#if CFDictionary\nvoid ` + name + `\(.*?^}`).Find(dictionarySource)
		if len(body) == 0 {
			panic(name)
		}
		unit += string(body) + "\n"
		hashes[name] = hash(body)
		names = append(names, name)
	}
	unit += "\n#include <string.h>\n#include <stdbool.h>\n#define DEPLOYMENT_TARGET_MACOSX 1\nCFErrorRef __CFPropertyListCreateError(CFIndex, CFStringRef, ...);\n"
	encodingBody := regexp.MustCompile(`(?ms)^static CFStringEncoding encodingForXMLData\(.*?^}`).Find(plistSource)
	if len(encodingBody) == 0 {
		panic("encodingForXMLData")
	}
	unit += string(encodingBody) + "\n"
	hashes["encodingForXMLData"] = hash(encodingBody)
	names = append(names, "encodingForXMLData")
	unit += "\n#include <CoreFoundation/CFByteOrder.h>\n"
	for _, name := range []string{"CFUniCharIsSurrogateHighCharacter", "CFUniCharIsSurrogateLowCharacter", "CFUniCharFromUTF32"} {
		body := regexp.MustCompile(`(?ms)^CF_INLINE bool ` + name + `\(.*?^}`).Find(unicodeSource)
		if len(body) == 0 {
			panic(name)
		}
		unit += string(body) + "\n"
		hashes[name] = hash(body)
		names = append(names, name)
	}

	unit += `
#define NO ((Boolean)0)
typedef struct { const char *curr, *end; CFErrorRef error; CFAllocatorRef allocator; Boolean skip; CFOptionFlags mutabilityOption; } _CFXMLPlistParseInfo;
CFIndex lineNumber(_CFXMLPlistParseInfo *);
void __CFPListRelease(CFTypeRef, CFAllocatorRef);
CFStringRef _createUniqueStringWithUTF8Bytes(_CFXMLPlistParseInfo *, const char *, CFIndex);
#define CDSECT_IX 12
#define CDSECT_TAG_LENGTH 9
extern const char *CFXMLPlistTags[];
`
	for _, name := range []string{"parseCDSect_pl", "parseEntityReference_pl", "parseStringTag"} {
		body := regexp.MustCompile(`(?ms)^static (?:void|Boolean) ` + name + `\(.*?^}`).Find(plistSource)
		if len(body) == 0 {
			panic(name)
		}
		unit += string(body) + "\n"
		hashes[name] = hash(body)
		names = append(names, name)
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
	result := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-removal-discovery.go")), "source_url": "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBundle.c", "source_sha256": hash(source), "info_source_url": "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBundle_InfoPlist.c", "info_source_sha256": hash(infoSource), "body_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets}
	result["dictionary_source_url"] = "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFDictionary.c"
	result["dictionary_source_sha256"] = hash(dictionarySource)
	result["plist_source_url"] = "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFPropertyList.c"
	result["plist_source_sha256"] = hash(plistSource)
	result["unicode_source_url"] = "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFUniChar.h"
	result["unicode_source_sha256"] = hash(unicodeSource)
	result["scope"] = "Fifteen complete verbatim functions; private bundle layout, directory iteration, locks, keys and helper declarations are interface shims. Dictionary Objective-C dispatch/KVO/type validation are shims; mutable-hash guards and AddValue/SetValue calls remain in the AST. The host SDK supplies CoreFoundation interfaces. This establishes name fallback, invalid/non-dictionary empty synthesis, platform/ordinary raw URL retention and distinct dictionary insertion/replacement calls. Current parser duplicate order, authorization, executable-key normalization and version arbitration are independently qualified by native corpora; BOM detection is retained in a complete encodingForXMLData body, and CFUniCharFromUTF32 plus both surrogate predicates retain strict and lossy scalar conversion branches; complete string, CDATA and entity bodies retain byte assembly and show no XML 1.0 character filtering. Parser state and string-interning interfaces are shims. The historical entity accumulator is 16-bit: current scalar behavior is qualified by retained live codesign and plutil corpora, not inferred from that historical width. Broader parser encodings/types remain open."
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-removal-discovery.json", append(b, '\n'), 0644))
	fmt.Println("extracted fifteen discovery bodies for two targets")
}
