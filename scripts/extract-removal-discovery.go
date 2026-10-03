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
	oldStyleSource := read(".research/apple/CFOldStylePList.c")
	builtinSource := read(".research/apple/CFBuiltinConverters.c")
	encodingSource := read(".research/apple/CFStringEncodings.c")
	icuSource := read(".research/apple/CFICUConverters.c")
	converterHeader := read(".research/apple/CFStringEncodingConverter.h")
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
typedef struct { const char *curr, *end; CFErrorRef error; CFAllocatorRef allocator; Boolean skip; CFOptionFlags mutabilityOption; void *stringTrie; CFMutableArrayRef stringCache; } _CFXMLPlistParseInfo;
CFIndex lineNumber(_CFXMLPlistParseInfo *);
void __CFPListRelease(CFTypeRef, CFAllocatorRef);
Boolean CFBurstTrieContainsUTF8String(void *,UInt8 *,CFIndex,uint32_t *);
Boolean CFBurstTrieAddUTF8String(void *,UInt8 *,CFIndex,uint32_t);
#define CDSECT_IX 12
#define CDSECT_TAG_LENGTH 9
extern const char *CFXMLPlistTags[];
`
	for _, name := range []string{"_createUniqueStringWithUTF8Bytes", "parseCDSect_pl", "parseEntityReference_pl", "parseStringTag"} {
		body := regexp.MustCompile(`(?ms)^static (?:void|Boolean|CFStringRef) ` + name + `\(.*?^}`).Find(plistSource)
		if len(body) == 0 {
			panic(name)
		}
		unit += string(body) + "\n"
		hashes[name] = hash(body)
		names = append(names, name)
	}

	unit += `
void initStatics(void);
Boolean __CFTryParseBinaryPlist(CFAllocatorRef,CFDataRef,CFOptionFlags,CFTypeRef *,CFErrorRef *);
Boolean _CFPropertyListCreateFromUTF8Data(CFAllocatorRef,CFDataRef,CFIndex,CFStringRef,CFStringEncoding,CFOptionFlags,CFErrorRef *,Boolean,CFPropertyListFormat *,CFSetRef,CFTypeRef *);
`
	for _, name := range []string{"_createUTF8DataFromString", "_CFPropertyListCreateWithData"} {
		body := regexp.MustCompile(`(?ms)^static (?:CFDataRef|Boolean) ` + name + `\(.*?^}`).Find(plistSource)
		if len(body) == 0 {
			panic(name)
		}
		unit += string(body) + "\n"
		hashes[name] = hash(body)
		names = append(names, name)
	}
	unit += `
typedef struct { const UniChar *curr, *end; CFErrorRef error; } _CFStringsFileParseInfo;
Boolean advanceToNonSpace(_CFStringsFileParseInfo *);
CFTypeRef parsePlistDict(_CFStringsFileParseInfo *),parsePlistArray(_CFStringsFileParseInfo *),parsePlistData(_CFStringsFileParseInfo *);
CFStringRef parseQuotedPlistString(_CFStringsFileParseInfo *,UniChar),parseUnquotedPlistString(_CFStringsFileParseInfo *);
CFIndex lineNumberStrings(_CFStringsFileParseInfo *);
`
	predicate := regexp.MustCompile(`(?m)^#define isValidUnquotedStringCharacter.*$`).Find(oldStyleSource)
	if len(predicate) == 0 {
		panic("unquoted predicate")
	}
	unit += string(predicate) + "\n"
	// Anchor the definition rather than the earlier forward declaration.
	body := regexp.MustCompile(`(?ms)^static CFTypeRef parsePlistObject\([^;\n]+\) \{.*?^}`).Find(oldStyleSource)
	if len(body) == 0 {
		panic("parsePlistObject")
	}
	unit += string(body) + "\n"
	hashes["parsePlistObject"] = hash(body)
	names = append(names, "parsePlistObject")
	converterTable := regexp.MustCompile(`(?ms)^static const uint16_t cp1252_to_uni\[32\] = \{.*?^};`).Find(builtinSource)
	if len(converterTable) == 0 {
		panic("cp1252_to_uni")
	}
	unit += string(converterTable) + "\n"
	for _, name := range []string{"__CFFromASCII", "__CFFromISOLatin1", "__CFFromWinLatin1"} {
		body := regexp.MustCompile(`(?ms)^static bool ` + name + `\(.*?^}`).Find(builtinSource)
		if len(body) == 0 {
			panic(name)
		}
		unit += string(body) + "\n"
		hashes[name] = hash(body)
		names = append(names, name)
	}

	unit += `
#include <stdio.h>
#include <xlocale.h>
#include <CoreFoundation/CFStringEncodingExt.h>
typedef struct UConverter UConverter;
typedef UniChar UChar;
typedef int32_t UErrorCode;
extern const UErrorCode U_ZERO_ERROR, U_BUFFER_OVERFLOW_ERROR;
uint16_t ucnv_countAliases(const char *,UErrorCode *);
const char *ucnv_getStandardName(const char *,const char *,UErrorCode *);
CFStringEncoding __CFStringEncodingGetFromWindowsCodePage(uint32_t);
CFStringEncoding __CFStringEncodingGetFromCanonicalName(const char *);
const char *ucnv_getAlias(const char *,uint16_t,UErrorCode *);
void ucnv_toUnicode(UConverter *,UChar **,const UChar *,const char **,const char *,int32_t *,bool,UErrorCode *);
void ucnv_getInvalidChars(const UConverter *,char *,int8_t *,UErrorCode *);
uint16_t __CFStringEncodingGetWindowsCodePage(CFStringEncoding);
bool __CFStringEncodingGetCanonicalName(CFStringEncoding,char *,CFIndex);
UConverter *__CFStringEncodingConverterCreateICUConverter(const char *,uint32_t,bool);
CFIndex __CFStringEncodingConverterReleaseICUConverter(UConverter *,uint32_t,CFIndex);
#define MAX_BUFFER_SIZE (1000)
#define HAS_ICU_BUG_6024743 (1)
#define HAS_ICU_BUG_6025527 (1)
`
	enums := regexp.MustCompile(`(?ms)^enum \{\n    kCFStringEncoding(?:AllowLossyConversion|ConversionSuccess).*?^};`).FindAll(converterHeader, -1)
	if len(enums) != 2 {
		panic("conversion constants")
	}
	for _, e := range enums {
		unit += string(e) + "\n"
	}
	for _, name := range []string{"__CFStringEncodingGetICUName", "__CFStringEncodingGetFromICUName", "__CFStringEncodingICUToUnicode"} {
		body := regexp.MustCompile(`(?ms)^CF_PRIVATE (?:const char \*|CFIndex |CFStringEncoding )` + name + `\(.*?^}`).Find(icuSource)
		if len(body) == 0 {
			panic(name)
		}
		unit += string(body) + "\n"
		hashes[name] = hash(body)
		names = append(names, name)
	}

	converterSource := read(".research/apple/CFStringEncodingConverter.c")
	converterExt := read(".research/apple/CFStringEncodingConverterExt.h")
	converterPriv := read(".research/apple/CFStringEncodingConverterPriv.h")
	// Retain the real typedefs, converter layout and call macros verbatim.
	declarations := regexp.MustCompile(`(?m)^typedef CFIndex \(\*CFStringEncodingTo(?:Bytes|Unicode)FallbackProc\).*;$`).FindAll(converterHeader, -1)
	if len(declarations) != 2 {
		panic("fallback interfaces")
	}
	for _, d := range declarations {
		unit += string(d) + "\n"
	}
	ext := regexp.MustCompile(`(?s)enum \{\n    kCFStringEncodingConverterStandard = 0,.*?} CFStringEncodingConverter;`).Find(converterExt)
	wrapper := regexp.MustCompile(`(?s)typedef CFIndex \(\*_CFToBytesProc\).*?} _CFEncodingConverter;`).Find(converterSource)
	macros := regexp.MustCompile(`(?m)^#define TO_UNICODE(?:_FALLBACK)?\(.*$`).FindAll(converterSource, -1)
	platform := regexp.MustCompile(`(?m)^extern  CFIndex __CFStringEncodingPlatformBytesToUnicode\(.*;$`).Find(converterPriv)
	dispatchBody := regexp.MustCompile(`(?ms)^uint32_t CFStringEncodingBytesToUnicode\(.*?^}`).Find(converterSource)
	if len(ext) == 0 || len(wrapper) == 0 || len(macros) != 2 || len(platform) == 0 || len(dispatchBody) == 0 {
		panic("complete converter dispatch evidence")
	}
	unit += string(ext) + "\n" + string(wrapper) + "\nconst _CFEncodingConverter *__CFGetConverter(uint32_t);\n" + string(platform) + "\n"
	for _, m := range macros {
		unit += string(m) + "\n"
	}
	unit += string(dispatchBody) + "\n"
	hashes["CFStringEncodingBytesToUnicode"] = hash(dispatchBody)
	names = append(names, "CFStringEncodingBytesToUnicode")

	foundationHeader := read(".research/apple/ForFoundationOnly.h")
	bufferDefinition := regexp.MustCompile(`(?s)enum \{\n     __kCFVarWidthLocalBufferSize = 1008\n};.*?} CFVarWidthCharBuffer;`).Find(foundationHeader)
	lengthBody := regexp.MustCompile(`(?ms)^CF_PRIVATE CFIndex CFStringEncodingCharLengthForBytes\(.*?^}`).Find(converterSource)
	lengthPlatform := regexp.MustCompile(`(?m)^extern  CFIndex __CFStringEncodingPlatformCharLengthForBytes\(.*;$`).Find(converterPriv)
	if len(bufferDefinition) == 0 || len(lengthBody) == 0 || len(lengthPlatform) == 0 {
		panic("complete sizing evidence")
	}
	unit += string(bufferDefinition) + "\nCFIndex __CFStringEncodingICUCharLength(const char *,uint32_t,const uint8_t *,CFIndex);\n" + string(lengthPlatform) + "\n" + string(lengthBody) + "\n"
	hashes["CFStringEncodingCharLengthForBytes"] = hash(lengthBody)
	names = append(names, "CFStringEncodingCharLengthForBytes")
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
	result["old_style_source_url"] = "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFOldStylePList.c"
	result["old_style_source_sha256"] = hash(oldStyleSource)
	result["unquoted_predicate_sha256"] = hash(predicate)
	result["builtin_source_url"] = "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBuiltinConverters.c"
	result["builtin_source_sha256"] = hash(builtinSource)
	result["encoding_source_url"] = "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFStringEncodings.c"
	result["encoding_source_sha256"] = hash(encodingSource)
	result["converter_table_sha256"] = hash(converterTable)
	result["scope"] = "Eighteen complete verbatim functions; private bundle layout, directory iteration, locks, keys and helper declarations are interface shims. Dictionary Objective-C dispatch/KVO/type validation are shims; mutable-hash guards and AddValue/SetValue calls remain in the AST. The host SDK supplies CoreFoundation interfaces. This establishes name fallback, invalid/non-dictionary empty synthesis, platform/ordinary raw URL retention and distinct dictionary insertion/replacement calls. Current parser duplicate order, authorization, executable-key normalization and version arbitration are independently qualified by native corpora; BOM detection is retained in a complete encodingForXMLData body, and CFUniCharFromUTF32 plus both surrogate predicates retain strict and lossy scalar conversion branches; complete string, CDATA and entity bodies retain byte assembly and show no XML 1.0 character filtering. Parser state and string-interning interfaces are shims. The historical entity accumulator is 16-bit: current scalar behavior is qualified by retained live codesign and plutil corpora, not inferred from that historical width. The complete property-list conversion caller and UTF-8 prefix conversion body retain encoding selection, skip offsets and non-external conversion. The complete old-style object dispatch body and verbatim unquoted-character macro establish invalid initial object rejection; old-style parser state/helper interfaces are shims. Current unmarked decoding remains independently qualified by native corpora. Broader parser encodings/types remain open."
	result["scope"] = strings.Replace(result["scope"].(string), "Eighteen", "Twenty-one", 1) + " Three complete built-in byte converters and the verbatim Windows-1252 table retain failure versus mapping branches. The larger CFStringEncodings bulk decoder is source-reviewed and source-hashed, not claimed as a compiled body: its ASCII/Latin-1 fast path bypasses the strict built-in ASCII converter. Current mappings and whole-stream behavior are qualified separately with native byte and operation corpora."
	result["icu_source_url"] = "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFICUConverters.c"
	result["icu_source_sha256"] = hash(icuSource)
	result["converter_header_sha256"] = hash(converterHeader)
	result["scope"] = strings.Replace(result["scope"].(string), "Twenty-one", "Twenty-five", 1) + " Three complete ICU alias/selection/conversion bodies retain Windows-codepage preference, canonical-name fallback, flush-at-end, buffer iteration and invalid-stream error handling, including historical invalid-input pointer adjustments. ICU types, constants and helper functions are interface declarations, not emulated behavior. Conversion flags/status enums are verbatim from the pinned header. The converter-creation STOP callback policy is source-reviewed, not claimed compiled; current Shift-JIS and EUC-JP mappings/errors are established by live property-list and codesign observations. The complete unique UTF-8 string constructor retains final assembled-string creation and cache behavior; live BOM cases qualify current string behavior. Historical ICU control flow does not assert which converter implements EUC-JP on the current host."
	result["converter_source_sha256"] = hash(converterSource)
	result["converter_ext_sha256"] = hash(converterExt)
	result["converter_priv_sha256"] = hash(converterPriv)
	result["converter_source_url"] = "https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFStringEncodingConverter.c"
	result["scope"] = strings.Replace(result["scope"].(string), "Twenty-five", "Twenty-six", 1) + " The complete byte-to-Unicode dispatcher retains ICU, platform-specific, standard/canonical and lossy-fallback paths, using verbatim source typedefs/layout/macros and the pinned platform declaration. Converter lookup is an interface declaration. This explains why generic ICU behavior alone cannot establish the current ISO-2022-JP contract; live exhaustive state/escape observations establish that behavior."
	result["foundation_header_sha256"] = hash(foundationHeader)
	result["buffer_definition_sha256"] = hash(bufferDefinition)
	result["scope"] = strings.Replace(result["scope"].(string), "Twenty-six", "Twenty-seven", 1) + " The complete decoded-length function and verbatim 1008-byte buffer definition retain native sizing interfaces. The source-reviewed bulk caller supplies max(504, guessed UTF-16 length) output units; the complete dispatcher stops at capacity before trailing non-emitting escapes. The larger bulk caller remains source-reviewed, not counted as compiled. Live 503/504/505-unit property-list observations qualify the current boundary independently."
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-removal-discovery.json", append(b, '\n'), 0644))
	fmt.Println("extracted twenty-seven discovery bodies for two targets")
}
