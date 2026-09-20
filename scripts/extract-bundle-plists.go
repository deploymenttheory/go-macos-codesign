//go:build ignore

// Research only: pinned Apple binary-plist framing and raw bundle components.
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

const cfRevision = "dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3"
const securityRevision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(p string) []byte { b, err := os.ReadFile(p); must(err); return b }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(input, command string, args ...string) []byte {
	c := exec.Command(command, args...)
	c.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, err := c.Output()
	if err != nil {
		panic(fmt.Sprintf("%v: %s", err, stderr.String()))
	}
	return b
}

type node struct {
	Kind, Name, Opcode string
	Value              any
	Inner              []node
}

func walk(n node, visit func(node)) {
	visit(n)
	for _, c := range n.Inner {
		walk(c, visit)
	}
}
func excerpt(data []byte, pattern string) []byte {
	b := regexp.MustCompile(pattern).Find(data)
	if len(b) == 0 {
		panic("missing excerpt: " + pattern)
	}
	return b
}

func main() {
	cf, header := read(".research/apple/CFBinaryPList.c"), read(".research/apple/ForFoundationOnly.h")
	bundle, static := read(".research/apple/bundlediskrep.cpp"), read(".research/apple/StaticCode.cpp")
	excerpts := map[string][]byte{
		"markers":                        excerpt(header, `(?s)enum \{\s*kCFBinaryPlistMarkerNull.*?\n};`),
		"trailer":                        excerpt(header, `(?s)typedef struct \{\s*uint8_t\s+_unused\[5\];.*?} CFBinaryPlistTrailer;`),
		"_getSizedInt":                   excerpt(cf, `(?s)CF_INLINE uint64_t _getSizedInt\(.*?\n}`),
		"__CFBinaryPlistGetTopLevelInfo": excerpt(cf, `(?s)bool __CFBinaryPlistGetTopLevelInfo\(.*?\n}`),
		"_readInt":                       excerpt(cf, `(?s)CF_INLINE bool _readInt\(.*?\n}`),
		"component":                      excerpt(bundle, `(?s)CFDataRef BundleDiskRep::component\(.*?\n}`),
		"getDictionary":                  excerpt(static, `(?s)CFDictionaryRef SecStaticCode::getDictionary\(.*?\n}`),
	}
	unit := `#include <cstdint>
#include <cstddef>
#include <climits>
#include <cstring>
#define CF_INLINE static inline
#define FAIL_FALSE do {return false;} while(0)
using CFIndex = long;
enum {CF_NO_ERROR=0};
void initStatics();
uint16_t CFSwapInt16BigToHost(uint16_t);
uint32_t CFSwapInt32BigToHost(uint32_t);
uint64_t CFSwapInt64BigToHost(uint64_t);
uint64_t __check_uint64_mul_unsigned_unsigned(uint64_t,uint64_t,int32_t*);
uint64_t __check_uint64_add_unsigned_unsigned(uint64_t,uint64_t,int32_t*);
const uint8_t* check_ptr_add(const uint8_t*,uint64_t,int32_t*);
using CFDataRef=void*;using CFDictionaryRef=void*;using CFURLRef=void*;
template<class T> struct CFRef {CFRef(T);operator T()const;T yield();};
struct CodeDirectory {using SpecialSlot=int;};
enum {cdInfoSlot=1,cdResourceDirSlot=3,errSecCSBadDictionaryFormat=1};
struct MacOSError {static void throwMe(int);};
struct Slots {void insert(int);};
struct ExecRep {CFDataRef component(int);};
CFURLRef _CFBundleCopyInfoPlistURL(void*);
CFDataRef loadRegularFile(CFURLRef);
CFDictionaryRef makeCFDictionaryFrom(CFDataRef);
struct BundleDiskRep {void* mBundle;ExecRep* mExecRep;Slots mUsedComponents;CFDataRef metaData(int);void componentFromExec(bool);CFDataRef component(CodeDirectory::SpecialSlot);};
struct SecStaticCode {void validateDirectory();void validateComponent(int);CFDataRef component(int);CFDictionaryRef getDictionary(CodeDirectory::SpecialSlot,bool);};
`
	for _, name := range []string{"markers", "trailer", "_getSizedInt", "__CFBinaryPlistGetTopLevelInfo", "_readInt", "component", "getDictionary"} {
		unit += "\n" + string(excerpts[name])
	}
	unit += `
enum {TrailerSize=sizeof(CFBinaryPlistTrailer),OffsetWidth=offsetof(CFBinaryPlistTrailer,_offsetIntSize),ReferenceWidth=offsetof(CFBinaryPlistTrailer,_objectRefSize),ObjectCount=offsetof(CFBinaryPlistTrailer,_numObjects),TopObject=offsetof(CFBinaryPlistTrailer,_topObject),OffsetTable=offsetof(CFBinaryPlistTrailer,_offsetTableOffset)};
`
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"), &ast))
		constants, methods := map[string]string{}, map[string]any{}
		walk(ast, func(n node) {
			if n.Kind == "EnumConstantDecl" {
				if strings.HasPrefix(n.Name, "kCFBinaryPlistMarker") || strings.Contains(" TrailerSize OffsetWidth ReferenceWidth ObjectCount TopObject OffsetTable ", " "+n.Name+" ") {
					walk(n, func(c node) {
						if c.Kind == "ConstantExpr" {
							constants[n.Name] = fmt.Sprint(c.Value)
						}
					})
				}
			}
			if n.Kind != "FunctionDecl" && n.Kind != "CXXMethodDecl" || excerpts[n.Name] == nil {
				return
			}
			body := false
			for _, c := range n.Inner {
				body = body || c.Kind == "CompoundStmt"
			}
			if !body {
				return
			}
			kinds, operators := map[string]int{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.Opcode != "" {
					operators[c.Opcode]++
				}
			})
			methods[n.Name] = map[string]any{"ast_kinds": kinds, "operators": operators}
		})
		if len(methods) != 5 || len(constants) != 20 {
			panic("incomplete AST")
		}
		targets[target] = map[string]any{"constants": constants, "methods": methods}
	}
	sources, hashes := map[string]any{}, map[string]string{}
	for name, data := range map[string][]byte{"CFBinaryPList.c": cf, "ForFoundationOnly.h": header, "bundlediskrep.cpp": bundle, "StaticCode.cpp": static} {
		base := "https://github.com/apple-oss-distributions/CF/blob/" + cfRevision + "/"
		if name == "bundlediskrep.cpp" || name == "StaticCode.cpp" {
			base = "https://github.com/apple-oss-distributions/Security/blob/" + securityRevision + "/OSX/libsecurity_codesigning/lib/"
		}
		sources[name] = map[string]string{"url": base + name, "sha256": hash(data)}
	}
	for name, data := range excerpts {
		hashes[name] = hash(data)
	}
	result := map[string]any{"schema": 1, "scope": "Verbatim CoreFoundation trailer/marker declarations, three binary framing/integer functions, and two Security component/dictionary methods. Explicit interface, checked-arithmetic, endian and error shims; AST analysis does not execute CoreFoundation or claim complete native parsing policy.", "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sources": sources, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets}
	b, err := json.MarshalIndent(result, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-bundle-plists.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-bundle-plists.json: two-target binary plist framing and metadata-binding AST")
}
