//go:build ignore

// Research only: complete Apple resource validation and collection bodies.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(input, name string, args ...string) []byte {
	c := exec.Command(name, args...)
	c.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, e := c.Output()
	if e != nil {
		panic(fmt.Sprintf("%s: %v: %s", name, e, stderr.String()))
	}
	return b
}

type node struct {
	Kind, Name, MangledName string
	ReferencedDecl          *struct{ Name string }
	Inner                   []node
}

func walk(n node, f func(node)) {
	f(n)
	for _, c := range n.Inner {
		walk(c, f)
	}
}
func main() {
	unit := `#include <string>
#include <set>
#include <cassert>
#include <unistd.h>
#include <cstdio>
#include <cerrno>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CodeSigning.h>
#define secinfo(...) ((void)0)
#define XATTR_RESOURCEFORK_NAME "com.apple.ResourceFork"
#define XATTR_FINDERINFO_NAME "com.apple.FinderInfo"
namespace Security { struct DynamicHash { bool verify(const unsigned char*); }; }
namespace CodesignResourceResearch {
using std::string;
template<class T> struct CFRef { CFRef(T); T get(); T retain(); void take(T); operator T() const; };
template<class T> T cfget(CFDictionaryRef,const char*);
struct ResourceSeal { ResourceSeal(CFTypeRef); bool optional(); bool nested(); CFStringRef link(); const unsigned char* hash(int) const; };
string cfString(CFTypeRef, OSStatus=noErr);
CFURLRef makeCFURL(string,bool,CFURLRef);
struct CFTempString { CFTempString(string); operator CFStringRef() const; };
struct CFTempURL { CFTempURL(CFStringRef,bool,CFURLRef); CFTempURL(string,bool,CFURLRef); CFURLRef get(); operator CFURLRef() const; };
struct CSError { CSError(OSStatus,CFDictionaryRef); [[noreturn]] static void throwMe(OSStatus,CFStringRef,CFTypeRef); };
struct MacOSError { [[noreturn]] static void throwMe(OSStatus); };
struct CFError { [[noreturn]] static void throwMe(); };
struct Mutex {};
template<class T> struct StLock { StLock(T&); ~StLock(); };
CFMutableDictionaryRef makeCFMutableDictionary();
CFMutableArrayRef makeCFMutableArray(int);
struct FileDesc { enum { modeMissingOk }; };
struct AutoFileDesc { AutoFileDesc(string); AutoFileDesc(string,int,int); bool hasExtendedAttribute(const char*); operator bool(); };
struct CodeDirectory { using HashAlgorithm=int; static void multipleHashFileData(AutoFileDesc&,int,std::set<int>,void(^)(HashAlgorithm,Security::DynamicHash*)); };
struct DiskRep { string mainExecutablePath(); };
bool isFlagSet(SecCSFlags,SecCSFlags);
extern const SecCSFlags kSecCSRestrictSidebandData;
extern const CFStringRef kSecCFErrorResourceRecursive;
struct SecStaticCode {
 struct ValidationContext { SecStaticCode& code; void reportProblem(OSStatus,CFStringRef,CFTypeRef); };
 struct CollectingContext { Mutex mLock; OSStatus mStatus; CFRef<CFMutableDictionaryRef> mCollection; void reportProblem(OSStatus,CFStringRef,CFTypeRef); void throwMe(); };
 DiskRep* mRep;
 CFURLRef resourceBase(); CFDictionaryRef resourceDictionary();
 bool loadResources(CFDictionaryRef&,CFDictionaryRef&,uint32_t&);
 static void checkOptionalResource(CFTypeRef,CFTypeRef,void*);
 void validateResource(CFDictionaryRef,string,bool,ValidationContext&,SecCSFlags,uint32_t);
 void validateNestedCode(CFURLRef,const ResourceSeal&,SecCSFlags,bool);
 void validateSymlinkResource(string,string,ValidationContext&,SecCSFlags);
 int hashAlgorithm(); std::set<int> hashAlgorithms();
 bool checkfix30814861(string,bool);
 void checkRevocationOnNestedBinary(AutoFileDesc&,CFURLRef,SecCSFlags);
};
extern bool verbose;
static void diagnose1(const char*,OSStatus);
static void diagnose1(const char*,CFTypeRef);
`
	excerpts := map[string]string{}
	sources := map[string]any{}
	for _, source := range []struct {
		file, repo, commit, path string
		patterns                 []string
	}{
		{"StaticCode.cpp", "Security", "db15acbe6a7f257a859ad9a3bb86097bfe0679d9", "OSX/libsecurity_codesigning/lib/", []string{`bool SecStaticCode::loadResources\(`, `void SecStaticCode::checkOptionalResource\(`, `void SecStaticCode::validateResource\(`, `void SecStaticCode::ValidationContext::reportProblem\(`, `void SecStaticCode::CollectingContext::reportProblem\(`, `void SecStaticCode::CollectingContext::throwMe\(`}},
		{"cs_utils.cpp", "security_systemkeychain", "2b4c65b1074521e9c1dd2c8dc7fbf45dd775ec70", "src/", []string{`void diagnose\(const char \*context, OSStatus rc, CFDictionaryRef info\)`, `static void diagnose1\(const char \*type, CFTypeRef value\)`}},
	} {
		data := read(".research/apple/" + source.file)
		sources[source.file] = map[string]string{"url": "https://github.com/apple-oss-distributions/" + source.repo + "/blob/" + source.commit + "/" + source.path + source.file, "sha256": hash(data)}
		for _, pattern := range source.patterns {
			body := regexp.MustCompile(`(?ms)^` + pattern + `[^\n]*\n\{.*?^}`).Find(data)
			if len(body) == 0 {
				panic("missing complete body " + pattern)
			}
			excerpts[pattern] = hash(body)
			unit += "\n" + string(body) + "\n"
		}
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-fblocks", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignResourceResearch", "-"), &ast))
		functions := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "CXXMethodDecl" && n.Kind != "FunctionDecl" {
				return
			}
			kinds, refs := map[string]int{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.Kind == "DeclRefExpr" && c.ReferencedDecl != nil {
					refs[c.ReferencedDecl.Name]++
				}
				if c.Kind == "MemberExpr" {
					refs[c.Name]++
				}
			})
			if kinds["CompoundStmt"] > 0 {
				functions[n.MangledName] = map[string]any{"ast_kinds": kinds, "references": refs}
			}
		})
		if len(functions) != 8 {
			panic(fmt.Sprintf("incomplete AST: %d", len(functions)))
		}
		targets[target] = functions
	}
	record := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-resource-verification.go")), "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk), "sources": sources, "excerpt_sha256": excerpts, "translation_unit_sha256": hash([]byte(unit)), "targets": targets, "scope": "Eight complete verbatim Apple bodies: resource loading, optional-resource checks, individual resource validation, immediate and collecting error contexts, collector throw, and two diagnostic output functions. Real SDK/CoreFoundation declarations; private code/resource/hash/file/lock/CF wrapper interfaces, private flags and POSIX aliases are declaration-only shims; tracing is a no-op. ASTs establish added/modified/missing classification, optional missing resources, first collected status and array append order, and grouped verbose output on stdout. The asynchronous traversal is read as source but is not reconstructed in this translation unit; repeated native probes establish unstable within-group ordering. Full rule sets, strict/xattr policy, filesystem races and native scheduling remain outside this profile. Production has no SDK or native runtime dependency."}
	b, e := json.MarshalIndent(record, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-resource-verification.json", append(b, '\n'), 0644))
	fmt.Println("Wrote eight complete Apple resource bodies on two targets")
}
