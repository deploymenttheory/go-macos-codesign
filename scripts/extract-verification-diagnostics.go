//go:build ignore

// Research only: complete Apple verification diagnostic/context bodies.
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
#include <cstdio>
#include <cerrno>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CodeSigning.h>
#define DTRACK(...) ((void)0)
namespace CodesignDiagnosticResearch {
using std::string;
using SecRequirementType=unsigned;
enum { cdInfoSlot=1, cdRequirementsSlot=2, cdResourceDirSlot=3 };
struct Requirement {};
struct Requirements { bool validateBlob() const; template<class T> const T* find(unsigned) const; };
struct SecRequirement { const Requirement* requirement() const; static const SecRequirement* required(SecRequirementRef); };
template<class T> struct CFRef { T& aref(); T get(); void take(T); operator T() const; };
template<class T> T cfmake(const char*, ...);
template<class T> struct SecPointer { SecPointer(T*); T* operator->(); operator T*(); };
struct ResourceSeal { CFStringRef requirement() const; };
struct ValidationContext { void reportProblem(OSStatus,CFStringRef,CFTypeRef); };
string cfString(CFURLRef);
struct CodeDirectory { using SpecialSlot=int; SpecialSlot maxSpecialSlot() const; };
struct Architecture { const char* displayName() const; };
struct MachO { Architecture architecture() const; };
struct Universal { MachO* architecture(); };
struct DiskRep { Universal* mainExecutableImage(); static DiskRep* bestGuess(string); };
struct CFTempString { CFTempString(const char*); operator CFStringRef() const; };
struct CSError { OSStatus error; CFRef<CFDictionaryRef> mInfoDict; void augment(CFStringRef,CFTypeRef); [[noreturn]] static void throwMe(OSStatus,CFStringRef,CFTypeRef); };
struct MacOSError { OSStatus error; [[noreturn]] static void throwMe(OSStatus); };
struct SecStaticCode {
 SecStaticCode(DiskRep*); ValidationContext* mResourcesValidContext;
 void initializeFromParent(SecStaticCode&); void staticValidate(SecCSFlags,const SecRequirement*);
 void validateNestedCode(CFURLRef,const ResourceSeal&,SecCSFlags,bool);
 void validateOtherVersions(CFURLRef,SecCSFlags,SecRequirementRef,SecStaticCode*);
 void staticValidateCore(SecCSFlags,const SecRequirement*);
 void validateNonResourceComponents(); void validateDirectory(); void validateTopDirectory(); void validateExecutable();
 DiskRep* diskRep(); const CodeDirectory* codeDirectory(); CFDataRef component(unsigned);
 const Requirements* internalRequirements(); const Requirement* internalRequirement(SecRequirementType);
 void validateRequirements(SecRequirementType,SecStaticCode*,OSStatus);
 bool satisfiesRequirement(const Requirement*,OSStatus); void validateRequirement(const Requirement*,OSStatus);
};
extern bool numericErrors, verbose;
extern const OSStatus errSecErrnoBase, errSecErrnoLimit;
string cfString(CFTypeRef, OSStatus=noErr);
void cssmPerror(const char*,OSStatus);
void diagnose(const char*,OSStatus,CFDictionaryRef);
static void diagnose1(const char*,CFTypeRef);
`
	data := read(".research/apple/StaticCode.cpp")
	excerpts := map[string]string{}
	for _, name := range []string{"staticValidateCore", "validateNestedCode"} {
		body := regexp.MustCompile(`(?ms)^(?:void |const Requirements? \*)SecStaticCode::` + name + `\(.*?^}`).Find(data)
		if len(body) == 0 {
			panic("missing complete body " + name)
		}
		excerpts[name] = hash(body)
		unit += "\n" + string(body) + "\n"
	}
	sources := map[string]any{}
	for _, source := range []struct {
		file, repo, commit, path string
		patterns                 []string
	}{
		{"StaticCode.cpp", "Security", "db15acbe6a7f257a859ad9a3bb86097bfe0679d9", "OSX/libsecurity_codesigning/lib/", []string{`static inline OSStatus errorForSlot\(`}},
		{"cs_utils.cpp", "security_systemkeychain", "2b4c65b1074521e9c1dd2c8dc7fbf45dd775ec70", "src/", []string{`void diagnose\(const char \*context, CFErrorRef err\)`, `static void diagnose1\(const char \*context, OSStatus rc\)`, `void diagnose\(const char \*context, OSStatus rc, CFDictionaryRef info\)`, `static void diagnose1\(const char \*type, CFTypeRef value\)`}},
		{"cserror.cpp", "Security", "db15acbe6a7f257a859ad9a3bb86097bfe0679d9", "OSX/libsecurity_codesigning/lib/", []string{`void CSError::augment\(`}},
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
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignDiagnosticResearch", "-"), &ast))
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
	record := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-verification-diagnostics.go")), "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk), "sources": sources, "excerpt_sha256": excerpts, "translation_unit_sha256": hash([]byte(unit)), "targets": targets, "scope": "Eight complete verbatim Apple bodies: static validation core, nested validation, special-slot error selection, four overloaded diagnostic functions, and exception context augmentation. Real SDK constants/CoreFoundation declarations; private class interfaces, cfmake and slot aliases are declaration-only shims; tracing is a no-op. Both targets establish error/path/architecture ordering, verbose resource details on stdout, parent-seal failures as altered resources and exception dictionary augmentation. Native acceptance establishes current CLI wording and arm64-first selection for the supported corpus. No full error inventory, CMS decoder, resource aggregation or native trust implementation is reconstructed. Production has no SDK or native runtime dependency."}
	b, e := json.MarshalIndent(record, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-verification-diagnostics.json", append(b, '\n'), 0644))
	fmt.Println("Wrote eight complete Apple diagnostic bodies on two targets")
}
