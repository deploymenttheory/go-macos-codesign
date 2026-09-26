//go:build ignore

// Research only: complete Apple requirement-verification control-flow bodies.
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
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CodeSigning.h>
#define DTRACK(...) ((void)0)
namespace CodesignVerificationResearch {
using std::string;
using SecRequirementType=unsigned;
enum { cdRequirementsSlot=2, cdResourceDirSlot=3 };
struct Requirement {};
struct Requirements { bool validateBlob() const; template<class T> const T* find(unsigned) const; };
struct SecRequirement { const Requirement* requirement() const; static const SecRequirement* required(SecRequirementRef); };
template<class T> struct CFRef { T& aref(); operator T() const; };
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
struct CSError { OSStatus error; void augment(CFStringRef,CFTypeRef); [[noreturn]] static void throwMe(OSStatus,CFStringRef,CFTypeRef); };
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
`
	data := read(".research/apple/StaticCode.cpp")
	excerpts := map[string]string{}
	for _, name := range []string{"staticValidateCore", "validateNonResourceComponents", "validateRequirements", "validateRequirement", "internalRequirements", "validateNestedCode"} {
		body := regexp.MustCompile(`(?ms)^(?:void |const Requirements? \*)SecStaticCode::` + name + `\(.*?^}`).Find(data)
		if len(body) == 0 {
			panic("missing complete body " + name)
		}
		excerpts[name] = hash(body)
		unit += "\n" + string(body) + "\n"
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignVerificationResearch", "-"), &ast))
		functions := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "CXXMethodDecl" {
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
		if len(functions) != 6 {
			panic(fmt.Sprintf("incomplete AST: %d", len(functions)))
		}
		targets[target] = functions
	}
	record := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-requirement-verification.go")), "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk), "sources": map[string]any{"StaticCode.cpp": map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/StaticCode.cpp", "sha256": hash(data)}}, "excerpt_sha256": excerpts, "translation_unit_sha256": hash([]byte(unit)), "targets": targets, "scope": "Six complete verbatim Apple bodies: static validation core, non-resource component validation, contextual/external requirement validation, internal set access and nested requirement enforcement. Real SDK flags, error constants, CoreFoundation and C++ declarations; private code/requirement/Mach-O/exception interfaces and slot aliases are declaration-only shims, and tracing is a no-op. Both target ASTs establish component checks before a supplied requirement, the absence of an automatic self-DR check in the core and separate contextual enforcement, including mapping a failed parent-sealed requirement to invalid nested code. The full trust engine, evaluator and current private CLI call sites are not reconstructed. Native probes establish verbosity-dependent self checks, explicit test ordering and architecture selection. Production has no SDK or native runtime dependency."}
	b, e := json.MarshalIndent(record, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-requirement-verification.json", append(b, '\n'), 0644))
	fmt.Println("Wrote six complete Apple verification bodies on two targets")
}
