//go:build ignore

// Research only: complete Apple resource-suppression and structure bodies.
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
#include <vector>
#include <cassert>
#include <cstring>
#include <dirent.h>
#include <mach/machine.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CodeSigning.h>
#define DTRACK(...) ((void)0)
#define secinfo(...) ((void)0)
#define kSecCS_SIGNATUREFILE "CodeSignature"
namespace CodesignIgnoreResourcesResearch {
using std::string;
using SecRequirementType=unsigned;
enum { cdInfoSlot=1, cdRequirementsSlot=2, cdResourceDirSlot=3 };
struct Requirement {};
struct Requirements { bool validateBlob() const; template<class T> const T* find(unsigned) const; };
struct SecRequirement { const Requirement* requirement() const; static const SecRequirement* required(SecRequirementRef); };
template<class T> struct CFRef { CFRef(T); T& aref(); operator T() const; template<class U> U as() const; };
template<class T> struct SecPointer { SecPointer(T*); T* operator->(); operator T*(); };
struct ResourceSeal { CFStringRef requirement() const; };
struct ValidationContext { void reportProblem(OSStatus,CFStringRef,CFTypeRef); };
string cfString(CFURLRef);
struct CodeDirectory { using SpecialSlot=int; SpecialSlot maxSpecialSlot() const; bool slotIsPresent(int) const; static const char* canonicalSlotName(unsigned); };
struct Architecture { const char* displayName() const; cpu_type_t cpuType() const; };
struct MachO { Architecture architecture() const; };
struct Universal { MachO* architecture(); bool narrowed(); Architecture bestNativeArch(); };
using ToleratedErrors=std::set<OSStatus>;
struct DiskRep { Universal* mainExecutableImage(); static DiskRep* bestGuess(string); void registerStapledTicket(); void strictValidate(const CodeDirectory*,const ToleratedErrors&,SecCSFlags); void strictValidateStructure(const CodeDirectory*,const ToleratedErrors&,SecCSFlags); };
struct CFTempString { CFTempString(const char*); operator CFStringRef() const; };
struct CSError { OSStatus error; void augment(CFStringRef,CFTypeRef); [[noreturn]] static void throwMe(OSStatus,CFStringRef,CFTypeRef); };
struct MacOSError { OSStatus error; [[noreturn]] static void throwMe(OSStatus); };
bool isFlagSet(SecCSFlags,SecCSFlags);
bool checkNotarizationServiceForRevocation(CFDataRef,SecCSDigestAlgorithm,CFAbsoluteTime*);
template<class T> T cfNumber(CFNumberRef);
extern const SecCSFlags kSecCSForceOnlineNotarizationCheck;
extern const SecCSFlags kSecCSStrictValidateStructure;
struct DirScanner { DirScanner(string); bool initialized(); dirent* getNext(); bool isRegularFile(dirent*); };
struct AutoFileDesc { AutoFileDesc(string); size_t fileSize(); };
bool pathFileSystemUsesXattrFiles(const char*);
bool pathIsValidXattrFile(string,const char*);
struct BundleDiskRep { std::set<unsigned> mUsedComponents; string mMetaPath; void validateMetaDirectory(const CodeDirectory*,SecCSFlags); string metaPath(const char*); void recordStrictError(OSStatus); };
struct SecStaticCode {
 bool mStaplingChecked,mNotarizationChecked; DiskRep* mRep; SecCSFlags mFlags,mValidationFlags;
 CFAbsoluteTime mNotarizationDate; ToleratedErrors mTolerateErrors;
 void setValidationFlags(SecCSFlags); bool validationCannotUseNetwork(); CFDataRef cdHash(); unsigned hashAlgorithm();
 void prepareProgress(size_t); size_t estimateResourceWorkload(); void reportProgress();
 void handleOtherArchitectures(void(^)(SecStaticCode*)); CFTypeRef reportEvent(CFStringRef,CFTypeRef);
 void validateResources(SecCSFlags);
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
	excerpts := map[string]string{}
	sources := map[string]any{}
	for _, source := range []struct {
		file, class string
		names       []string
	}{
		{"StaticCode.cpp", "SecStaticCode", []string{"staticValidate", "staticValidateCore", "validateNonResourceComponents"}},
		{"bundlediskrep.cpp", "BundleDiskRep", []string{"validateMetaDirectory"}},
	} {
		data := read(".research/apple/" + source.file)
		sources[source.file] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/" + source.file, "sha256": hash(data)}
		for _, name := range source.names {
			body := regexp.MustCompile(`(?ms)^void ` + source.class + `::` + name + `\(.*?^}`).Find(data)
			if len(body) == 0 {
				panic("missing complete body " + name)
			}
			excerpts[source.class+"::"+name] = hash(body)
			unit += "\n" + string(body) + "\n"
		}
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-fblocks", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignIgnoreResourcesResearch", "-"), &ast))
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
		if len(functions) != 4 {
			panic(fmt.Sprintf("incomplete AST: %d", len(functions)))
		}
		targets[target] = functions
	}
	record := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-ignore-resources.go")), "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk), "sources": sources, "excerpt_sha256": excerpts, "translation_unit_sha256": hash([]byte(unit)), "targets": targets, "scope": "Four complete verbatim Apple bodies: staticValidate, staticValidateCore, validateNonResourceComponents and validateMetaDirectory. Real SDK flags, errors, CoreFoundation, Mach types, C++ and blocks; private interfaces, private flag symbols and slot aliases are declaration-only shims; tracing is a no-op. TARGET_OS_OSX is not overridden, preserving the notarization branch. ASTs establish resource suppression after per-architecture integrity checks and before retained strict structure checks; non-resource slots are still loaded, and metadirectory allowlisting is independent of envelope validation. Native CLI probes determine flag applicability, diagnostics, self/explicit requirement stages and supported filesystem outcomes. These ASTs do not reconstruct the full trust engine, filesystem, current private CLI or implement notarization. Production has no SDK/native runtime dependency."}
	b, e := json.MarshalIndent(record, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-ignore-resources.json", append(b, '\n'), 0644))
	fmt.Println("Wrote four complete Apple resource-suppression bodies on two targets")
}
