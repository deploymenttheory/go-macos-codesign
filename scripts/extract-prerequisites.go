//go:build ignore

// Research only: retain complete Apple bodies exposing live-service boundaries.
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
func run(input, command string, args ...string) []byte {
	c := exec.Command(command, args...)
	c.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, e := c.Output()
	if e != nil {
		panic(fmt.Sprintf("%s: %v: %s", command, e, stderr.String()))
	}
	return b
}

type node struct {
	Kind, Name, MangledName string
	ReferencedDecl          *struct{ Name string }
	Inner                   []node
}

func walk(n node, visit func(node)) {
	visit(n)
	for _, c := range n.Inner {
		walk(c, visit)
	}
}
func main() {
	const revision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
	unit := `#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <string>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CodeSigning.h>
#define secinfo(...) ((void)0)
#define secerror(...) ((void)0)
#define secnotice(...) ((void)0)
#define DTRACK(...) ((void)0)
#define CODESIGN_EVAL_DYNAMIC_ROOT(...) ((void)0)
namespace CodesignPrerequisiteResearch {
template<class T> struct CFRef { CFRef(); CFRef(T); operator T() const; T get() const; T& aref(); T* take(); void take(T); T yield(); CFRef& operator=(T); };
struct MacOSError { static void check(OSStatus); [[noreturn]] static void throwMe(OSStatus); };
using SecCodeRemoteSignHandler=void*;
struct CodeDirectory { CFDataRef cdhash() const; unsigned hashType; };
struct Requirement { struct Context { const CodeDirectory* directory; CFDataRef packageChecksum; SecCSDigestAlgorithm packageAlgorithm; }; };
enum {kSecAssessmentTicketFlagDefault=0,kSecAssessmentTicketFlagForceOnlineCheck=1,cdTicketSlot=0x10002};
bool SecAssessmentTicketRegister(CFDataRef,CFErrorRef*);
bool SecAssessmentTicketLookup(CFDataRef,SecCSDigestAlgorithm,unsigned,double*,CFErrorRef*);
OSStatus doRemoteSigning(const CodeDirectory*,CFDictionaryRef,CFArrayRef,CFAbsoluteTime,CFArrayRef,SecCodeRemoteSignHandler,CFDataRef*);
struct BlobCore { size_t length() const; };
std::string cfString(CFURLRef);
struct AutoFileDesc { AutoFileDesc(std::string,int); void writeAll(const BlobCore&); };
struct SignatureDatabaseWriter { void storeCode(BlobCore*,const char*); };
struct SecCodeSigner {
 struct Signer { bool emitSigningTime,useRemoteSigning; CFAbsoluteTime signingTime; CFArrayRef rsCertChain; SecCodeRemoteSignHandler rsHandler;
 std::string path(); CFDataRef signCodeDirectoryRemote(const CodeDirectory*,CFDictionaryRef,CFArrayRef);
 void setupRemoteSigning(CFArrayRef,SecCodeRemoteSignHandler); };
 CFRef<CFTypeRef> mDetached; void returnDetachedSignature(BlobCore*,Signer&);
};
struct EmbeddedSignatureBlob { CFDataRef component(int); };
struct DiskImageRep { EmbeddedSignatureBlob* mSigningData; void registerStapledTicket(); CFDataRef copyStapledTicket(); };
struct DiskRep { struct ToleratedErrors {}; void strictValidate(const CodeDirectory*,ToleratedErrors,SecCSFlags); void strictValidateStructure(const CodeDirectory*,ToleratedErrors,SecCSFlags); };
struct SecStaticCode { void setValidationFlags(SecCSFlags); void validateNonResourceComponents(); DiskRep* diskRep(); const CodeDirectory* codeDirectory(); CFDataRef cdHash(); CFURLRef copyCanonicalPath(); void validateRequirements(unsigned,SecStaticCode*,OSStatus=0); };
bool SecIsInternalRelease();
extern const SecCSFlags kSecCSStrictValidateStructure;
struct SecCode { bool mIdentified; CFRef<CFDataRef> mCDHash; SecCode* host(); bool isRoot(); SecStaticCode* staticCode(); void identify(); uint32_t getGuestStatus(SecCode*); CFDataRef cdHash(); SecCodeStatus status(); void checkValidity(SecCSFlags); };
`
	selections := []struct{ file, name, pattern string }{
		{"notarization.cpp", "registerStapledTicketWithSystem", `(?ms)^void\nregisterStapledTicketWithSystem\(.*?^}`},
		{"notarization.cpp", "checkNotarizationServiceForRevocation", `(?ms)^bool\ncheckNotarizationServiceForRevocation\(.*?^}`},
		{"notarization.cpp", "isNotarized", `(?ms)^bool\nisNotarized\(.*?^}`},
		{"CodeSigner.cpp", "returnDetachedSignature", `(?ms)^void SecCodeSigner::returnDetachedSignature\(.*?^}`},
		{"signer.cpp", "signCodeDirectoryRemote", `(?ms)^CFDataRef\nSecCodeSigner::Signer::signCodeDirectoryRemote\(.*?^}`},
		{"signer.cpp", "setupRemoteSigning", `(?ms)^void\nSecCodeSigner::Signer::setupRemoteSigning\(.*?^}`},
		{"diskimagerep.cpp", "registerStapledTicket", `(?ms)^void DiskImageRep::registerStapledTicket\(.*?^}`},
		{"diskimagerep.cpp", "copyStapledTicket", `(?ms)^CFDataRef DiskImageRep::copyStapledTicket\(.*?^}`},
		{"Code.cpp", "cdHash", `(?ms)^CFDataRef SecCode::cdHash\(.*?^}`},
		{"Code.cpp", "status", `(?ms)^SecCodeStatus SecCode::status\(.*?^}`},
		{"Code.cpp", "checkValidity", `(?ms)^void SecCode::checkValidity\(.*?^}`},
	}
	sources, excerpts := map[string]any{}, map[string]string{}
	for _, s := range selections {
		data := read(".research/apple/" + s.file)
		body := regexp.MustCompile(s.pattern).Find(data)
		if len(body) == 0 {
			panic("missing complete body " + s.name)
		}
		sources[s.file] = map[string]string{"sha256": hash(data), "url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/" + s.file}
		excerpts[s.name] = hash(body)
		unit += "\n" + string(body) + "\n"
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignPrerequisiteResearch", "-"), &ast))
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
				functions[n.Name] = map[string]any{"ast_kinds": kinds, "references": refs}
			}
		})
		if len(functions) != len(selections) {
			panic(fmt.Sprintf("incomplete bodies: %d", len(functions)))
		}
		targets[target] = functions
	}
	headers := map[string]string{}
	for _, name := range []string{"CodeSigning.h", "CSCommon.h", "SecCode.h", "SecStaticCode.h"} {
		headers[name] = hash(read(filepath.Join(sdk, "System/Library/Frameworks/Security.framework/Headers", name)))
	}
	result := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-prerequisites.go")), "sources": sources, "excerpt_sha256": excerpts, "sdk_headers": headers, "translation_unit_sha256": hash([]byte(unit)), "targets": targets, "sdk": filepath.Base(sdk), "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "scope": "Eleven complete verbatim Apple bodies. SDK types/constants are real; CFRef, code/disk/database classes, remote handler, assessment functions, private slot/flag aliases and internal-release predicate are declaration-only shims; tracing is disabled. TARGET_OS_OSX branches are analyzed on both Darwin targets, not executed. ASTs prove call/control-flow dependencies, not current private service policy, ticket authentication or non-Darwin access. No production imports or bindings."}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-prerequisites.json", append(b, '\n'), 0644))
	fmt.Println("Wrote eleven complete prerequisite bodies for two Darwin targets")
}
