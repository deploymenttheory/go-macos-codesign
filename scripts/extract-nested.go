//go:build ignore

// Research only: complete pinned Apple nested-code and identifier method bodies.
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

const revision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"

func must(err error) {
	if err != nil {
		panic(err)
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
	Kind, Name, Opcode string
	Value              any
	Inner              []node
}

func walk(n node, f func(node)) {
	f(n)
	for _, c := range n.Inner {
		walk(c, f)
	}
}
func main() {
	methods := []struct{ file, class, name string }{
		{"signer.cpp", "SecCodeSigner::Signer::", "signNested"},
		{"CodeSigner.cpp", "SecCodeSigner::", "sign"},
		{"StaticCode.cpp", "SecStaticCode::", "validateNestedCode"},
		{"machorep.cpp", "MachORep::", "identificationFor"},
		{"signer.cpp", "SecCodeSigner::Signer::", "uniqueName"},
	}
	sources := map[string][]byte{}
	excerpts := map[string][]byte{}
	unit := `#include <string>
#include <cstring>
#include <cstdio>
#include <cstdint>
using std::string;
using CFDataRef=void*; using CFMutableDictionaryRef=void*; using CFURLRef=void*;
using SecRequirementRef=void*; using CFIndex=long; using UInt8=unsigned char; using SecCSFlags=unsigned;
template<class T> struct CFRef { CFRef(T = nullptr); operator T() const; T& aref(); };
template<class T> struct SecPointer { SecPointer(T*); T* operator->(); operator T*(); };
template<class T,class... A> T cfmake(const char*,A...);
const UInt8* CFDataGetBytePtr(CFDataRef); CFIndex CFDataGetLength(CFDataRef);
CFDataRef makeCFData(const void*,size_t); CFURLRef CFTempURL(const string&); string cfString(CFURLRef);
enum {kSecCSSignNestedCode=1,kSecCSSignPreserveSignature=2,kSecCodeSignatureLinkerSigned=4,
 kSecCSRemoveSignature=8,kSecCSEditSignature=16,kSecCSStripDisallowedXattrs=32,
 kSecCSDefaultFlags=0,kSecCSCheckNestedCode=64,kSecCSBasicValidateOnly=128,kSecCSQuickCheck=256,
 kSecCSRestrictToAppLike=512,kSecCSStrictValidate=1024,errSecCSUnsigned=1,kSecCFErrorPath=2,
 errSecCSInvalidObjectRef=3,errSecCSResourcesInvalid=4,errSecCSBadFrameworkVersion=5,
 errSecCSReqFailed=6,errSecCSBadNestedCode=7,kSecCFErrorResourceAltered=8,errSecCSSignatureInvalid=9,
 LC_UUID=0x1b};
#define secinfo(...) ((void)0)
struct CommonError { int osStatus() const; };
struct MacOSError {int error; [[noreturn]] static void throwMe(int);};
struct CSError {int error; void augment(int,CFURLRef); [[noreturn]] static void throwMe(int,int,CFURLRef);};
struct DiskRep {static void* bestGuess(const string&); CFDataRef identification();};
struct ResourceSeal {void* requirement() const;};
struct ResourceContext {void reportProblem(int,int,CFURLRef);};
struct SecStaticCode {
 SecStaticCode(void*); bool isSigned();bool flag(unsigned);void setValidationFlags(unsigned);void resetValidity();
 void* designatedRequirement();CFDataRef cdHash();void initializeFromParent(SecStaticCode&);void staticValidate(unsigned,void*);
 void validateNestedCode(CFURLRef,const ResourceSeal&,SecCSFlags,bool);
 void validateOtherVersions(CFURLRef,SecCSFlags,SecRequirementRef,SecStaticCode*);
 ResourceContext* mResourcesValidContext;
};
int SecRequirementCreateWithString(void*,unsigned,SecRequirementRef*);
struct SecRequirement {static void* required(SecRequirementRef);};
struct Dumper {static string dump(void*);};
struct SecCodeSigner {
 unsigned mOpFlags;bool valid();void sign(SecStaticCode*,SecCSFlags);
 struct Signer {
  Signer(SecCodeSigner&,SecStaticCode*);void remove(unsigned);void edit(unsigned);void sign(unsigned);
  CFMutableDictionaryRef signNested(const string&,const string&);unsigned signingFlags();
  SecCodeSigner& state;DiskRep* rep;string uniqueName() const;
 };
};
struct load_command {uint32_t cmd,cmdsize;};
struct uuid_command {uint32_t cmd,cmdsize;unsigned char uuid[16];};
struct mach_header {uint32_t magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags;};
struct MachO {const load_command* findCommand(int);uint32_t flip(uint32_t);mach_header& header();void* loadCommands();size_t commandLength();};
struct MachORep {CFDataRef identificationFor(MachO*);};
struct SHA1 {using Digest=unsigned char[20];void operator()(const void*,size_t);void finish(Digest&);};
`
	for _, m := range methods {
		if sources[m.file] == nil {
			sources[m.file] = read(".research/apple/" + m.file)
		}
		e := regexp.MustCompile(`(?ms)^[a-zA-Z_:]+ ` + regexp.QuoteMeta(m.class+m.name) + `\(.*?\n}`).Find(sources[m.file])
		if len(e) == 0 {
			panic("missing complete method " + m.name)
		}
		excerpts[m.name] = e
		unit += "\n" + string(e)
	}
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"), &ast))
		facts := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "CXXMethodDecl" || excerpts[n.Name] == nil {
				return
			}
			body := false
			for _, c := range n.Inner {
				body = body || c.Kind == "CompoundStmt"
			}
			if !body {
				return
			}
			kinds, members, operators := map[string]int{}, map[string]int{}, map[string]int{}
			literals := []string{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.Kind == "MemberExpr" {
					members[c.Name]++
				}
				if c.Opcode != "" {
					operators[c.Opcode]++
				}
				if c.Kind == "StringLiteral" {
					literals = append(literals, fmt.Sprint(c.Value))
				}
			})
			facts[n.Name] = map[string]any{"ast_kinds": kinds, "members": members, "operators": operators, "literals": literals}
		})
		if len(facts) != len(methods) {
			panic("incomplete AST")
		}
		targets[target] = facts
	}
	records := map[string]any{}
	hashes := map[string]string{}
	for name, data := range sources {
		records[name] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/" + name, "sha256": hash(data)}
	}
	for name, data := range excerpts {
		hashes[name] = hash(data)
	}
	result := map[string]any{"schema": 1, "scope": "Five complete verbatim Apple method bodies parsed through Clang with explicit interface, error-code, flag and logging shims. Flag shim values are placeholders, not extracted constants. AST facts establish source control flow, not execution of Security services or full nested-code policy.", "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sources": records, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-nested.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-nested.json: two-target nested-code and identifier AST")
}
