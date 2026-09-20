//go:build ignore

// Research only: framework-root and symlink validation control flow.
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
	bundle, code, disk := read(".research/apple/bundlediskrep.cpp"), read(".research/apple/StaticCode.cpp"), read(".research/apple/diskrep.cpp")
	excerpts := map[string][]byte{
		"bestGuess":               regexp.MustCompile(`(?ms)^DiskRep \*DiskRep::bestGuess\(const char \*path, const Context \*ctx\).*?\n}`).Find(disk),
		"setup":                   regexp.MustCompile(`(?ms)^void BundleDiskRep::setup\(.*?\n}`).Find(bundle),
		"validateOtherVersions":   regexp.MustCompile(`(?ms)^void SecStaticCode::validateOtherVersions\(.*?\n}`).Find(code),
		"validateFrameworkRoot":   regexp.MustCompile(`(?ms)^void BundleDiskRep::validateFrameworkRoot\(.*?\n}`).Find(bundle),
		"checkMoved":              regexp.MustCompile(`(?ms)^void BundleDiskRep::checkMoved\(.*?\n}`).Find(bundle),
		"validateSymlinkResource": regexp.MustCompile(`(?ms)^void SecStaticCode::validateSymlinkResource\(.*?\n}`).Find(code),
		"remove":                  regexp.MustCompile(`(?ms)^void BundleDiskRep::Writer::remove\(\).*?\n}`).Find(bundle),
		"purgeMetaDirectory":      regexp.MustCompile(`(?ms)^void BundleDiskRep::Writer::purgeMetaDirectory\(\).*?\n}`).Find(bundle),
	}
	unit := `#include <string>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <cstdint>
#include <set>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sstream>
#include <sys/stat.h>
#include <fcntl.h>
#include <TargetConditionals.h>
using std::string;
using CFURLRef=const void*;using SecCSFlags=uint32_t;
using CFBundleRef=const void*;using CFDictionaryRef=const void*;using CFTypeRef=const void*;using CFStringRef=const void*;
using SecRequirementRef=const void*;
template<class T> struct CFRef {CFRef();CFRef(T);operator T() const;CFRef& operator=(T);void take(T);};
template<class T> using SecPointer=T*;
#define CFSTR(s) (s)
CFURLRef CFBundleCopyExecutableURL(CFBundleRef);CFURLRef _CFBundleCopyInfoPlistURL(CFBundleRef);
CFURLRef CFBundleCopySupportFilesDirectoryURL(CFBundleRef);CFURLRef CFTempURL(string);
CFBundleRef _CFBundleCreateUnique(const void*,CFURLRef);
CFBundleRef _CFBundleCreateWithExecutableURLIfMightBeBundle(const void*,CFURLRef);
CFDictionaryRef CFBundleGetInfoDictionary(CFBundleRef);CFTypeRef CFDictionaryGetValue(CFDictionaryRef,CFTypeRef);
bool CFEqual(CFTypeRef,CFTypeRef);int CFGetTypeID(CFTypeRef);int CFStringGetTypeID();
string cfStringRelease(CFURLRef);CFURLRef makeCFURL(string,bool=false,CFURLRef=nullptr);
string findDistFile(string);void checkPlainFile(int,string);
struct Context{const char* version;bool skipFrameworkCheck,fileOnly;};
struct DiskRep{static DiskRep* bestFileGuess(string,const Context*);static DiskRep* bestGuess(const char*,const Context* = nullptr);int fd();string format();CFURLRef copyCanonicalPath();};
struct FileDiskRep:DiskRep{FileDiskRep(const char*);};
struct AutoFileDesc{AutoFileDesc(const char*,int);};
struct MachORep:DiskRep{static bool candidate(AutoFileDesc&);MachORep(const char*,const Context*);};
struct DiskImageRep:DiskRep{static bool candidate(AutoFileDesc&);DiskImageRep(const char*);};
struct EncDiskImageRep:DiskRep{static bool candidate(AutoFileDesc&);EncDiskImageRep(const char*);};
struct DYLDCacheRep:DiskRep{static bool candidate(AutoFileDesc&);DYLDCacheRep(const char*);};
struct CommonError{int unixError() const;};
struct SecRequirement{static const void* required(SecRequirementRef);};
enum{errSecCSStaticCodeNotFound=10,errSecCSBadBundleFormat=11};
string cfString(CFURLRef);string CFTempString(const string&);
enum{errSecCSAmbiguousBundleFormat=1,errSecCSUnsealedFrameworkRoot=2,errSecCSBadResource=3,errSecCSInvalidSymlink=4,kSecCFErrorResourceAltered=5,errSecCSUnsealedAppRoot=6,kSecCSStrictValidate=1,kSecCSRestrictSymlinks=2};
struct MacOSError{[[noreturn]] static void throwMe(int);int error;};
struct UnixError{static void check(int);[[noreturn]] static void throwMe();};
struct ResourceBuilder{static string escapeRE(string);};
struct DirValidator {
 enum{directory=1,descend=2,symlink=4,file=8,noexec=16};
 void require(string,int);void require(string,int,string);
 void allow(string,int);void allow(string,int,string);void allow(string,int,string (^)(const string&,const string&));
 void validate(string,int);
};
struct CodeDirectory{using SpecialSlot=int;};
enum{cdSlotCount=16,cdSignatureSlot=65536};
struct ExecWriter{void remove();};
struct DirScanner{DirScanner(string);bool initialized();dirent* getNext();bool isRegularFile(dirent*);void unlink(dirent*,int);};
struct BundleDiskRep:DiskRep {
 BundleDiskRep(const char*,const Context*);BundleDiskRep(CFBundleRef,const Context*);
 bool mComponentsFromExecValid,mInstallerPackage,mAppLike;CFRef<CFBundleRef> mBundle;CFRef<CFURLRef> mMainExecutableURL;DiskRep* mExecRep;
 string mFormat;CFURLRef copyCanonicalPath();string mainExecutablePath();string resourcesRootPath();void setup(const Context*);
 void recordStrictError(int);void checkMoved(CFURLRef,CFURLRef);void validateFrameworkRoot(string);
 string mMetaPath;
 struct Writer{BundleDiskRep* rep;ExecWriter* execWriter;std::set<string> mWrittenFiles;void remove();void remove(CodeDirectory::SpecialSlot);void purgeMetaDirectory();};
};
struct ValidationContext{void reportProblem(int,int,string);};
struct ResourceScope{string root() const;bool includes(const char*) const;};
struct SecStaticCode{
 SecStaticCode(DiskRep*);DiskRep* diskRep();void initializeFromParent(SecStaticCode&);void staticValidate(SecCSFlags,const void*);
 void validateOtherVersions(CFURLRef,SecCSFlags,SecRequirementRef,SecStaticCode*);
 uint32_t mValidationFlags;std::set<int> mTolerateErrors;
 const SecStaticCode* mOuterScope;const ResourceScope* mResourceScope;
 void validateSymlinkResource(string,string,ValidationContext&,SecCSFlags);
};
`
	for _, name := range []string{"bestGuess", "setup", "checkMoved", "validateFrameworkRoot", "validateOtherVersions", "validateSymlinkResource", "remove", "purgeMetaDirectory"} {
		if len(excerpts[name]) == 0 {
			panic("missing complete body " + name)
		}
		unit += "\n" + string(excerpts[name])
	}
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-fblocks", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"), &ast))
		facts := map[string]any{}
		walk(ast, func(n node) {
			if (n.Kind != "CXXMethodDecl" && n.Kind != "FunctionDecl") || excerpts[n.Name] == nil {
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
		if len(facts) != len(excerpts) {
			panic("incomplete AST")
		}
		targets[target] = facts
	}
	sources, hashes := map[string]any{}, map[string]string{}
	for name, data := range map[string][]byte{"bundlediskrep.cpp": bundle, "StaticCode.cpp": code, "diskrep.cpp": disk} {
		sources[name] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/" + name, "sha256": hash(data)}
	}
	for name, data := range excerpts {
		hashes[name] = hash(data)
	}
	result := map[string]any{"schema": 1, "scope": "Complete verbatim DiskRep::bestGuess(const char*,const Context*), BundleDiskRep::setup, BundleDiskRep::checkMoved, BundleDiskRep::validateFrameworkRoot, SecStaticCode::validateOtherVersions, SecStaticCode::validateSymlinkResource, BundleDiskRep::Writer::remove() and BundleDiskRep::Writer::purgeMetaDirectory bodies parsed with real SDK filesystem declarations, TargetConditionals and C++ blocks. CoreFoundation, disk-representation/validation/writer interfaces, error codes, slots and flags are explicitly shimmed; shim numbers are not extracted constants. AST facts establish source control flow, not execution or complete bundle policy. Host acceptance separately establishes direct version-directory boundaries, Current resolution, version selection and nested alternate-version checking. Executable-path promotion and absolute/outer-scope resource links remain outside the Go profile.", "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sources": sources, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-bundle-layouts.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-bundle-layouts.json: two-target framework root and symlink AST")
}
