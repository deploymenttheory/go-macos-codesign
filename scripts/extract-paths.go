//go:build ignore

// Research only: analyze Apple's CLI path resolution, notices and file representation.
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
func read(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(input, name string, args ...string) []byte {
	c := exec.Command(name, args...)
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
	Kind, Name     string
	ReferencedDecl *struct{ Name string }
	Inner          []node
}

func walk(n node, f func(node)) {
	f(n)
	for _, c := range n.Inner {
		walk(c, f)
	}
}

func main() {
	unit := `#include <string>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CodeSigning.h>
namespace CodesignPathResearch {
using std::string;
extern unsigned verbose;
struct UnixError { [[noreturn]] static void throwMe(); };
struct MacOSError { static void check(OSStatus); [[noreturn]] static void throwMe(OSStatus); };
struct Architecture { operator bool() const; int cpuType() const; int cpuSubtype() const; };
template <typename T> struct CFRef { operator T() const; CFRef& operator=(T); void take(T); };
CFMutableDictionaryRef makeCFMutableDictionary();
void cfadd(CFMutableDictionaryRef, const char*, ...);
struct CFTempURL { CFTempURL(const std::string&); operator CFURLRef() const; };
CFURLRef makeCFURL(const std::string&);
struct SigningContext {};
struct SingleDiskRep {
 std::string mPath;
 CFURLRef copyCanonicalPath();
 std::string mainExecutablePath();
 std::string recommendedIdentifier(const SigningContext&);
 static std::string canonicalIdentifier(const std::string&);
};
struct DiskRep { CFDataRef signature(); };
struct SecStaticCode {
 CFRef<CFDataRef> mSignature; DiskRep* mRep; CFArrayRef mCertChain;
 void validateDirectory(); CFDataRef signature(); CFArrayRef certificates();
};
`
	sources, hashes := map[string]any{}, map[string]string{}
	for _, source := range []struct {
		name, url string
		functions []string
	}{
		{"cs_utils.cpp", "https://github.com/apple-oss-distributions/security_systemkeychain/blob/2b4c65b1074521e9c1dd2c8dc7fbf45dd775ec70/src/cs_utils.cpp", []string{"cleanPath", "staticCodePath", "note"}},
		{"singlediskrep.cpp", "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/singlediskrep.cpp", []string{"copyCanonicalPath", "mainExecutablePath", "recommendedIdentifier"}},
		{"StaticCode.cpp", "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/StaticCode.cpp", []string{"signature", "certificates"}},
	} {
		data := read(".research/apple/" + source.name)
		sources[source.name] = map[string]string{"url": source.url, "sha256": hash(data)}
		for _, name := range source.functions {
			excerpt := regexp.MustCompile(`(?ms)^(?:void|std::string|string|CFURLRef|CFDataRef|CFArrayRef|SecStaticCodeRef) (?:(?:SingleDiskRep|SecStaticCode)::)?` + name + `\(.*?^}`).Find(data)
			if len(excerpt) == 0 {
				panic("missing complete function " + name)
			}
			hashes[name] = hash(excerpt)
			unit += "\n" + string(excerpt) + "\n"
		}
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignPathResearch", "-"), &ast))
		functions := map[string]any{}
		walk(ast, func(n node) {
			if (n.Kind != "FunctionDecl" && n.Kind != "CXXMethodDecl") || hashes[n.Name] == "" {
				return
			}
			kinds, references := map[string]int{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.Kind == "DeclRefExpr" && c.ReferencedDecl != nil {
					references[c.ReferencedDecl.Name]++
				}
				if c.Kind == "MemberExpr" {
					references[c.Name]++
				}
			})
			if kinds["CompoundStmt"] > 0 {
				functions[n.Name] = map[string]any{"ast_kinds": kinds, "references": references}
			}
		})
		if len(functions) != 8 {
			panic("incomplete AST")
		}
		targets[target] = functions
	}
	record := map[string]any{
		"schema": 1, "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk),
		"scope":   "Eight complete verbatim function bodies: CLI cleanPath/staticCodePath/note, three SingleDiskRep path/identifier methods and SecStaticCode signature/certificates accessors. Real SDK declarations supply realpath, PATH_MAX, stdio/variadic functions, CoreFoundation and public Security APIs/constants. Private error, Architecture, CFRef, CFTempURL, dictionary helper, disk-representation and static-code interfaces are declaration-only shims; verbose is an extern declaration. AST records physical-path resolution, verbosity-gated stderr notices, signature component retrieval and directory validation before returning a certificate chain. It does not extract validateDirectory, signingInformation or the unpublished current CLI signing/display call sites. Native acceptance independently establishes replacement notices and certificate extraction filenames, bytes, order and failures. Production uses pure Go path resolution, CMS/certificate decoding and go-apfs-v2 metadata writes, with no Apple runtime or SDK dependency.",
		"sources": sources, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets,
	}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-paths.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-paths.json: eight path/notice/signature functions on two targets")
}
