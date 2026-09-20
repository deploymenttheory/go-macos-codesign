//go:build ignore

// Research only: analyze Apple's CLI path resolution and file representation.
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
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CodeSigning.h>
namespace CodesignPathResearch {
using std::string;
struct UnixError { [[noreturn]] static void throwMe(); };
struct MacOSError { static void check(OSStatus); };
struct Architecture { operator bool() const; int cpuType() const; int cpuSubtype() const; };
template <typename T> struct CFRef { operator T() const; CFRef& operator=(T); };
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
`
	sources, hashes := map[string]any{}, map[string]string{}
	for _, source := range []struct {
		name, url string
		functions []string
	}{
		{"cs_utils.cpp", "https://github.com/apple-oss-distributions/security_systemkeychain/blob/2b4c65b1074521e9c1dd2c8dc7fbf45dd775ec70/src/cs_utils.cpp", []string{"cleanPath", "staticCodePath"}},
		{"singlediskrep.cpp", "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/singlediskrep.cpp", []string{"copyCanonicalPath", "mainExecutablePath", "recommendedIdentifier"}},
	} {
		data := read(".research/apple/" + source.name)
		sources[source.name] = map[string]string{"url": source.url, "sha256": hash(data)}
		for _, name := range source.functions {
			excerpt := regexp.MustCompile(`(?ms)^(?:std::string|string|CFURLRef|SecStaticCodeRef) (?:SingleDiskRep::)?` + name + `\(.*?^}`).Find(data)
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
		if len(functions) != 5 {
			panic("incomplete AST")
		}
		targets[target] = functions
	}
	record := map[string]any{
		"schema": 1, "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk),
		"scope":   "Five complete verbatim function bodies: CLI cleanPath/staticCodePath plus SingleDiskRep canonical path, executable path and identifier. Real SDK declarations supply realpath, PATH_MAX, CoreFoundation and public Security APIs/constants. Private error, Architecture, CFRef, CFTempURL, dictionary helper and SingleDiskRep interfaces are declaration-only shims. AST records realpath before static-code creation and common path storage for display and identifier; it does not execute Apple source or compile all Security. Native acceptance independently tests aliases and physical-parent resolution. Production uses pure Go filepath resolution and go-apfs-v2 metadata writes, with no Apple runtime or SDK dependency.",
		"sources": sources, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets,
	}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-paths.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-paths.json: five path functions on two targets")
}
