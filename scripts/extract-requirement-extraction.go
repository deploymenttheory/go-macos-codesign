//go:build ignore

// Research only: analyze complete pinned Apple requirement selection/dump bodies.
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
#include <cstdarg>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecBase.h>
#include <Security/CSCommon.h>
namespace CodesignRequirementResearch {
using std::string;
using SecRequirementType=unsigned;
enum { kSecRequirementTypeCount=6, kSecDesignatedRequirementType=3, cdRequirementsSlot=2, kSecCodeSignatureAdhoc=2, opOr=7, kSecCodeSignatureNoHash=0 };
template<typename T> struct CFRef { CFRef(); CFRef(T); operator T() const; void take(T); };
struct CodeDirectory {};
struct Requirement {
 static const unsigned typeMagic=0xfade0c00; static const char* typeNames[];
 struct Maker { struct Chain { Chain(Maker&,unsigned); void add(); }; void cdhash(CFDataRef); const Requirement* make(); };
 struct Context { Context(CFArrayRef,CFDictionaryRef,CFDictionaryRef,string,const CodeDirectory*,void*,unsigned,bool,CFDateRef,string); };
};
struct Requirements { unsigned magic() const; bool validateBlob() const; unsigned count() const; unsigned type(unsigned) const;
 template<typename T> const T* find(unsigned) const; template<typename T> const T* blob(unsigned) const;
};
struct Dumper { Dumper(const Requirement*,bool); void expr(); string value();
 string mOutput; void print(const char*,...);
 static string dump(const Requirement*,bool=false); static string dump(const Requirements*,bool=false);
};
struct MacOSError { [[noreturn]] static void throwMe(OSStatus); };
struct DRMaker { DRMaker(const Requirement::Context&); const Requirement* make(); };
struct SecStaticCode {
 const Requirement* mDesignatedReq; CFDataRef component(unsigned);
 const Requirements* internalRequirements(); const Requirement* internalRequirement(SecRequirementType);
 const Requirement* designatedRequirement(); const Requirement* defaultDesignatedRequirement();
 bool flag(unsigned); CFArrayRef cdHashes(); void handleOtherArchitectures(void (^)(SecStaticCode*));
 void validateDirectory(); CFAbsoluteTime signingTimestamp(); CFArrayRef certificates();
 CFDictionaryRef infoDictionary(); CFDictionaryRef entitlements(); string identifier(); string teamID(); const CodeDirectory* codeDirectory();
};
`
	sources, hashes := map[string]any{}, map[string]string{}
	for _, source := range []struct {
		name      string
		functions []string
	}{
		{"StaticCode.cpp", []string{"SecStaticCode::internalRequirements", "SecStaticCode::internalRequirement", "SecStaticCode::designatedRequirement", "SecStaticCode::defaultDesignatedRequirement"}},
		{"reqdumper.cpp", []string{"Dumper::dump", "Dumper::print"}},
	} {
		data := read(".research/apple/" + source.name)
		sources[source.name] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/" + source.name, "sha256": hash(data)}
		for _, name := range source.functions {
			pattern := `(?ms)^(?:const Requirements? \*|string |void )` + name + `\(.*?^}`
			if name == "Dumper::dump" {
				pattern = `(?ms)^string Dumper::dump\(const Requirements \*.*?^}`
			}
			excerpt := regexp.MustCompile(pattern).Find(data)
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
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-fblocks", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignRequirementResearch", "-"), &ast))
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
	record := map[string]any{"schema": 1, "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk),
		"scope":   "Six complete verbatim Apple bodies on two targets: internalRequirements, internalRequirement, designatedRequirement, defaultDesignatedRequirement, Dumper's Requirements-set overload and Dumper::print. Real SDK CoreFoundation, Security errors and C++ library declarations; private blob, maker, context, CFRef and StaticCode interfaces are declaration-only shims. The AST establishes explicit/default selection, selected-first ad-hoc hash collection across architectures, certificate-context delegation, ordered set labels, newline output and a 256-byte printf buffer. It does not implement the private current CLI, DRMaker internals or every expression opcode. Destination truncation, diagnostics, implicit comments and extraction ordering come from native differential acceptance. Production has no SDK/runtime dependency.",
		"sources": sources, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-requirement-extraction.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-requirement-extraction.json: six complete requirement functions on two targets")
}
