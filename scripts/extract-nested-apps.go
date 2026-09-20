//go:build ignore

// Research only: native bundle boundaries and shallow metadata validation.
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
	resources, header, code := read(".research/apple/resources.cpp"), read(".research/apple/resources.h"), read(".research/apple/StaticCode.cpp")
	excerpts := map[string][]byte{
		"scan":                          regexp.MustCompile(`(?ms)^void ResourceBuilder::scan\(Scanner next, Scanner unhandledScanner\).*?\n}`).Find(resources),
		"validateNonResourceComponents": regexp.MustCompile(`(?ms)^void SecStaticCode::validateNonResourceComponents\(\).*?\n}`).Find(code),
		"findStringEndingNoCase":        regexp.MustCompile(`(?ms)^static bool findStringEndingNoCase\(.*?\n}`).Find(resources),
	}
	flags := regexp.MustCompile(`(?s)enum \{\s*optional =.*?\n\s*};`).Find(header)
	if len(flags) == 0 {
		panic("resource flag declaration missing")
	}
	unit := `#include <string>
#include <cstring>
#include <strings.h>
#include <cassert>
#include <cstdint>
#include <fts.h>
using std::string;
#define secinfo(...) ((void)0)
int GKBIS_Num_files,GKBIS_Dot_underbar_Present,GKBIS_DS_Store_Present,GKBIS_Num_symlinks,GKBIS_Num_dirs,GKBIS_Num_localizations;
enum{errSecCSDSStoreSymlink=1,errSecCSSignatureNotVerifiable=2,errSecCSResourceNotSupported=3,cdResourceDirSlot=3};
struct MacOSError{[[noreturn]] static void throwMe(int);};
struct ResourceBuilder{
 FLAGS
 struct Rule{uint32_t flags;};
 using Scanner=void(*)(FTSENT*,uint32_t,string,Rule*);
 string mRoot,mRelBase;FTS* mFTS;bool mCheckUnreadable,mCheckUnknownType;
 Rule* findRule(const string&);void scan(Scanner,Scanner);
};
struct CodeDirectory{using SpecialSlot=int;SpecialSlot maxSpecialSlot() const;};
struct SecStaticCode{void validateDirectory();const CodeDirectory* codeDirectory();void* component(int);void validateNonResourceComponents();};
`
	unit = strings.Replace(unit, "FLAGS", string(flags), 1)
	for _, name := range []string{"findStringEndingNoCase", "scan", "validateNonResourceComponents"} {
		if len(excerpts[name]) == 0 {
			panic("missing complete body " + name)
		}
		unit += "\n" + string(excerpts[name])
	}
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"), &ast))
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
	for name, data := range map[string][]byte{"resources.cpp": resources, "resources.h": header, "StaticCode.cpp": code} {
		sources[name] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/" + name, "sha256": hash(data)}
	}
	for name, data := range excerpts {
		hashes[name] = hash(data)
	}
	hashes["resource_flags"] = hash(flags)
	result := map[string]any{"schema": 1, "scope": "Complete verbatim ResourceBuilder::scan(Scanner,Scanner), findStringEndingNoCase and SecStaticCode::validateNonResourceComponents bodies, plus resource flag declarations, parsed with SDK FTS declarations. Interface, error-code, resource-slot and logging shims are explicit. Error/slot shim values are not extracted constants. AST facts establish source control flow, not execution or full native bundle policy.", "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sources": sources, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-nested-apps.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-nested-apps.json: two-target bundle boundary and shallow metadata AST")
}
