//go:build ignore

// Research only: pinned Apple bundle rules and resource hash naming through Clang.
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
	Kind, Name string
	Value      any
	Inner      []node
}

func walk(n node, f func(node)) {
	f(n)
	for _, v := range n.Inner {
		walk(v, f)
	}
}
func main() {
	bundle, resources, header := read(".research/apple/bundlediskrep.cpp"), read(".research/apple/resources.cpp"), read(".research/apple/resources.h")
	rules := regexp.MustCompile(`(?s)CFDictionaryRef BundleDiskRep::defaultResourceRules\(.*?\n}`).Find(bundle)
	naming := regexp.MustCompile(`(?s)std::string ResourceBuilder::hashName\(.*?\n}`).Find(resources)
	flags := regexp.MustCompile(`(?s)enum \{\s*optional =.*?\n\s*};`).Find(header)
	if len(rules) == 0 || len(naming) == 0 || len(flags) == 0 {
		panic("source excerpts missing")
	}
	unit := `#include <string>
#include <stdio.h>
using std::string;
using CFDictionaryRef = void*;
template<class T, class... A> T cfmake(const char*, A...);
enum {kSecCSSignV1=1,kSecCSSignOpaque=2,kSecCodeSignatureHashSHA1=1};
struct SigningContext { unsigned signingFlags() const; };
struct BundleDiskRep {bool mInstallerPackage; string resourcesRelativePath(); CFDictionaryRef defaultResourceRules(const SigningContext&);};
struct CodeDirectory {using HashAlgorithm=int;};
struct ResourceBuilder { FLAGS static std::string hashName(CodeDirectory::HashAlgorithm);};
` + string(rules) + "\n" + string(naming)
	unit = strings.Replace(unit, "FLAGS", string(flags), 1)
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"), &ast))
		methods := map[string]any{}
		enums := map[string]string{}
		walk(ast, func(n node) {
			if n.Kind == "EnumConstantDecl" {
				for _, name := range []string{"optional", "omitted", "nested", "exclusion", "softTarget", "user_controlled"} {
					if n.Name == name {
						walk(n, func(c node) {
							if c.Kind == "ConstantExpr" {
								enums[name] = fmt.Sprint(c.Value)
							}
						})
					}
				}
			}
			if n.Kind != "CXXMethodDecl" || n.Name != "defaultResourceRules" && n.Name != "hashName" {
				return
			}
			hasBody := false
			for _, c := range n.Inner {
				hasBody = hasBody || c.Kind == "CompoundStmt"
			}
			if !hasBody {
				return
			}
			literals := []string{}
			kinds := map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.Kind == "StringLiteral" {
					literals = append(literals, fmt.Sprint(c.Value))
				}
			})
			methods[n.Name] = map[string]any{"literals": literals, "ast_kinds": kinds}
		})
		if len(methods) != 2 || len(enums) != 6 {
			panic("incomplete AST")
		}
		targets[target] = map[string]any{"methods": methods, "flags": enums}
	}
	sources := map[string]any{}
	for name, data := range map[string][]byte{"bundlediskrep.cpp": bundle, "resources.cpp": resources, "resources.h": header} {
		sources[name] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/" + name, "sha256": hash(data)}
	}
	result := map[string]any{"schema": 1, "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "scope": "Verbatim defaultResourceRules and hashName methods and ResourceBuilder flags, with explicit interface/type/signing-flag shims. Source AST facts, not execution of Apple's bundle or trust services.", "sources": sources, "translation_unit_sha256": hash([]byte(unit)), "excerpt_sha256": map[string]string{"defaultResourceRules": hash(rules), "hashName": hash(naming), "flags": hash(flags)}, "targets": targets}
	out, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-bundles.json", append(out, '\n'), 0644))
	fmt.Println("Wrote spec/apple-bundles.json: two-target C++ resource-rule AST")
}
