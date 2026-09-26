//go:build ignore

// Research only: complete Apple requirement-default selection bodies.
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
#include <cstdlib>
#include <cassert>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <TargetConditionals.h>
namespace CodesignDefaultResearch {
using std::string;
void secinfo(const char*,const char*,...);
struct DERItem {}; extern DERItem oidOrganizationName;
CFStringRef SecCertificateCopySubjectAttributeValue(SecCertificateRef, DERItem*);
template<class T> struct CFRef { CFRef(T=nullptr); void take(T); operator T() const; };
struct SHA1 { using Digest=unsigned char[20]; };
void hashOfCertificate(SecCertificateRef,SHA1::Digest&);
bool isAppleCA(SecCertificateRef);
enum { opAnd=6 };
struct Requirement {
 enum { leafCert=0,anchorCert=-1 };
 struct Context { unsigned certCount() const; SecCertificateRef cert(int) const; string identifier; };
 struct Maker { void put(unsigned); void ident(string); Requirement* make(); };
};
struct Requirements { struct Maker { void add(unsigned,Requirement*); const Requirements* make(); }; };
struct DRMaker: Requirement::Maker {
 const Requirement::Context& ctx; DRMaker(const Requirement::Context&);
 Requirement* make(); void nonAppleAnchor(); void appleAnchor(); void anchor(int,SHA1::Digest&);
};
struct InternalRequirements {
 const Requirements* mReqs; void add(const Requirements*); void add(unsigned,Requirement*);
 bool contains(unsigned); const Requirements* make();
 void operator()(const Requirements*,const Requirements*,const Requirement::Context&);
};
struct Architecture {}; struct SigningContext {};
struct DiskRep { const Requirements* defaultRequirements(const Architecture*,const SigningContext&); };
struct MachORep { const Requirements* defaultRequirements(const Architecture*,const SigningContext&); Requirement* libraryRequirements(const Architecture*,const SigningContext&); };
struct BundleDiskRep { MachORep* mExecRep; const Requirements* defaultRequirements(const Architecture*,const SigningContext&); };
`
	sources, excerpts := map[string]any{}, map[string]string{}
	for _, s := range []struct {
		file      string
		functions []string
	}{
		{"signerutils.cpp", []string{"InternalRequirements::operator \\(\\)"}},
		{"drmaker.cpp", []string{"DRMaker::make", "DRMaker::nonAppleAnchor"}},
		{"machorep.cpp", []string{"MachORep::defaultRequirements"}},
		{"bundlediskrep.cpp", []string{"BundleDiskRep::defaultRequirements"}},
		{"diskrep.cpp", []string{"DiskRep::defaultRequirements"}},
	} {
		b := read(".research/apple/" + s.file)
		sources[s.file] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/" + s.file, "sha256": hash(b)}
		for _, name := range s.functions {
			body := regexp.MustCompile(`(?ms)^(?:const Requirements \*|Requirement \*|void )` + name + `\s*\(.*?^}`).Find(b)
			if len(body) == 0 {
				panic("missing complete function " + name)
			}
			excerpts[name] = hash(body)
			unit += "\n" + string(body) + "\n"
		}
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignDefaultResearch", "-"), &ast))
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
	record := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-requirement-defaults.go")), "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk), "sources": sources, "excerpt_sha256": excerpts, "translation_unit_sha256": hash([]byte(unit)), "targets": targets,
		"scope": "Six complete verbatim Apple bodies: InternalRequirements merge/default selection, DRMaker make/nonAppleAnchor, MachORep/BundleDiskRep/DiskRep default dispatch. Real SDK certificate/CoreFoundation declarations, requirement-kind constants, target macros and C++ library; private maker/context/CFRef/DERItem/logging interfaces are declaration-only shims. Both target ASTs establish explicit override precedence, absent-designated synthesis, no ad-hoc default at signing time, organization anchor selection and representation default delegation. Library dependency extraction, interpreter defaults, Apple proper policy and private current CLI call sites are not reconstructed or implemented by this increment. Native signing acceptance supplies the executed oracle. Production has no SDK or native runtime dependency."}
	b, e := json.MarshalIndent(record, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-requirement-defaults.json", append(b, '\n'), 0644))
	fmt.Println("Wrote six complete Apple default-requirement bodies on two targets")
}
