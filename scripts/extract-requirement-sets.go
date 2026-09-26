//go:build ignore

// Research only: complete Apple parser bodies and native requirement-set bytes.
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
#include <map>
#include <cstdlib>
#include <cstdint>
#include <Security/SecRequirement.h>
#include <TargetConditionals.h>
namespace CodesignSetResearch {
using namespace std;
void secinfo(const char*,const char*,...);
namespace antlr {
 struct Token { enum { EOF_TYPE=1 }; string getText(); };
 using RefToken=Token*; extern RefToken nullToken;
 struct RecognitionException {};
 struct NoViableAltException: RecognitionException { NoViableAltException(RefToken,string); };
 struct BitSet { bool member(int); };
}
#define ANTLR_BEGIN_NAMESPACE(name)
#define ANTLR_END_NAMESPACE
`
	sources, excerpts := map[string]any{}, map[string]string{}
	for _, file := range []string{"RequirementParserTokenTypes.hpp", "RequirementParser.cpp", "superblob.h", "signerutils.cpp", "requirements.grammar"} {
		b := read(".research/apple/" + file)
		base := "OSX/libsecurity_codesigning/lib/"
		if file == "superblob.h" {
			base = "OSX/libsecurity_utilities/lib/"
		}
		if file == "requirements.grammar" {
			base = "OSX/libsecurity_codesigning/"
		}
		sources[file] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/" + base + file, "sha256": hash(b)}
	}
	unit += string(read(".research/apple/RequirementParserTokenTypes.hpp"))
	unit += `
struct BlobCore {};
struct Requirement: BlobCore { struct Context {}; struct Maker { Requirement* operator()(); }; };
struct Requirements {
 struct Maker { void add(uint32_t,Requirement*); Requirements* operator()(); };
};
struct RequirementParser: RequirementParserTokenTypes {
 string errors; antlr::BitSet _tokenSet_0,_tokenSet_1,_tokenSet_2,_tokenSet_3,_tokenSet_4;
 int LA(int); antlr::RefToken LT(int); string getFilename(); void match(int);
 void reportError(antlr::RecognitionException&); void recover(antlr::RecognitionException&,antlr::BitSet&);
 Requirements* requirementSet(); uint32_t requirementType(); Requirement* requirementElement(); int32_t integer();
 void expr(Requirement::Maker&); void fluff();
};
template<class _BlobType,uint32_t _magic,class _Type> class SuperBlobCore {
public: using Type=_Type; class Maker { public: void add(Type,BlobCore*);
private: using BlobMap=map<Type,BlobCore*>; BlobMap mPieces; };
};
struct DRMaker { DRMaker(const Requirement::Context&); Requirement* make(); };
struct InternalRequirements {
 const Requirements* mReqs; void add(const Requirements*); void add(unsigned,Requirement*);
 bool contains(unsigned); const Requirements* make();
 void operator()(const Requirements*,const Requirements*,const Requirement::Context&);
};
`
	for _, v := range []struct{ file, name, pattern string }{
		{"RequirementParser.cpp", "requirementSet", `(?ms)^Requirements \* RequirementParser::requirementSet\(.*?^}`},
		{"RequirementParser.cpp", "requirementType", `(?ms)^uint32_t  RequirementParser::requirementType\(.*?^}`},
		{"RequirementParser.cpp", "requirementElement", `(?ms)^Requirement \* RequirementParser::requirementElement\(.*?^}`},
		{"RequirementParser.cpp", "integer", `(?ms)^int32_t  RequirementParser::integer\(.*?^}`},
		{"superblob.h", "Maker::add", `(?ms)^template <class _BlobType, uint32_t _magic, class _Type>\nvoid SuperBlobCore<_BlobType, _magic, _Type>::Maker::add\(Type type, BlobCore \*blob\).*?^}`},
		{"signerutils.cpp", "InternalRequirements::operator()", `(?ms)^void InternalRequirements::operator \(\).*?^}`},
	} {
		b := regexp.MustCompile(v.pattern).Find(read(".research/apple/" + v.file))
		if len(b) == 0 {
			panic("missing complete body " + v.name)
		}
		excerpts[v.name] = hash(b)
		unit += "\n" + string(b) + "\n"
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignSetResearch", "-"), &ast))
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
				name := n.MangledName
				if name == "" {
					name = n.Name
				}
				functions[name] = map[string]any{"ast_kinds": kinds, "references": refs}
			}
		})
		if len(functions) != 6 {
			panic(fmt.Sprintf("incomplete AST: %d", len(functions)))
		}
		targets[target] = functions
	}
	dir, e := os.MkdirTemp("", "codesign-set-research-")
	must(e)
	defer os.RemoveAll(dir)
	cases := map[string]any{}
	for name, source := range map[string]string{
		"host": "host => always", "guest": "guest => never", "designated": "designated => always", "library": "library => never", "plugin": "plugin => always",
		"reordered":               "plugin => always library => never designated => always guest => never host => always",
		"duplicate":               "host => never designated => always host => always designated => never",
		"numeric-alias":           "3 => never designated => always 1 => never host => always",
		"numeric-bounds":          "4294967295 => never 6 => always 0 => never 08 => always 03 => never",
		"comments":                "# leading\nhost /* kind */ => always // next\nguest => never; # middle\ndesignated => always# EOF",
		"semicolons":              "host => always;;; designated => never;;",
		"quoted-comment":          "host => identifier \"a#b//c/*d*/\"",
		"exists-boundary":         "host => certificate leaf[field.1.2.3] /* exists */ guest => always designated => certificate leaf[field.1.2.4]; library => always",
		"numeric-exists-boundary": "1 => certificate 08[field.1.2.3] 3 => always",
		"precedence":              "host => always and never or always designated => ! (never or always) library => ! false",
		"strings":                 "host => identifier helper designated => identifier \"é\" plugin => identifier \"a b\"",
		"certificate":             "host => certificate root = H\"0000000000000000000000000000000000000000\" designated => certificate leaf[subject.CN] = Example guest => anchor apple generic",
		"empty":                   "", "comment-only": "# no expression\n", "missing-arrow": "host always", "split-arrow": "host = > always", "comment-arrow": "host =/*x*/> always",
		"missing-expression": "host =>", "missing-type": "=> always", "invalid-name": "invalid => always", "negative": "-1 => always", "hex-kind": "0x3 => always",
		"unknown-kind": "future => always", "leading-semi": ";host => always", "comma": "host => always, guest => never", "unclosed-comment": "host => always /*", "unclosed-string": "host => identifier \"oops", "trailing-token": "host => always bogus",
	} {
		path := filepath.Join(dir, "compiled")
		_ = os.Remove(path)
		cmd := exec.Command("/usr/bin/csreq", "-r", "="+source, "-b", path)
		cmd.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				panic(err)
			}
		}
		record := map[string]any{"source": source, "exit": code, "stdout": out.String(), "stderr": stderr.String()}
		if code == 0 {
			b := read(path)
			record["compiled_hex"] = hex.EncodeToString(b)
			record["compiled_sha256"] = hash(b)
		}
		cases[name] = record
	}
	record := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-requirement-sets.go")), "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk), "sources": sources, "excerpt_sha256": excerpts, "translation_unit_sha256": hash([]byte(unit)), "targets": targets, "native": map[string]any{"macos": string(run("", "/usr/bin/sw_vers")), "csreq_sha256": hash(read("/usr/bin/csreq")), "cases": cases},
		"scope": "Six complete verbatim Apple bodies: four generated parser methods, SuperBlob Maker::add and InternalRequirements merge/default selection. Real SDK requirement-kind constants, target macros and C++ library; ANTLR, maker, DRMaker, logging and private interfaces are declarations only. Two Clang targets establish set grammar, semicolon consumption, unsigned kind conversion, duplicate replacement and missing-designated default selection; native csreq independently supplies complete compiled bytes. Lexer implementation and full expression grammar are not reconstructed. The recorded certificate default merge is an outstanding signing obligation, not implemented by this compiler increment. Production requires no native tools or SDK."}
	b, e := json.MarshalIndent(record, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-requirement-sets.json", append(b, '\n'), 0644))
	fmt.Printf("Wrote six complete Apple bodies on two targets and %d native cases\n", len(cases))
}
