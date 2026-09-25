//go:build ignore

// Research only: analyze Apple's entitlement component selection, validation and output helpers.
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
#include <map>
#include <cstring>
#include <cassert>
#include <stdio.h>
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecBase.h>
namespace CodesignEntitlementResearch {
template <typename T> struct CFRef { CFRef(); CFRef(T); operator T() const; T get(); void take(T); CFRef& operator=(T); };
CFDataRef makeCFData(CFDictionaryRef);
CFDictionaryRef makeCFDictionaryFrom(const UInt8*, size_t);
void secinfo(const char*,const char*,...); void secerror(const char*,...);
namespace Hashing { using Byte=unsigned char; }
struct CodeDirectory { using SpecialSlot=int; using Slot=int; unsigned nSpecialSlots,nCodeSlots,hashSize;
 const Hashing::Byte* getSlot(Slot,bool) const; bool slotIsPresent(Slot) const; bool validateSlot(const UInt8*,CFIndex,Slot,bool);
};
enum { cdSlotMax=11, cdEntitlementSlot=5, cdEntitlementDERSlot=7 };
struct DiskRep { CFDataRef component(int); };
struct EntitlementBlob { bool validateBlob() const; size_t length() const; template<typename T> T at(size_t) const; CFDictionaryRef entitlements() const; };
struct EntitlementDERBlob { static CFDataRef blobify(CFDataRef); bool validateBlob() const; size_t length() const; CFDataRef innerData() const; };
struct MacOSError { static void throwMe(OSStatus); };
using CEQueryContext=void*;
extern void* CECRuntime;
bool CE_OK(int); int CESerializeCFDictionary(void*,CFDictionaryRef,CFDataRef*);
int SecCEContextFromCFData(CFDataRef,CEQueryContext*);
int CEQueryContextToCFDictionary(CEQueryContext,CFMutableDictionaryRef*);
struct SecStaticCode {
 std::map<int,CFRef<CFDataRef>> mCache; DiskRep* mRep;
 CFRef<CFDictionaryRef> mEntitlements; bool mEntitlementsValidated; CEQueryContext mCEQueryContext;
 bool validated(); CodeDirectory* codeDirectory(); OSStatus errorForSlot(int);
 void validateComponent(int); void validateDirectory();
 CFDataRef component(int,OSStatus=0); CFDictionaryRef entitlements(bool);
};
`

	sources, hashes := map[string]any{}, map[string]string{}
	for _, source := range []struct {
		name, revision, repo, prefix string
		functions                    []string
	}{
		{"cs_utils.cpp", "2b4c65b1074521e9c1dd2c8dc7fbf45dd775ec70", "security_systemkeychain", "src/", []string{"writeDictionary", "writeData"}},
		{"StaticCode.cpp", "db15acbe6a7f257a859ad9a3bb86097bfe0679d9", "Security", "OSX/libsecurity_codesigning/lib/", []string{"SecStaticCode::component", "SecStaticCode::entitlements"}},
		{"sigblob.cpp", "db15acbe6a7f257a859ad9a3bb86097bfe0679d9", "Security", "OSX/libsecurity_codesigning/lib/", []string{"EntitlementBlob::entitlements"}},
		{"codedirectory.cpp", "db15acbe6a7f257a859ad9a3bb86097bfe0679d9", "Security", "OSX/libsecurity_codesigning/lib/", []string{"CodeDirectory::slotIsPresent"}},
	} {
		data := read(".research/apple/" + source.name)
		sources[source.name] = map[string]string{"url": "https://github.com/apple-oss-distributions/" + source.repo + "/blob/" + source.revision + "/" + source.prefix + source.name, "sha256": hash(data)}
		for _, name := range source.functions {
			excerpt := regexp.MustCompile(`(?ms)^(?:void|bool|CFDataRef|CFDictionaryRef) ` + name + `\(.*?^}`).Find(data)
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
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignEntitlementResearch", "-"), &ast))
		functions := map[string]any{}
		walk(ast, func(n node) {
			if (n.Kind != "FunctionDecl" && n.Kind != "CXXMethodDecl") || (n.Name != "writeDictionary" && n.Name != "writeData" && n.Name != "component" && n.Name != "entitlements" && n.Name != "slotIsPresent") {
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
				functions[n.MangledName] = map[string]any{"ast_kinds": kinds, "references": references}
			}
		})
		if len(functions) != 6 {
			panic("incomplete AST")
		}
		targets[target] = functions
	}
	record := map[string]any{
		"schema": 1, "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk),
		"scope":   "Six complete verbatim Apple function bodies on two targets: SecStaticCode::component/entitlements, CodeDirectory::slotIsPresent, EntitlementBlob::entitlements, writeDictionary and writeData. Real SDK declarations supply stdio, CoreFoundation and Security base types. Private CFRef, disk representation, blobs, CodeDirectory, logging, exceptions and CoreEntitlements interfaces are declaration-only shims; symbolic slot values are supplied explicitly. The AST establishes DER preference, XML fallback, conditional slot validation, nonzero-hash presence, and generic fopen/error/write helpers. It does not contain the private CoreEntitlements parser/serializers or current CLI call sites. Current typed text, compact XML, append mode, colon consumption, warnings and operation ordering are established by native differential acceptance. Production has no SDK/runtime dependency.",
		"sources": sources, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets,
	}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-entitlement-extraction.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-entitlement-extraction.json: six entitlement functions on two targets")
}
