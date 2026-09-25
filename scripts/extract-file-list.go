//go:build ignore

// Research only: analyze Apple's signature-file selection and CLI file-list writing.
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
#include <cstring>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
namespace CodesignFileListResearch {
using std::string;
template <typename T> struct CFRef { CFRef(T); operator T() const; T get(); T yield(); };
CFURLRef makeCFURL(const string&);
CFArrayRef makeCFArray(unsigned, ...);
string cfString(CFURLRef);
string cfStringRelease(CFURLRef);
struct CFTempURL { CFTempURL(const string&); operator CFURLRef() const; };
// Declaration-only private interfaces and symbolic slot values. Slot constants
// are not inferred from these shims; the project has separate SDK format evidence.
enum { cdCodeDirectorySlot=0, cdRequirementsSlot=2, cdResourceDirSlot=3, cdTopDirectorySlot=4,
 cdEntitlementSlot=5, cdRepSpecificSlot=6, cdEntitlementDERSlot=7,
 cdSignatureSlot=0x10000, cdAlternateCodeDirectorySlots=0x1000,
 cdAlternateCodeDirectoryLimit=0x1005, cdLaunchConstraintSelf=8,
 cdLaunchConstraintParent=9, cdLaunchConstraintResponsible=10, cdLibraryConstraint=11 };
struct CodeDirectory { using SpecialSlot=int; using Slot=int; static const char* canonicalSlotName(int); };
struct DiskRep { CFArrayRef modifiedFiles(); string mainExecutablePath(); CFDataRef component(int); };
struct BundleDiskRep {
 DiskRep* mExecRep; string mMetaPath; bool mMetaExists; CFBundleRef mBundle;
 CFArrayRef modifiedFiles(); void checkModifiedFile(CFMutableArrayRef, CodeDirectory::SpecialSlot); string metaPath(const char*);
};
#define BUNDLEDISKREP_DIRECTORY "_CodeSignature"
`

	sources, hashes := map[string]any{}, map[string]string{}
	header := read(".research/apple/codedirectory.h")
	sources["codedirectory.h"] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/codedirectory.h", "sha256": hash(header)}
	for _, definition := range regexp.MustCompile(`(?m)^#define kSecCS_.*$`).FindAll(header, -1) {
		unit += string(definition) + "\n"
	}
	for _, source := range []struct {
		name, revision, repo, prefix string
		functions                    []string
	}{
		{"cs_utils.cpp", "2b4c65b1074521e9c1dd2c8dc7fbf45dd775ec70", "security_systemkeychain", "src/", []string{"writeFileList"}},
		{"diskrep.cpp", "db15acbe6a7f257a859ad9a3bb86097bfe0679d9", "Security", "OSX/libsecurity_codesigning/lib/", []string{"DiskRep::modifiedFiles"}},
		{"bundlediskrep.cpp", "db15acbe6a7f257a859ad9a3bb86097bfe0679d9", "Security", "OSX/libsecurity_codesigning/lib/", []string{"BundleDiskRep::modifiedFiles", "BundleDiskRep::checkModifiedFile", "BundleDiskRep::metaPath"}},
		{"codedirectory.cpp", "db15acbe6a7f257a859ad9a3bb86097bfe0679d9", "Security", "OSX/libsecurity_codesigning/lib/", []string{"CodeDirectory::canonicalSlotName"}},
	} {
		data := read(".research/apple/" + source.name)
		sources[source.name] = map[string]string{"url": "https://github.com/apple-oss-distributions/" + source.repo + "/blob/" + source.revision + "/" + source.prefix + source.name, "sha256": hash(data)}
		for _, name := range source.functions {
			excerpt := regexp.MustCompile(`(?ms)^(?:void|string|CFArrayRef|const char \*) ?` + name + `\(.*?^}`).Find(data)
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
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignFileListResearch", "-"), &ast))
		functions := map[string]any{}
		walk(ast, func(n node) {
			if (n.Kind != "FunctionDecl" && n.Kind != "CXXMethodDecl") || (n.Name != "modifiedFiles" && n.Name != "checkModifiedFile" && n.Name != "metaPath" && n.Name != "writeFileList" && n.Name != "canonicalSlotName") {
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
		"scope":   "Six complete verbatim Apple function bodies on two targets: writeFileList, DiskRep::modifiedFiles, BundleDiskRep::modifiedFiles/checkModifiedFile/metaPath and CodeDirectory::canonicalSlotName; filename macros are verbatim from the pinned codedirectory.h. Real SDK declarations supply stdio, access/F_OK and CoreFoundation functions. Private CFRef, CFTempURL, disk-representation, slot-name and string/array helper interfaces are declaration-only shims; slot values and the signature-directory macro are explicitly supplied. This records append-mode forwarding, destination errors exiting the process, unchecked stdio writes/closes, executable-first ordering, embedded-slot exclusion and existing metadata paths. It does not extract current CLI call sites or supported behavior for every slot. Native acceptance supplies actual option behavior, framework dot spelling and failure ordering. Production is pure Go without SDK/runtime dependencies.",
		"sources": sources, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets,
	}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-file-list.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-file-list.json: six file-list functions on two targets")
}
