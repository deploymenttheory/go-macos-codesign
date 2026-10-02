//go:build ignore

// Research only: compile complete Apple generic-removal methods against the SDK.
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
	Inner                   []node
	ReferencedDecl          *node
}

func walk(n node, f func(node)) {
	f(n)
	for _, c := range n.Inner {
		walk(c, f)
	}
}
func main() {
	const revision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
	header := read(".research/apple/codedirectory.h")
	macros := regexp.MustCompile(`(?m)^#define kSecCS_.*$`).FindAll(header, -1)
	slots := regexp.MustCompile(`(?ms)^enum \{\n\t//\n\t// Primary slot numbers.*?^};`).Find(header)
	if len(slots) == 0 || len(macros) != 12 {
		panic("incomplete slot definitions")
	}
	unit := `#include <string>
#include <vector>
#include <set>
#include <cstring>
#include <cstdint>
#include <sys/types.h>
#include <sys/xattr.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <arpa/inet.h>
namespace GenericRemovalResearch {
using std::string;
struct UnixError {static void throwMe();};
struct FileDesc {int mFd; size_t read(void*,size_t,off_t); void removeAttr(const char*,int=0);void removeAttr(const string&);size_t listAttr(char*,size_t); void open(const string&,int);operator bool();};
struct CodeDirectory {using SpecialSlot=int;static const char* canonicalSlotName(SpecialSlot);};
struct FileDiskRep {static string attrName(const char*);struct Writer{FileDesc& fd();std::set<string> mWrittenAttributes;void remove();void flush();};};
struct SingleDiskRep {string path();struct Writer{FileDesc mFd;SingleDiskRep* rep;FileDesc& fd();};};
struct Universal {static uint32_t typeOf(FileDesc);};
struct MachORep {static bool candidate(FileDesc&);};
namespace LowLevelMemoryUtilities {template<class T> T* increment(void*,size_t);}
uint32_t flip(uint32_t);
`
	for _, macro := range macros {
		unit += string(macro) + "\n"
	}
	unit += string(slots) + "\n"
	hashes := map[string]string{}
	sources := map[string]any{}
	for _, fn := range []struct{ file, name, start string }{
		{"filediskrep.cpp", "attrName", `string FileDiskRep::attrName`},
		{"filediskrep.cpp", "remove", `void FileDiskRep::Writer::remove`},
		{"filediskrep.cpp", "flush", `void FileDiskRep::Writer::flush`},
		{"codedirectory.cpp", "canonicalSlotName", `const char *CodeDirectory::canonicalSlotName`},
		{"singlediskrep.cpp", "fd", `FileDesc &SingleDiskRep::Writer::fd`},
		{"unix++.cpp", "removeAttr", `void FileDesc::removeAttr`},
		{"machorep.cpp", "candidate", `bool MachORep::candidate`},
		{"macho++.cpp", "typeOf", `uint32_t Universal::typeOf`},
	} {
		source := read(".research/apple/" + fn.file)
		body := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(fn.start) + `\(.*?^}`).Find(source)
		if len(body) == 0 {
			panic("missing complete body " + fn.name)
		}
		hashes[fn.name] = hash(body)
		unit += string(body) + "\n"
		directory := "libsecurity_codesigning"
		if fn.file == "unix++.cpp" || fn.file == "macho++.cpp" {
			directory = "libsecurity_utilities"
		}
		sources[fn.file] = map[string]string{"sha256": hash(source), "url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/" + directory + "/lib/" + fn.file}
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=GenericRemovalResearch", "-"), &ast))
		methods := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "CXXMethodDecl" || hashes[n.Name] == "" {
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
				methods[n.Name] = map[string]any{"ast_kinds": kinds, "references": refs}
			}
		})
		if len(methods) != len(hashes) {
			panic("incomplete methods")
		}
		targets[target] = methods
	}
	sources["codedirectory.h"] = map[string]string{"sha256": hash(header), "url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/codedirectory.h"}
	record := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-generic-removal.go")), "sources": sources, "body_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets, "scope": "Eight complete verbatim Apple methods. SDK headers supply real file flags, xattr options and Mach-O structures. Other methods are declarations only. The pinned flush compares 13 bytes against the 12-byte prefix: current native macOS probes remove arbitrary com.apple.cs.* names, so production follows measured native prefix behavior rather than this older source defect. FAT64 remains on the existing validated Mach-O path; the pinned typeOf recognizes FAT32 only. No claim of full CoreFoundation bundle selection or specialized-format parity."}
	data, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-generic-removal.json", append(data, '\n'), 0644))
}
