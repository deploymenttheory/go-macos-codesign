//go:build ignore

// Research only: parse Apple's complete MachOEditor commit and destructor.
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
	Kind, Name, Opcode string
	Value              any
	Inner              []node
	ReferencedDecl     *node
}

func walk(n node, f func(node)) {
	f(n)
	for _, c := range n.Inner {
		walk(c, f)
	}
}

func main() {
	const revision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
	source := read(".research/apple/signerutils.cpp")
	unit := `#include <string>
#include <cstdio>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/clonefile.h>
#include <copyfile.h>
#include <CoreFoundation/CoreFoundation.h>
#include <TargetConditionals.h>
namespace CodesignWriterResearch {
struct UnixError { static void check(int); };
struct UidGuard { bool seteuid(uid_t); };
struct Copyfile { void set(unsigned int, void*); void operator()(const char*, const char*, copyfile_flags_t); };
struct FD { operator int(); void read(void*, size_t, off_t); void write(const void*, size_t, off_t); };
struct Writer { bool getPreserveAFSC(); void flush(); };
struct Universal {};
struct cmpInfo { unsigned int compressionType; unsigned long long compressedSize; };
int queryCompressionInfo(const char*, cmpInfo*);
using CompressionQueueContext = void*;
CompressionQueueContext CreateCompressionQueue(void*, void*, void*, void*, CFDictionaryRef);
bool CompressFile(CompressionQueueContext, const char*, void*);
void FinishCompressionAndCleanUp(CompressionQueueContext);
extern CFStringRef kAFSCCompressionTypes;
void secinfo(const char*, const char*, ...);
struct MacOSError { static void throwMe(int); };
constexpr int errSecCSInternalError = -67050;
struct MachOEditor {
  ~MachOEditor(); void commit();
  std::string sourcePath, tempPath; FD mFd;
  Writer* writer; Universal* mNewCode; bool mTempMayExist;
};
enum MetadataConstants : unsigned long long {
 CloneACL = CLONE_ACL,
 FileSecMagic = KAUTH_FILESEC_MAGIC,
 NoACL = KAUTH_FILESEC_NOACL,
 FileSecSize = KAUTH_FILESEC_SIZE(0),
 AttrReferenceSize = sizeof(attrreference_t)
};
`
	hashes := map[string]string{}
	for _, name := range []string{"~MachOEditor", "commit"} {
		excerpt := regexp.MustCompile(`(?ms)^(?:void )?MachOEditor::` + regexp.QuoteMeta(name) + `\(\).*?^}`).Find(source)
		if len(excerpt) == 0 {
			panic("missing complete method " + name)
		}
		hashes[name] = hash(excerpt)
		unit += "\n" + string(excerpt) + "\n"
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignWriterResearch", "-"), &ast))
		methods, constants := map[string]any{}, map[string]string{}
		walk(ast, func(n node) {
			if n.Kind == "EnumConstantDecl" {
				walk(n, func(c node) {
					if c.Kind == "ConstantExpr" {
						constants[n.Name] = fmt.Sprint(c.Value)
					}
				})
			}
			if (n.Kind != "CXXMethodDecl" && n.Kind != "CXXDestructorDecl") || hashes[n.Name] == "" {
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
				methods[n.Name] = map[string]any{"ast_kinds": kinds, "references": references}
			}
		})
		if len(methods) != 2 || len(constants) != 5 {
			panic("incomplete AST")
		}
		targets[target] = map[string]any{"methods": methods, "metadata_constants": constants}
	}
	headers := map[string]string{}
	for _, path := range []string{"sys/clonefile.h", "sys/attr.h", "sys/acl.h", "sys/kauth.h", "copyfile.h"} {
		headers[path] = hash(read(filepath.Join(sdk, "usr/include", path)))
	}
	record := map[string]any{
		"schema": 1, "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk),
		"scope":       "Complete verbatim MachOEditor::commit and destructor bodies. Stat, rename, remove, copyfile flags, filesystem layouts and CoreFoundation declarations come from the real SDK. Private Copyfile/UidGuard/FD/Writer/Universal/compression interfaces, logging and the internal error constant are declaration-only research shims. AST analysis records metadata-copy-before-rename and cleanup control flow, not execution or full Security compilation. Native tests independently establish hard-link outcomes. Production delegates metadata to go-apfs-v2; no SDK or Apple tool is a runtime/build requirement. The clone-based Darwin implementation has narrower filesystem/compression support than native copyfile.",
		"sources":     map[string]any{"signerutils.cpp": map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/signerutils.cpp", "sha256": hash(source)}},
		"sdk_headers": headers, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets,
	}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-writer.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-writer.json: two-target MachOEditor and metadata AST")
}
