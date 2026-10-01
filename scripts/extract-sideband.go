//go:build ignore

// Research only: complete pinned Apple sideband attribute and policy bodies.
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
#include <set>
#include <vector>
#include <algorithm>
#include <iterator>
#include <cerrno>
#include <sys/xattr.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CodeSigning.h>
namespace CodesignSidebandResearch {
static_assert(MAXSYMLINKS == 32, "requalify native open symlink budget");
using std::string;
using std::vector;
struct UnixError { [[noreturn]] static void throwMe(); };
using UnixStat=struct stat;
struct FileDesc {
 int mFd;
 ssize_t getAttrLength(const char*,int);
 ssize_t getAttr(const char*,void*,size_t,u_int32_t,int);
 void removeAttr(const char*,int=0);
 bool hasExtendedAttribute(const char*) const;
 bool isPlainFile(const std::string&); void fstat(UnixStat&);
 int fcntl(int,int);
 size_t fileSize();
};
namespace UnixPlusPlus { struct AutoFileDesc : FileDesc { AutoFileDesc(string); }; }
using ToleratedErrors=std::set<OSStatus>;
namespace Hashing { using Byte=unsigned char; }
namespace Security { struct DynamicHash { size_t digestLength(); void finish(void*); }; }
struct CodeDirectory {
 size_t signingLimit() const;
 using HashAlgorithm=unsigned int; using HashAlgorithms=std::set<HashAlgorithm>;
 static void multipleHashFileData(FileDesc&,size_t,HashAlgorithms,void (^)(HashAlgorithm,Security::DynamicHash*));
};
template<class T> struct CFRef { CFRef(T); operator T() const; T get(); T yield(); };
CFMutableDictionaryRef makeCFMutableDictionary();
CFStringRef CFTempString(string); CFDataRef CFTempData(const void*,size_t);
struct ResourceBuilder {
 static string hashName(CodeDirectory::HashAlgorithm);
 static CFMutableDictionaryRef hashFile(const char*,CodeDirectory::HashAlgorithms,bool);
};
struct MacOSError { [[noreturn]] static void throwMe(OSStatus); };
struct CSError { [[noreturn]] static void throwMe(OSStatus,CFStringRef,CFTypeRef); };
extern const SecCSFlags kSecCSStripDisallowedXattrs;
string cfStringRelease(CFURLRef);
struct DiskRep { void strictValidate(const CodeDirectory*,const ToleratedErrors&,SecCSFlags); };
struct SingleDiskRep : DiskRep {
 FileDesc mFd; bool appleInternalForcePlatform() const;
 string mPath; FileDesc& fd(); size_t signingLimit();
 void strictValidate(const CodeDirectory*,const ToleratedErrors&,SecCSFlags);
};
struct DiskImageRep : SingleDiskRep {
 void strictValidate(const CodeDirectory*,const ToleratedErrors&,SecCSFlags);
};
struct Executable { bool isSuspicious(); };
struct MachORep : SingleDiskRep {
 Executable* mExecutable;
 void strictValidate(const CodeDirectory*,const ToleratedErrors&,SecCSFlags);
};
struct BundleDiskRep {
 void checkPlainFile(FileDesc,const std::string&); void recordStrictError(OSStatus);
 SingleDiskRep* mExecRep;
 bool mAppLike; std::set<OSStatus> mStrictErrors;
 CFURLRef copyCanonicalPath(); void validateMetaDirectory(const CodeDirectory*,SecCSFlags);
 void strictValidateStructure(const CodeDirectory*,const ToleratedErrors&,SecCSFlags);
 void strictValidate(const CodeDirectory*,const ToleratedErrors&,SecCSFlags);
};
`
	excerpts := map[string]string{}
	sources := map[string]any{}
	for _, source := range []struct {
		file, directory, sha string
		declarations         []string
	}{
		{"unix++.cpp", "libsecurity_utilities", "b71f48a4b375021b13a3c268b29c1e3f605f2db961f7825b7a7d429e27601567", []string{
			"ssize_t FileDesc::getAttrLength", "ssize_t FileDesc::getAttr", "void FileDesc::removeAttr", "static bool checkFork", "bool filehasExtendedAttribute", "bool FileDesc::hasExtendedAttribute", "bool FileDesc::isPlainFile",
		}},
		{"singlediskrep.cpp", "libsecurity_codesigning", "321835f049a1b0dfef3d74559142a43d79a3205cb7e2f81285b968f1bb29baf4", []string{"void SingleDiskRep::strictValidate", "bool SingleDiskRep::appleInternalForcePlatform"}},
		{"bundlediskrep.cpp", "libsecurity_codesigning", "c69c5976a70a33292e5d565c1c7e6411a5c97aba829332f89a899d8cd89fbcb4", []string{"void BundleDiskRep::strictValidateStructure", "void BundleDiskRep::strictValidate", "void BundleDiskRep::checkPlainFile"}},
		{"diskimagerep.cpp", "libsecurity_codesigning", "ca424f5b65da6534d332bcc64277bdf0133442e63586ed5cd8b01c3f125165df", []string{"void DiskImageRep::strictValidate"}},
		{"machorep.cpp", "libsecurity_codesigning", "a4bad9b5376334efef9f87e00e740a6c336b0ca70dee4263a123995ef51ba9d6", []string{"void MachORep::strictValidate"}},
		{"resources.cpp", "libsecurity_codesigning", "1a911c38fd9aaa4ddda0e041d5711317e92b312fe62d9b99674f7eca8c5b85c4", []string{"CFMutableDictionaryRef ResourceBuilder::hashFile"}},
	} {
		data := read(".research/apple/" + source.file)
		if hash(data) != source.sha {
			panic("source does not match pinned Apple revision: " + source.file)
		}
		sources[source.file] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/" + source.directory + "/lib/" + strings.ReplaceAll(source.file, "+", "%2B"), "sha256": hash(data)}
		for _, declaration := range source.declarations {
			bodies := regexp.MustCompile(`(?ms)^`+regexp.QuoteMeta(declaration)+`\(.*?^}`).FindAll(data, -1)
			if len(bodies) != 1 {
				panic("expected one complete body: " + declaration)
			}
			body := bodies[0]
			excerpts[declaration] = hash(body)
			unit += "\n" + string(body) + "\n"
		}
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-fblocks", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignSidebandResearch", "-"), &ast))
		functions := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "CXXMethodDecl" && n.Kind != "FunctionDecl" {
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
		if len(functions) != 15 {
			panic(fmt.Sprintf("incomplete AST: %d bodies", len(functions)))
		}
		targets[target] = functions
	}
	record := map[string]any{
		"schema": 1, "driver_sha256": hash(read("scripts/extract-sideband.go")),
		"compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk),
		"sources": sources, "excerpt_sha256": excerpts, "translation_unit_sha256": hash([]byte(unit)), "targets": targets,
		"scope": "Fifteen complete verbatim pinned Apple bodies: strict size/read/remove utilities, checkFork, path/descriptor presence checks, SingleDiskRep::strictValidate and appleInternalForcePlatform, FileDesc::isPlainFile, BundleDiskRep::checkPlainFile, BundleDiskRep::strictValidateStructure and strictValidate, MachORep::strictValidate, DiskImageRep::strictValidate and ResourceBuilder::hashFile (multiple algorithms). The complete hashing body checks ResourceFork before FinderInfo when strictCheck is enabled, before reading data. Signer::prepare and buildResources are source-reviewed separately: prepare applies QuickCheck plus RestrictSidebandData; ordinary resource stripping precedes hashFile, while symlink and nested branches bypass that removal. Real SDK xattr/CoreFoundation/Security declarations and C++ library; private interfaces and the strip flag are declaration-only shims. Ordinary options-zero presence queries ignore empty values and ENOATTR/EPERM; generic utilities preserve other errors. Single/bundle bodies show ResourceFork before FinderInfo and strip before sideband rejection. BundleDiskRep checks its canonical root before delegating to its executable. The real host SDK asserts MAXSYMLINKS=32 on both Clang targets. MachORep calls SingleDiskRep before suspicious-layout checks; DiskImageRep calls DiskRep directly, bypassing sideband policy. This does not reconstruct the current private CLI, prove filesystem/race behavior, cover resource traversal or establish full codesign sideband/strip parity. Native observations and the separately released APFS dependency qualify bounded production integration. Production has no SDK/native runtime dependency.",
	}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-sideband.json", append(b, '\n'), 0644))
	fmt.Println("Wrote fifteen complete Apple sideband bodies on two targets")
}
