//go:build ignore

// Research only: Apple's UDIF signature handling parsed through Clang.
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
func read(p string) []byte { b, err := os.ReadFile(p); must(err); return b }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(input, command string, args ...string) []byte {
	c := exec.Command(command, args...)
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
}

func walk(n node, visit func(node)) {
	visit(n)
	for _, c := range n.Inner {
		walk(c, visit)
	}
}

func main() {
	dmg, disk := read(".research/apple/diskimagerep.cpp"), read(".research/apple/diskrep.cpp")
	excerpts := map[string][]byte{}
	for _, method := range []string{"readHeader", "setup", "signingLimit", "flush", "canonicalIdentifier"} {
		source := dmg
		class := "DiskImageRep::"
		if method == "flush" {
			class += "Writer::"
		}
		if method == "canonicalIdentifier" {
			source, class = disk, "DiskRep::"
		}
		pattern := `(?ms)^[a-zA-Z_:]+ ` + regexp.QuoteMeta(class+method) + `\(.*?\n}`
		excerpts[method] = regexp.MustCompile(pattern).Find(source)
		if len(excerpts[method]) == 0 {
			panic("missing method " + method)
		}
	}
	version := regexp.MustCompile(`static const int32_t udifVersion = [0-9]+;`).Find(dmg)
	unit := `#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <string>
using std::string;
template<class T> T n2h(T);
template<class T> T h2n(T);
enum {kUDIFSignature=0x6b6f6c79,errSecCSBadDiskImageFormat=1};
struct BlobCore {char opaque[8];};
struct UDIFFileHeader {uint32_t fUDIFSignature,fUDIFVersion;uint64_t fUDIFCodeSignOffset,fUDIFCodeSignLength;};
struct EmbeddedSignatureBlob;
struct FileDesc {size_t fileSize();size_t read(void*,size_t,size_t);void seek(size_t);void writeAll(const EmbeddedSignatureBlob&);void writeAll(const void*,size_t);void truncate(size_t);size_t position();};
struct EmbeddedSignatureBlob {static EmbeddedSignatureBlob* readBlob(FileDesc&,size_t,size_t);size_t length() const;bool strictValidateBlob(size_t);};
struct Maker {static EmbeddedSignatureBlob* make();};
struct UnixError {static void throwMe(int);};
struct MacOSError {static void throwMe(int);};
struct DiskRep {static std::string canonicalIdentifier(const std::string&);};
struct DiskImageRep {
 UDIFFileHeader mHeader; const EmbeddedSignatureBlob* mSigningData;size_t mHeaderOffset,mEndOfDataOffset;
 FileDesc& fd();static bool readHeader(FileDesc&,UDIFFileHeader&);void setup();size_t signingLimit();
 struct Writer {const EmbeddedSignatureBlob* mSigningData;DiskImageRep* rep;FileDesc& fd();void flush();};
};
` + string(version)
	order := []string{"readHeader", "setup", "signingLimit", "flush", "canonicalIdentifier"}
	for _, name := range order {
		unit += "\n" + string(excerpts[name])
	}
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"), &ast))
		methods := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "CXXMethodDecl" || excerpts[n.Name] == nil {
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
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.Kind == "MemberExpr" {
					members[c.Name]++
				}
				if c.Opcode != "" {
					operators[c.Opcode]++
				}
			})
			methods[n.Name] = map[string]any{"ast_kinds": kinds, "members": members, "operators": operators}
		})
		if len(methods) != len(order) {
			panic("incomplete AST")
		}
		targets[target] = methods
	}
	sources, hashes := map[string]any{}, map[string]string{}
	for name, data := range map[string][]byte{"diskimagerep.cpp": dmg, "diskrep.cpp": disk} {
		sources[name] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/" + name, "sha256": hash(data)}
	}
	for name, data := range excerpts {
		hashes[name] = hash(data)
	}
	result := map[string]any{"schema": 1, "scope": "Five verbatim Apple methods with explicit interface, error-code and UDIF header shims. Source AST facts only; shim layouts do not establish wire offsets. Production reuses go-apfs-v2/disk.DMGFooter.", "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sources": sources, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "udif_version_declaration": string(version), "targets": targets}
	out, err := json.MarshalIndent(result, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-dmg.json", append(out, '\n'), 0644))
	fmt.Println("Wrote spec/apple-dmg.json: two-target UDIF signing AST")
}
