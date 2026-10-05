//go:build ignore

// Research only: compile complete pinned resource hashing methods with Clang.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
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
	check := flag.Bool("check", false, "compare complete AST bodies")
	out := flag.String("out", "spec/apple-bundle-streaming.json", "output")
	flag.Parse()
	const revision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
	unit := `#include <CoreFoundation/CoreFoundation.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <cassert>
#include <map>
#include <set>
#include <vector>
namespace BundleStreamingResearch {
using std::map; using std::vector;
namespace Hashing { using Byte=unsigned char; }
namespace Security { struct DynamicHash { size_t digestLength() const; void update(const void*,size_t); void finish(unsigned char*); }; }
using Security::DynamicHash;
struct FileDesc {};
namespace UnixPlusPlus { struct AutoFileDesc : FileDesc { AutoFileDesc(const char*); void fcntl(int,bool); bool hasExtendedAttribute(const char*); }; }
template<class T> struct RefPointer { RefPointer(); RefPointer(T*); RefPointer& operator=(T*); T* operator->() const; T* get() const; operator T*() const; };
template<class T> struct CFRef { CFRef(T); operator T() const; T yield(); };
CFMutableDictionaryRef makeCFMutableDictionary();
struct CFTempString { CFTempString(const char*); operator CFStringRef() const; };
struct CFTempData { CFTempData(const void*,size_t); operator CFDataRef() const; };
struct CSError { static void throwMe(int,CFStringRef,CFStringRef); };
const int errSecCSInvalidAssociatedFileData=1;
extern CFStringRef kSecCFErrorResourceSideband;
void hashFileData(FileDesc,DynamicHash*);
void scanFileData(FileDesc,size_t,void (^)(const void*,size_t));
struct CodeDirectory {
 using HashAlgorithm=int; using HashAlgorithms=std::set<int>;
 static bool viableHash(HashAlgorithm);
 static DynamicHash* hashFor(HashAlgorithm);
 static void multipleHashFileData(FileDesc,size_t,HashAlgorithms,void (^)(HashAlgorithm,DynamicHash*));
};
struct ResourceBuilder {
 CFDataRef hashFile(const char*,CodeDirectory::HashAlgorithm);
 CFMutableDictionaryRef hashFile(const char*,CodeDirectory::HashAlgorithms,bool);
 const char* hashName(CodeDirectory::HashAlgorithm);
};
`
	sources, excerpts := map[string]any{}, map[string]string{}
	for _, s := range []struct{ name, digest, pattern string }{{"resources.cpp", "1a911c38fd9aaa4ddda0e041d5711317e92b312fe62d9b99674f7eca8c5b85c4", `(?ms)^CF(?:DataRef|MutableDictionaryRef) ResourceBuilder::hashFile\(.*?^}`}, {"codedirectory.cpp", "9a4b47e6cee40983d71e3214286415ed7b83b22b403d5a7e89fad50d776646af", `(?ms)^void CodeDirectory::multipleHashFileData\(.*?^}`}} {
		url := "https://raw.githubusercontent.com/apple-oss-distributions/Security/" + revision + "/OSX/libsecurity_codesigning/lib/" + s.name
		source, e := os.ReadFile(filepath.Join(".research/apple", s.name))
		if os.IsNotExist(e) {
			client := http.Client{Timeout: 60 * time.Second}
			r, e := client.Get(url)
			must(e)
			if r.StatusCode != 200 {
				panic(r.Status)
			}
			source, e = io.ReadAll(io.LimitReader(r.Body, 1<<20))
			must(e)
			must(r.Body.Close())
		} else {
			must(e)
		}
		if hash(source) != s.digest {
			panic("changed pinned source " + s.name)
		}
		sources[s.name] = map[string]string{"url": url, "sha256": s.digest}
		bodies := regexp.MustCompile(s.pattern).FindAll(source, -1)
		want := 1
		if s.name == "resources.cpp" {
			want = 2
		}
		if len(bodies) != want {
			panic("missing complete bodies")
		}
		for i, b := range bodies {
			excerpts[fmt.Sprintf("%s-%d", s.name, i)] = hash(b)
			unit += "\n" + string(b) + "\n"
		}
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-fblocks", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=BundleStreamingResearch", "-"), &ast))
		var methods []any
		walk(ast, func(n node) {
			if n.Kind != "CXXMethodDecl" || (n.Name != "hashFile" && n.Name != "multipleHashFileData") {
				return
			}
			body := false
			for _, c := range n.Inner {
				body = body || c.Kind == "CompoundStmt"
			}
			if !body {
				return
			}
			kinds, refs := map[string]int{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.ReferencedDecl != nil {
					refs[c.ReferencedDecl.Name]++
				}
			})
			methods = append(methods, map[string]any{"name": n.Name, "ast_kinds": kinds, "references": refs})
		})
		if len(methods) != 3 {
			panic("missing AST bodies")
		}
		targets[target] = methods
	}
	result := map[string]any{"schema": 1, "driver_sha256": hash(read("scripts/extract-bundle-streaming.go")), "sources": sources, "excerpt_sha256": excerpts, "translation_unit_sha256": hash([]byte(unit)), "targets": targets, "sdk": filepath.Base(sdk), "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "scope": "Three complete verbatim methods: both ResourceBuilder::hashFile overloads and CodeDirectory::multipleHashFileData. CoreFoundation, xattr and fcntl declarations use the host SDK. Private file/hash/ref-counting helpers, scanFileData and error values are declaration-only shims. AST records digest selection, one-pass shared input and sideband ordering, not runtime execution or full Security compilation. Existing writer/allocation AST and independent native bundle captures qualify transfer, mutation limits and commit effects. No aggregate 1 GiB limit is inferred from these bodies alone."}
	data, e := json.MarshalIndent(result, "", "  ")
	must(e)
	if *check {
		var baseline, actual map[string]any
		must(json.Unmarshal(read("spec/apple-bundle-streaming.json"), &baseline))
		must(json.Unmarshal(data, &actual))
		for _, key := range []string{"driver_sha256", "sources", "excerpt_sha256", "translation_unit_sha256", "targets"} {
			if !reflect.DeepEqual(baseline[key], actual[key]) {
				panic("changed bundle streaming AST " + key)
			}
		}
	}
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	must(os.WriteFile(*out, append(data, '\n'), 0644))
	fmt.Println("Wrote", *out)
}
