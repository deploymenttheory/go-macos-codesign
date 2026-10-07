//go:build ignore

// Research only: inspect complete pinned Apple method bodies through Clang.
// Apple source is subject to its original Apple Public Source License notice;
// the source URLs and exact complete-source/excerpt hashes accompany the facts.
package main

import (
	"bytes"
	"context"
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

const revision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
const driver = "scripts/extract-macho-command-policy.go"
const baselinePath = "spec/apple-macho-command-policy.json"

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(ctx context.Context, input, name string, args ...string) []byte {
	c := exec.CommandContext(ctx, name, args...)
	c.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, e := c.Output()
	if e != nil {
		panic(fmt.Sprintf("%s: %v %s", name, e, stderr.String()))
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
func source(ctx context.Context, name, folder, want string) ([]byte, string) {
	url := "https://raw.githubusercontent.com/apple-oss-distributions/Security/" + revision + "/OSX/" + folder + "/lib/" + name
	b, e := os.ReadFile(filepath.Join(".research/apple", name))
	if os.IsNotExist(e) {
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		must(e)
		response, e := (&http.Client{Timeout: 60 * time.Second}).Do(request)
		must(e)
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			panic(response.Status)
		}
		b, e = io.ReadAll(io.LimitReader(response.Body, 2<<20))
		must(e)
	} else {
		must(e)
	}
	if hash(b) != want {
		panic("pinned Apple source changed: " + name)
	}
	return b, url
}
func main() {
	out := flag.String("out", baselinePath, "facts output")
	check := flag.Bool("check", false, "compare pinned method facts with retained evidence")
	flag.Parse()
	var baseline map[string]any
	if *check {
		must(json.Unmarshal(read(baselinePath), &baseline))
	}
	ctx := context.Background()
	sources := map[string]map[string]string{}
	files := map[string][]byte{}
	for _, entry := range []struct{ name, folder, sha string }{
		{"machorep.cpp", "libsecurity_codesigning", "a4bad9b5376334efef9f87e00e740a6c336b0ca70dee4263a123995ef51ba9d6"},
		{"macho++.cpp", "libsecurity_utilities", "86392252644a1627df61545932f061376c67d90ef5501acd1b14bebbdf7145bf"},
		{"macho++.h", "libsecurity_utilities", "68a8ddf756751dea7c59b39927f23c47a784871713caf28c1c95bbc16e828f8b"},
	} {
		b, url := source(ctx, entry.name, entry.folder, entry.sha)
		files[entry.name] = b
		sources[entry.name] = map[string]string{"url": url, "sha256": hash(b)}
	}
	platform := regexp.MustCompile(`(?m)^\s*uint32_t platform\(\) const \{[^\n]*\};`).Find(files["macho++.h"])
	if len(platform) == 0 {
		panic("complete inline platform method missing")
	}
	unit := `#include <cstdint>
#include <cstddef>
#include <cerrno>
#include <memory>
#include <mach-o/loader.h>
namespace CommandPolicyResearch {
using std::unique_ptr;
struct UnixError { static void throwMe(int); };
struct Architecture {};
template<class From, class To> To int_cast(From);
class MachOBase {
public:
 template<class T> T flip(T) const;
 bool is64() const;
 const load_command *loadCommands() const;
 const load_command *nextCommand(const load_command *) const;
 const segment_command *findSegment(const char *) const;
 const version_min_command *findMinVersion() const;
 const build_version_command *findBuildVersion() const;
 bool version(uint32_t *, uint32_t *, uint32_t *) const;
` + string(platform) + `
};
class MachO : public MachOBase {};
class Executable { public: MachO *architecture(); MachO *architecture(const Architecture&); };
class MachORep {
public:
 bool needsExecSeg(const MachO&);
 size_t execSegBase(const Architecture *);
 size_t execSegLimit(const Architecture *);
 Executable *mExecutable;
};
`
	excerpts := map[string]string{"platform": hash(platform)}
	for _, entry := range []struct{ file, name, pattern string }{
		{"machorep.cpp", "needsExecSeg", `bool MachORep::needsExecSeg\(`},
		{"machorep.cpp", "execSegBase", `size_t MachORep::execSegBase\(`},
		{"machorep.cpp", "execSegLimit", `size_t MachORep::execSegLimit\(`},
		{"macho++.cpp", "findMinVersion", `const version_min_command \*MachOBase::findMinVersion\(`},
		{"macho++.cpp", "findBuildVersion", `const build_version_command \*MachOBase::findBuildVersion\(`},
		{"macho++.cpp", "version", `bool MachOBase::version\(`},
	} {
		body := regexp.MustCompile(`(?ms)^` + entry.pattern + `.*?^}`).Find(files[entry.file])
		if len(body) == 0 {
			panic("complete Apple method missing: " + entry.name)
		}
		excerpts[entry.name] = hash(body)
		unit += "\n" + string(body) + "\n"
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run(ctx, "", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(ctx, unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CommandPolicyResearch", "-"), &ast))
		facts := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "CXXMethodDecl" || excerpts[n.Name] == "" {
				return
			}
			body := false
			for _, child := range n.Inner {
				if child.Kind == "CompoundStmt" {
					body = true
				}
			}
			if !body {
				return
			}
			kinds, refs, members, operators, integers := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.Kind == "DeclRefExpr" && c.ReferencedDecl != nil {
					refs[c.ReferencedDecl.Name]++
				}
				if c.Kind == "MemberExpr" {
					members[c.Name]++
				}
				if c.Opcode != "" {
					operators[c.Opcode]++
				}
				if c.Kind == "IntegerLiteral" {
					integers[fmt.Sprint(c.Value)]++
				}
			})
			facts[n.Name] = map[string]any{"ast_kinds": kinds, "references": refs, "members": members, "operators": operators, "integers": integers}
		})
		if len(facts) != len(excerpts) {
			panic("incomplete method-body AST inventory")
		}
		targets[target] = facts
	}
	result := map[string]any{"schema": 1, "scope": "Seven complete verbatim Apple methods: MachORep needsExecSeg/execSegBase/execSegLimit and MachOBase findMinVersion/findBuildVersion/version/platform. SDK Mach-O structures, platform constants and standard unique_ptr are real. Private executable lookup, integer cast, endian conversion, command iteration and error interfaces are declaration-only shims; this extracts all selected method bodies but neither links nor executes Apple code. AST establishes first-build-command precedence, fallback first legacy version, size checks and platform-conditioned executable-segment metadata. Native C-generated corpus independently validates signing behavior.", "license": "Original Apple source notices apply; Apple Public Source License 2.0, https://www.opensource.apple.com/apsl/", "driver_sha256": hash(read(driver)), "compiler": strings.Split(string(run(ctx, "", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk), "sources": sources, "sdk_headers": map[string]string{"mach-o/loader.h": hash(read(filepath.Join(sdk, "usr/include/mach-o/loader.h")))}, "excerpt_sha256": excerpts, "translation_unit_sha256": hash([]byte(unit)), "targets": targets}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	must(os.WriteFile(*out, append(b, '\n'), 0644))
	if *check {
		var actual map[string]any
		must(json.Unmarshal(b, &actual))
		for _, key := range []string{"driver_sha256", "sources", "excerpt_sha256", "translation_unit_sha256", "targets"} {
			if !reflect.DeepEqual(baseline[key], actual[key]) {
				panic("Apple command policy AST changed: " + key)
			}
		}
	}
	fmt.Println("qualified seven complete Apple methods for both Clang targets")
}
