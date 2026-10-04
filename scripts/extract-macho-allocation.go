//go:build ignore

// Research only: parse Apple's complete signature-allocation body using Clang.
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

func must(err error) {
	if err != nil {
		panic(err)
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
	check := flag.Bool("check", false, "compare complete native allocation AST bodies")
	output := flag.String("out", "spec/apple-macho-allocation.json", "output path")
	flag.Parse()
	const revision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
	const sourcePath = ".research/apple/codesign_alloc.cpp"
	source, err := os.ReadFile(sourcePath)
	if os.IsNotExist(err) {
		client := &http.Client{Timeout: 60 * time.Second}
		response, err := client.Get("https://raw.githubusercontent.com/apple-oss-distributions/Security/" + revision + "/OSX/libsecurity_codesigning/lib/codesign_alloc.cpp")
		must(err)
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			panic(response.Status)
		}
		source, err = io.ReadAll(io.LimitReader(response.Body, 1<<20))
		must(err)
	} else {
		must(err)
	}
	if hash(source) != "d76101e6f989374b3a065ca9c9d5fdfc2b8237f05894eda93b43e48f5e04a604" {
		panic("changed pinned Apple allocator source")
	}
	// The full translation unit requires a private os/cleanup.h header. These
	// complete functions need only public SDK types plus I/O declarations.
	unit := `#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <os/overflow.h>
namespace CodesignAllocationResearch {
void log_error(char*&, const char*, ...);
bool mapFile(const char*, const void*&, uint64_t&, char*&);
bool vm_alloc(void*&, vm_size_t, char*&);
bool vm_dealloc(void*&, vm_size_t, char*&);
bool writeFile(const char*, const void*, size_t, char*&);
`
	hashes := map[string]string{}
	for _, name := range []string{"get32", "get64", "assure_signature_space"} {
		excerpt := regexp.MustCompile(`(?ms)^(?:static )?(?:bool|uint32_t|uint64_t) ` + name + `\(.*?^}`).Find(source)
		if len(excerpt) == 0 {
			panic("missing complete function " + name)
		}
		hashes[name] = hash(excerpt)
		unit += "\n" + string(excerpt) + "\n"
	}
	unit += "}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignAllocationResearch", "-"), &ast))
		facts := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "FunctionDecl" || hashes[n.Name] == "" {
				return
			}
			kinds, members, operators, integers, references := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.Kind == "MemberExpr" {
					members[c.Name]++
				}
				if c.Opcode != "" {
					operators[c.Opcode]++
				}
				if c.Kind == "IntegerLiteral" {
					integers[fmt.Sprint(c.Value)]++
				}
				if c.Kind == "DeclRefExpr" && c.ReferencedDecl != nil {
					references[c.ReferencedDecl.Name]++
				}
			})
			if kinds["CompoundStmt"] == 0 {
				panic("missing body")
			}
			facts[n.Name] = map[string]any{"ast_kinds": kinds, "members": members, "operators": operators, "integers": integers, "references": references}
		})
		if len(facts) != len(hashes) {
			panic("incomplete AST")
		}
		targets[target] = facts
	}
	result := map[string]any{
		"schema":         1,
		"driver_sha256":  hash(read("scripts/extract-macho-allocation.go")),
		"scope":          "Complete verbatim get32, get64 and assure_signature_space bodies. Public SDK Mach-O, VM, endian and overflow declarations/macros are real. Logging, file I/O and VM allocation wrappers are declaration-only shims. No private header or complete Security build is claimed. AST records source control flow, not execution; independent native comparisons determine observed behavior. The portable implementation validates malformed symbol ranges before truncation and does not reproduce unsafe native pointer/overflow behavior.",
		"compiler":       strings.Split(string(run("", "clang++", "--version")), "\n")[0],
		"sdk":            filepath.Base(sdk),
		"sources":        map[string]any{"codesign_alloc.cpp": map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/codesign_alloc.cpp", "sha256": hash(source)}},
		"sdk_headers":    map[string]string{"mach-o/loader.h": hash(read(filepath.Join(sdk, "usr/include/mach-o/loader.h"))), "mach-o/fat.h": hash(read(filepath.Join(sdk, "usr/include/mach-o/fat.h")))},
		"excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets,
	}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.MkdirAll(filepath.Dir(*output), 0755))
	must(os.WriteFile(*output, append(b, '\n'), 0644))
	if *check {
		var baseline, actual map[string]any
		must(json.Unmarshal(read("spec/apple-macho-allocation.json"), &baseline))
		must(json.Unmarshal(b, &actual))
		for _, key := range []string{"driver_sha256", "sources", "excerpt_sha256", "translation_unit_sha256", "targets"} {
			if !reflect.DeepEqual(baseline[key], actual[key]) {
				panic("changed native allocation AST: " + key)
			}
		}
	}
	fmt.Println("Wrote spec/apple-macho-allocation.json: two-target allocation AST")
}
