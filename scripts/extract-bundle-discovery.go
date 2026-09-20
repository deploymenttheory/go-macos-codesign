//go:build ignore

// Research only: Apple's executable-path bundle discovery through Clang ASTs.
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

const revision = "dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3"

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
	ReferencedDecl     *struct{ Name string }
	Inner              []node
}

func walk(n node, f func(node)) {
	f(n)
	for _, c := range n.Inner {
		walk(c, f)
	}
}

func main() {
	source := read(".research/apple/CFBundle.c")
	names := []string{"_CFBundleCopyBundleURLForExecutablePath", "_CFBundleCopyResolvedURLForExecutableURL", "_CFBundleCopyBundleURLForExecutableURL", "_CFBundleCreateWithExecutableURLIfLooksLikeBundle", "_CFBundleCreateWithExecutableURLIfMightBeBundle"}
	unit := `#include <CoreFoundation/CoreFoundation.h>
#include <string.h>
#define CFMaxPathSize 1024
#define DEPLOYMENT_TARGET_WINDOWS 0
#define PLATFORM_PATH_STYLE kCFURLPOSIXPathStyle
CFIndex _CFLengthAfterDeletingLastPathComponent(UniChar*,CFIndex);
CFIndex _CFStartOfLastPathComponent(UniChar*,CFIndex);
CFStringRef _CFBundleGetPlatformExecutablesSubdirectoryName(void);
CFStringRef _CFBundleGetAlternatePlatformExecutablesSubdirectoryName(void);
CFStringRef _CFBundleGetOtherPlatformExecutablesSubdirectoryName(void);
CFStringRef _CFBundleGetOtherAlternatePlatformExecutablesSubdirectoryName(void);
extern CFStringRef _CFBundleExecutablesDirectoryName;
static CFURLRef _CFBundleCopyExecutableURLIgnoringCache(CFBundleRef);
static uint8_t _CFBundleEffectiveLayoutVersion(CFBundleRef);
`
	hashes := map[string]string{}
	for _, name := range names {
		excerpt := regexp.MustCompile(`(?ms)^(?:static )?CF(?:URL|Bundle)Ref ` + name + `\(.*?\n}`).Find(source)
		if len(excerpt) == 0 {
			panic("missing complete body " + name)
		}
		hashes[name] = hash(excerpt)
		unit += "\n" + string(excerpt)
	}
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang", "-target", target, "-isysroot", sdk, "-std=c11", "-x", "c", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"), &ast))
		facts := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "FunctionDecl" || hashes[n.Name] == "" {
				return
			}
			body := false
			for _, c := range n.Inner {
				body = body || c.Kind == "CompoundStmt"
			}
			if !body {
				return
			}
			kinds, references, operators := map[string]int{}, map[string]int{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.ReferencedDecl != nil {
					references[c.ReferencedDecl.Name]++
				}
				if c.Opcode != "" {
					operators[c.Opcode]++
				}
			})
			facts[n.Name] = map[string]any{"ast_kinds": kinds, "references": references, "operators": operators}
		})
		if len(facts) != len(names) {
			panic("incomplete AST")
		}
		targets[target] = facts
	}
	result := map[string]any{"schema": 1, "scope": "Five complete verbatim CoreFoundation executable discovery bodies parsed as C with real SDK CoreFoundation declarations on two Apple targets. Private path helpers, executable lookup, effective layout version, platform directory names and the CFMaxPathSize bound are explicit interface shims, not implementations or extracted constants. The Windows-specific CF branch is excluded: production implements macOS file formats on every host. This record establishes path derivation, exact executable-path comparison and the flat-bundle metadata gate; it does not execute CoreFoundation or prove all layout/URL behavior. Native acceptance independently establishes the supported Contents/framework cases. Security's DiskRep::bestGuess call site is recorded in apple-bundle-layouts.json.", "compiler": strings.Split(string(run("", "clang", "--version")), "\n")[0], "sources": map[string]any{"CFBundle.c": map[string]string{"url": "https://github.com/apple-oss-distributions/CF/blob/" + revision + "/CFBundle.c", "sha256": hash(source)}}, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets}
	b, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile("spec/apple-bundle-discovery.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-bundle-discovery.json: five executable-discovery bodies on two targets")
}
