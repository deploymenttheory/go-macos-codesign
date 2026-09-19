//go:build ignore

// Research only. Clang AST of the pinned Apple Objective-C request methods.
// Run from the repository root: go run scripts/extract-timestamp-http.go
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
func read(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(input, name string, args ...string) []byte {
	c := exec.Command(name, args...)
	c.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, err := c.Output()
	if err != nil {
		panic(fmt.Sprintf("%s: %v\n%s", name, err, stderr.String()))
	}
	return b
}

type node struct {
	Kind, Name, Selector string
	Value                any
	Inner                []node
}

func walk(n node, visit func(node)) {
	visit(n)
	for _, c := range n.Inner {
		walk(c, visit)
	}
}
func main() {
	source := read(".research/apple/timestampclient.m")
	prefs := read(".research/apple/TimeStampingPrefs.plist")
	init := regexp.MustCompile(`(?s)- \(id\)initWithURLString:.*?\n}`).Find(source)
	post := regexp.MustCompile(`(?s)- \(void\)post:.*?\n}`).Find(source)
	endpoint := regexp.MustCompile(`<key>ServerURL</key>\s*<string>([^<]+)</string>`).FindSubmatch(prefs)
	if len(init) == 0 || len(post) == 0 || len(endpoint) != 2 {
		panic("missing pinned source excerpt")
	}
	unit := `#import <Foundation/Foundation.h>
@interface TimeStampClient : NSObject {
 NSURL *url;
 NSMutableURLRequest *urlRequest;
}
@property (readonly) NSURL *url;
@property (readonly) NSMutableURLRequest *urlRequest;
@end
@implementation TimeStampClient
@synthesize url;
@synthesize urlRequest;
` + string(init) + "\n" + string(post) + "\n@end\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang", "-target", target, "-isysroot", sdk, "-x", "objective-c", "-fsyntax-only", "-Wno-deprecated-declarations", "-Xclang", "-ast-dump=json", "-"), &ast))
		methods := map[string]any{}
		walk(ast, func(n node) {
			if n.Kind != "ObjCMethodDecl" || n.Name != "post:" && n.Name != "initWithURLString:" {
				return
			}
			hasBody := false
			for _, c := range n.Inner {
				hasBody = hasBody || c.Kind == "CompoundStmt"
			}
			if !hasBody {
				return
			}
			literals, messages, kinds := []string{}, []string{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				switch c.Kind {
				case "StringLiteral", "FloatingLiteral":
					literals = append(literals, fmt.Sprint(c.Value))
				case "ObjCMessageExpr":
					messages = append(messages, c.Selector)
				}
			})
			methods[n.Name] = map[string]any{"literals": literals, "messages": messages, "ast_kinds": kinds}
		})
		if len(methods) != 2 {
			panic("incomplete Objective-C AST extraction")
		}
		targets[target] = methods
	}
	base := "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_keychain/"
	result := map[string]any{"schema": 1, "compiler": strings.Split(string(run("", "clang", "--version")), "\n")[0], "scope": "Verbatim initWithURLString: and post: bodies with a minimal TimeStampClient interface and the Foundation SDK; request construction facts only, not execution of Apple's transport or trust policy.", "sources": map[string]any{"timestampclient.m": map[string]string{"url": base + "xpc-tsa/timestampclient.m", "sha256": hash(source)}, "TimeStampingPrefs.plist": map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/lib/TimeStampingPrefs.plist", "sha256": hash(prefs)}}, "excerpt_sha256": map[string]string{"initWithURLString:": hash(init), "post:": hash(post)}, "translation_unit_sha256": hash([]byte(unit)), "default_url": string(endpoint[1]), "targets": targets}
	b, err := json.MarshalIndent(result, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-timestamp-http.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-timestamp-http.json: two-target Objective-C Clang AST")
}
