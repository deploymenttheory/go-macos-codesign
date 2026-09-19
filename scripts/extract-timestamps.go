//go:build ignore

// Research only: Clang AST analysis of pinned Apple timestamp source excerpts.
// Run from the repository root: go run scripts/extract-timestamps.go
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
func run(input string, name string, args ...string) []byte {
	c := exec.Command(name, args...)
	c.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		panic(fmt.Sprintf("%s: %v\n%s", name, err, stderr.String()))
	}
	return out
}

type node struct {
	Kind  string
	Name  string
	Value string
	Type  struct{ QualType string }
	Inner []node
}

func walk(n node, visit func(node)) {
	visit(n)
	for _, c := range n.Inner {
		walk(c, visit)
	}
}

func main() {
	header, source := read(".research/apple/tsaTemplates.h"), read(".research/apple/tsaSupport.c")
	declarations := regexp.MustCompile(`(?s)typedef CSSM_OID TSAPolicyId;.*?} SecAsn1TSAPKIFailureInfo;`).Find(header)
	method := regexp.MustCompile(`(?s)static OSStatus verifyTSTInfo\(.*?\n}`).Find(source)
	if len(declarations) == 0 || len(method) == 0 {
		panic("pinned Apple excerpts missing")
	}
	shim := `
#include <stdint.h>
#include <stddef.h>
typedef struct { unsigned long Length; unsigned char* Data; } CSSM_DATA;
typedef CSSM_DATA CSSM_OID;
typedef struct { CSSM_OID algorithm; CSSM_DATA parameters; } CSSM_X509_ALGORITHM_IDENTIFIER;
typedef struct { void* unused; } CSSM_X509_EXTENSIONS;
typedef struct { void* unused; } SecCmsContentInfo;
typedef CSSM_DATA* CSSM_DATA_PTR;
typedef void* SecCmsSignerInfoRef;
typedef void* SecCertificateRef;
typedef void* SecAsn1CoderRef;
typedef double CFAbsoluteTime;
typedef int OSStatus;
typedef int SECOidTag;
enum { paramErr=-50, SECFailure=-1, errSecTimestampRejection=1, errSecInvalidDigestAlgorithm=2, errSecTimestampInvalid=3, SEC_OID_SHA256=4, SEC_OID_SHA1=5 };
#define require_action(condition, label, action) do { if (!(condition)) { action; goto label; } } while (0)
#define require_noerr(value, label) do { if ((value) != 0) goto label; } while (0)
#define dtprintf(...) ((void)0)
DECLARATIONS
extern const void* kSecAsn1TSATSTInfoTemplate;
SecCertificateRef SecCmsSignerInfoGetTimestampSigningCert(SecCmsSignerInfoRef);
OSStatus SecAsn1CoderCreate(SecAsn1CoderRef*);
OSStatus SecAsn1Decode(SecAsn1CoderRef, const void*, unsigned long, const void*, void*);
void SecAsn1CoderRelease(SecAsn1CoderRef);
void displayTSTInfo(SecAsn1TSATSTInfo*);
uint64_t tsaDER_ToInt(const CSSM_DATA*);
OSStatus SecTSAValidateTimestamp(const SecAsn1TSATSTInfo*, SecCertificateRef, CFAbsoluteTime*);
SECOidTag SECOID_GetAlgorithmTag(const CSSM_X509_ALGORITHM_IDENTIFIER*);
OSStatus createTSAMessageImprint(SecCmsSignerInfoRef, const CSSM_X509_ALGORITHM_IDENTIFIER*, CSSM_DATA_PTR, SecAsn1TSAMessageImprint*);
int CERT_CompareCssmData(const CSSM_DATA*, const CSSM_DATA*);
void secerror(const char*);
METHOD
`
	shim = strings.ReplaceAll(strings.ReplaceAll(shim, "DECLARATIONS", string(declarations)), "METHOD", string(method))
	sources := map[string]any{}
	for name, data := range map[string][]byte{"tsaTemplates.h": header, "tsaSupport.c": source} {
		sources[name] = map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_smime/lib/" + name, "sha256": hash(data)}
	}
	result := map[string]any{"schema": 1, "compiler": strings.Split(string(run("", "clang", "--version")), "\n")[0], "scope": "Verbatim timestamp ASN.1 carrier declarations, status/failure enums and verifyTSTInfo body with explicit type/function/macro shims; not a full Apple translation unit or an executed policy oracle.", "sources": sources, "excerpt_sha256": map[string]string{"declarations": hash(declarations), "verifyTSTInfo": hash(method)}, "translation_unit_sha256": hash([]byte(shim))}
	targets := map[string]any{}
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(shim, "clang", "-target", target, "-isysroot", sdk, "-x", "c", "-std=c11", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"), &ast))
		enums := map[string]string{}
		fields := map[string][]map[string]string{}
		methodKinds := map[string]int{}
		walk(ast, func(n node) {
			if n.Kind == "EnumConstantDecl" && (strings.HasPrefix(n.Name, "PKIS_") || strings.HasPrefix(n.Name, "FI_")) {
				walk(n, func(c node) {
					if c.Kind == "ConstantExpr" {
						enums[n.Name] = c.Value
					}
				})
			}
			if n.Kind == "TypedefDecl" && strings.HasPrefix(n.Name, "SecAsn1TSA") {
				fields[n.Name] = nil
			}
			if n.Kind == "FunctionDecl" && n.Name == "verifyTSTInfo" {
				walk(n, func(c node) { methodKinds[c.Kind]++ })
			}
		})
		// Anonymous C records precede their typedefs in the translation unit.
		var previous []map[string]string
		for _, n := range ast.Inner {
			if n.Kind == "RecordDecl" {
				previous = nil
				for _, f := range n.Inner {
					if f.Kind == "FieldDecl" {
						previous = append(previous, map[string]string{"name": f.Name, "type": f.Type.QualType})
					}
				}
			}
			if n.Kind == "TypedefDecl" && strings.HasPrefix(n.Name, "SecAsn1TSA") {
				fields[n.Name] = previous
			}
		}
		if len(enums) != 14 || len(methodKinds) == 0 {
			panic("incomplete AST extraction")
		}
		targets[target] = map[string]any{"enums": enums, "records": fields, "verifyTSTInfo_ast_kinds": methodKinds}
	}
	result["targets"] = targets
	b, err := json.MarshalIndent(result, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-timestamps.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-timestamps.json: two-target Clang timestamp AST")
}
