#!/usr/bin/env python3
"""Research only: analyze verbatim Apple certificate policy excerpts with Clang."""
import collections
import hashlib
import json
import pathlib
import re
import subprocess

REVISION = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
FILES = ("StaticCode.cpp", "CodeSigner.cpp", "drmaker.cpp")


def run(args, source=None):
    return subprocess.run(args, input=source, text=True, capture_output=True, check=True).stdout


def walk(node):
    yield node
    for child in node.get("inner", []):
        yield from walk(child)


def main():
    sources = {name: (pathlib.Path(".research/apple") / name).read_bytes() for name in FILES}
    declarations = re.findall(r"static const char (?:WWDRRequirement|MACWWDRRequirement|developerID|distributionCertificate|iPhoneDistributionCert)\[\].*?;", sources["StaticCode.cpp"].decode(), re.S)
    team = re.search(r"std::string SecCodeSigner::getTeamIDFromSigner\(CFArrayRef certs\)\n\{.*?\n\}", sources["CodeSigner.cpp"].decode(), re.S).group()
    organization = re.search(r"void DRMaker::nonAppleAnchor\(\)\n\{.*?\n\}", sources["drmaker.cpp"].decode(), re.S).group()
    shim = r"""
#include <string>
#include <cstddef>
#define TARGET_OS_OSX 1
namespace CertificateResearch {
using CFArrayRef = void*; using CFStringRef = void*;
using SecCertificateRef = void*; using SecIdentityRef = void*;
struct DERItem {}; extern DERItem oidOrganizationalUnitName, oidOrganizationName;
extern void* kCFNull;
constexpr int errSecCSInvalidTeamIdentifier=1, kCFCompareEqualTo=0;
void secerror(const char*); void secinfo(const char*, const char*);
template<class T> struct CFRef {
    CFRef(T = nullptr); T& aref(); T get(); void take(T);
    operator T() const;
};
struct MacOSError { static void check(int); static void throwMe(int); };
int SecIdentityCopyCertificate(SecIdentityRef, SecCertificateRef*);
CFStringRef SecCertificateCopySubjectAttributeValue(SecCertificateRef, DERItem*);
int CFStringCompare(CFStringRef, CFStringRef, int);
std::string cfString(CFStringRef);
struct SecStaticCode { static bool isAppleDeveloperCert(CFArrayRef); };
struct SecCodeSigner { SecIdentityRef mSigner; std::string getTeamIDFromSigner(CFArrayRef); };
struct Requirement { static constexpr int leafCert=0, anchorCert=-1; };
struct Context { SecCertificateRef cert(int); unsigned certCount(); };
struct SHA1 { using Digest = unsigned char[20]; };
void hashOfCertificate(SecCertificateRef, SHA1::Digest&);
struct DRMaker { Context ctx; void anchor(int, SHA1::Digest&); void nonAppleAnchor(); };
DECLARATIONS
TEAM
ORGANIZATION
}
""".replace("DECLARATIONS", "\n".join(declarations)).replace("TEAM", team).replace("ORGANIZATION", organization)
    sdk = run(["xcrun", "--show-sdk-path"]).strip()
    result = {"schema": 1, "compiler": run(["clang", "--version"]).splitlines()[0],
              "scope": "verbatim macOS Team ID method, organization anchor method and developer requirement constants with type shims; not a full Apple translation unit or executed policy oracle",
              "sources": {name: {"url": f"https://github.com/apple-oss-distributions/Security/blob/{REVISION}/OSX/libsecurity_codesigning/lib/{name}", "sha256": hashlib.sha256(data).hexdigest()} for name, data in sources.items()},
              "excerpt_sha256": {"team": hashlib.sha256(team.encode()).hexdigest(), "organization": hashlib.sha256(organization.encode()).hexdigest()},
              "translation_unit_sha256": hashlib.sha256(shim.encode()).hexdigest(), "targets": {}}
    for target in ("arm64-apple-macos27", "x86_64-apple-macos27"):
        ast = json.loads(run(["clang", "-target", target, "-isysroot", sdk, "-x", "c++", "-std=c++17", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter", "-Xclang", "CertificateResearch", "-"], shim))
        facts = {"requirements": {}, "methods": {}}
        for node in walk(ast):
            if node.get("kind") == "VarDecl" and node.get("name") in {"WWDRRequirement", "MACWWDRRequirement", "developerID", "distributionCertificate", "iPhoneDistributionCert"}:
                facts["requirements"][node["name"]] = next(n["value"] for n in walk(node) if n.get("kind") == "StringLiteral")
            if node.get("kind") == "CXXMethodDecl" and node.get("name") in {"getTeamIDFromSigner", "nonAppleAnchor"} and any(n.get("kind") == "CompoundStmt" for n in node.get("inner", [])):
                facts["methods"][node["name"]] = dict(sorted(collections.Counter(n["kind"] for n in walk(node) if "kind" in n).items()))
        result["targets"][target] = facts
    pathlib.Path("spec/apple-certificates.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Wrote spec/apple-certificates.json: two-target Clang certificate policy AST")


if __name__ == "__main__":
    main()
