#!/usr/bin/env python3
"""Research only: compile pinned Apple signature sizing excerpts with Clang."""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import subprocess

REVISION = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
SOURCES = {
    "CodeSigner.cpp": "OSX/libsecurity_codesigning/lib/CodeSigner.cpp",
    "superblob.h": "OSX/libsecurity_utilities/lib/superblob.h",
    "cmsasn1.c": "OSX/libsecurity_smime/lib/cmsasn1.c",
}


def run(args, source=None):
    return subprocess.run(args, input=source, text=True, capture_output=True, check=True).stdout


def walk(node):
    yield node
    for child in node.get("inner", []):
        yield from walk(child)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", default=".research/apple")
    parser.add_argument("--output", default="spec/apple-signature.json")
    args = parser.parse_args()
    sources = {name: (pathlib.Path(args.source_dir) / name).read_bytes() for name in SOURCES}
    assignment = re.search(r"state\.mCMSSize = \d+;", sources["CodeSigner.cpp"].decode()).group()
    sizing = re.search(r"template <class _BlobType, uint32_t _magic, class _Type>\nsize_t SuperBlobCore.*?\n\}",
                       sources["superblob.h"].decode(), re.S).group()
    # Only the surrounding types are shims. The assignment and the entire
    # sizing method body are verbatim Apple source, compiled without rewriting.
    shim = """
#include <cstdint>
#include <cstddef>
#include <cstdarg>
#include <map>
#include <vector>
namespace CodesignSizingResearch {
struct State { size_t mCMSSize; } state;
void defaultCMSSize() { ASSIGNMENT }
struct BlobCore { size_t length() const; };
template<class _BlobType, uint32_t _magic, class _Type>
class SuperBlobCore {
    uint32_t magic, length, count;
    struct Index { uint32_t type, offset; };
public:
    class Maker {
        std::map<_Type, BlobCore*> mPieces;
    public:
        size_t size(const std::vector<size_t>& sizes, size_t size1, ...) const;
    };
};
SIZING
}
""".replace("ASSIGNMENT", assignment).replace("SIZING", sizing)
    sdk = run(["xcrun", "--show-sdk-path"]).strip()
    result = {"schema": 1, "compiler": run(["clang", "--version"]).splitlines()[0],
              "sdk": pathlib.Path(sdk).resolve().name,
              "scope": "verbatim assignment and complete sizing method body, with declared type shims; not the full Apple translation unit or a wire-layout derivation",
              "sources": {name: {"url": f"https://github.com/apple-oss-distributions/Security/blob/{REVISION}/{path}",
                                  "sha256": hashlib.sha256(sources[name]).hexdigest()} for name, path in SOURCES.items()},
              "assignment_sha256": hashlib.sha256(assignment.encode()).hexdigest(),
              "sizing_excerpt_sha256": hashlib.sha256(sizing.encode()).hexdigest(),
              "translation_unit_sha256": hashlib.sha256(shim.encode()).hexdigest(), "targets": {}}
    for target in ("arm64-apple-macos27", "x86_64-apple-macos27"):
        ast = json.loads(run(["clang", "-target", target, "-isysroot", sdk, "-x", "c++", "-std=c++17",
                              "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter",
                              "-Xclang", "CodesignSizingResearch", "-"], shim))
        default = next(n for n in walk(ast) if n.get("kind") == "FunctionDecl" and n.get("name") == "defaultCMSSize")
        value = next(n["value"] for n in walk(default) if n.get("kind") == "IntegerLiteral")
        method = next(n for n in walk(ast) if n.get("kind") == "CXXMethodDecl" and n.get("name") == "size"
                      and any(c.get("kind") == "CompoundStmt" for c in n.get("inner", [])))
        result["targets"][target] = {"default_cms_blob_size": int(value), "sizing_method_type": method["type"]["qualType"],
                                     "sizing_ast_node_counts": dict(sorted(collections.Counter(n["kind"] for n in walk(method) if "kind" in n).items())),
                                     "sizing_operators": sorted(set(n["opcode"] for n in walk(method) if "opcode" in n))}
    output = pathlib.Path(args.output)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {output}: two-target Clang sizing AST facts and pinned CMS template provenance")


if __name__ == "__main__":
    main()
