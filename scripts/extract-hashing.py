#!/usr/bin/env python3
"""Compile complete pinned CodeDirectory hash/validation methods; research only."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request


def run(args, source=None):
    return subprocess.run(args, input=source, text=True, capture_output=True, check=True).stdout


def walk(node):
    yield node
    for child in node.get("inner", []):
        yield from walk(child)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=".research/apple/codedirectory.cpp")
    parser.add_argument("--output", default="spec/apple-hashing.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source_path = Path(args.source)
    url = "https://raw.githubusercontent.com/apple-oss-distributions/Security/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/codedirectory.cpp"
    if source_path.is_file():
        source = source_path.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=60) as response:
            source = response.read()
    if args.check:
        baseline = json.loads(Path("spec/apple-hashing.json").read_text())
        if hashlib.sha256(source).hexdigest() != baseline["source_sha256"]:
            raise ValueError("Apple source hash changed")
    excerpts = re.findall(r"(?:bool CodeDirectory::validateSlot|size_t CodeDirectory::generateHash)\([^\n]+\n\{.*?\n\}", source.decode(), re.S)
    if len(excerpts) != 4:
        raise ValueError("Expected four complete Apple method bodies")
    shim = '''
#include <cstddef>
#include <cstring>
#include <vector>
namespace CodesignHashingResearch {
using std::vector;
namespace Hashing { using Byte = unsigned char; }
struct FileDesc { int fd; };
struct DynamicHash {
 size_t digestLength() const;
 void update(const void *, size_t);
 void finish(Hashing::Byte *);
};
template<class T> struct MakeHash {
 MakeHash(const T *);
 DynamicHash *operator->() const;
 operator DynamicHash *() const;
};
void secinfo(const char *, const char *, ...);
size_t hashFileData(FileDesc, DynamicHash *, size_t);
struct CodeDirectory {
 using Slot = int;
 const void *getSlot(Slot, bool) const;
 bool validateSlot(const void *, size_t, Slot, bool) const;
 bool validateSlot(FileDesc, size_t, Slot, bool) const;
 static size_t generateHash(DynamicHash *, FileDesc, Hashing::Byte *, size_t);
 static size_t generateHash(DynamicHash *, const void *, size_t, Hashing::Byte *);
};
''' + '\n'.join(excerpts) + '\n}\n'
    sdk = run(["xcrun", "--show-sdk-path"]).strip()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    result = {"schema": 1, "scope": "four complete verbatim Apple methods with declaration-only type shims; neither full translation unit nor runtime evidence for hashFileData",
              "source_url": "https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/codedirectory.cpp",
              "source_sha256": sha(source), "driver_sha256": sha(Path(__file__).read_bytes()), "excerpt_sha256": [sha(e.encode()) for e in excerpts],
              "translation_unit_sha256": sha(shim.encode()), "compiler": run(["clang", "--version"]).splitlines()[0], "targets": {}}
    for target in ("arm64-apple-macos27", "x86_64-apple-macos27"):
        ast = json.loads(run(["clang", "-target", target, "-isysroot", sdk, "-x", "c++", "-std=c++17", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter", "-Xclang", "CodesignHashingResearch", "-"], shim))
        methods = [n for n in walk(ast) if n.get("kind") == "CXXMethodDecl" and n.get("name") in ("generateHash", "validateSlot") and any(c.get("kind") == "CompoundStmt" for c in n.get("inner", []))]
        if len(methods) != 4:
            raise ValueError("Incomplete method AST")
        result["targets"][target] = [{"name": n["name"], "type": n["type"]["qualType"], "nodes": dict(sorted(collections.Counter(c["kind"] for c in walk(n)).items()))} for n in methods]
    if args.check:
        for key in ("source_sha256", "driver_sha256", "excerpt_sha256", "translation_unit_sha256", "targets"):
            if result[key] != baseline[key]:
                raise ValueError("Hashing AST changed: " + key)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print("Wrote", args.output)


if __name__ == "__main__":
    main()
