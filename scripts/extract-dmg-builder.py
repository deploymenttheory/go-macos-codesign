#!/usr/bin/env python3
"""Compile complete pinned CodeDirectory builder bodies; research only."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import urllib.request

spec = importlib.util.spec_from_file_location("hashing", Path(__file__).with_name("extract-hashing.py"))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", default="spec/apple-dmg-builder.json")
    args = parser.parse_args()
    url = "https://raw.githubusercontent.com/apple-oss-distributions/Security/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/cdbuilder.cpp"
    path = Path(".research/apple/cdbuilder.cpp")
    if path.is_file():
        source = path.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=60) as response:
            source = response.read()
    excerpts = re.findall(r"(?:size_t|CodeDirectory \*) ?CodeDirectory::Builder::(?:fixedSize|size|build)\([^\n]*\)\n\{.*?\n\}", source.decode(), re.S)
    if len(excerpts) != 3:
        raise ValueError("Expected three complete builder bodies")
    unit = '''
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
namespace CodesignBuilderResearch {
using std::min; using std::frexp;
using SpecialSlot = int;
using PreEncryptHashMap = std::map<int, const void *>;
const unsigned char *CFDataGetBytePtr(const void *);
struct UnixError { static void throwMe(int); };
struct MacOSError { static void throwMe(int); };
const int errSecCSTooBig = -1; // declaration shim, not a wire/error oracle
struct FileDesc { operator bool(); size_t fileSize(); void seek(size_t); };
template<class T> struct MakeHash { MakeHash(T *); };
struct CodeDirectory {
 static const uint32_t supportsScatter=0x20100, supportsTeamID=0x20200,
 supportsCodeLimit64=0x20300, supportsExecSegment=0x20400,
 supportsPreEncrypt=0x20500, currentVersion=0x20500;
 uint32_t version, flags, nSpecialSlots, nCodeSlots, codeLimit, runtime,
 preEncryptOffset, spare3, teamIDOffset, scatterOffset, identOffset, hashOffset;
 uint64_t codeLimit64, execSegBase, execSegLimit, execSegFlags;
 uint8_t hashType, platform, hashSize, pageSize;
 void initialize(size_t); void *scatterVector(); char *identifier(); char *teamID();
 unsigned char *getSlotMutable(int, bool); const unsigned char *getSlot(int, bool);
 struct Builder;
};
struct CodeDirectory::Builder : CodeDirectory {
 FileDesc mExec; CodeDirectory *mDir; std::string mIdentifier, mTeamID;
 bool mGeneratePreEncryptHashes; PreEncryptHashMap mPreservedPreEncryptHashMap;
 uint32_t mRuntimeVersion, mFlags; int mHashType, mPlatform;
 size_t mExecLength, mExecOffset, mExecSegOffset, mExecSegLimit, mExecSegFlags,
 mCodeSlots, mSpecialSlots, mDigestLength, mPageSize, mScatterSize;
 void *mScatter;
 size_t fixedSize(uint32_t); size_t size(uint32_t); CodeDirectory *build();
 const void *specialSlot(SpecialSlot);
 void generateHash(MakeHash<Builder>&, FileDesc&, unsigned char *, size_t);
};
''' + '\n'.join(excerpts) + '\n}\n'
    sha = lambda b: hashlib.sha256(b).hexdigest()
    result = {"schema": 1, "scope": "Complete verbatim fixedSize, size and build bodies with declaration-only type/API shims; shim object layout is not wire-layout evidence and bodies are not executed. Native large-source signatures establish serialized headers and limits.",
              "source_url": url, "source_sha256": sha(source), "driver_sha256": sha(Path(__file__).read_bytes()),
              "helper_sha256": sha(Path(__file__).with_name("extract-hashing.py").read_bytes()),
              "excerpt_sha256": [sha(e.encode()) for e in excerpts], "translation_unit_sha256": sha(unit.encode()),
              "compiler": h.run(["clang", "--version"]).splitlines()[0], "targets": {}}
    sdk = h.run(["xcrun", "--show-sdk-path"]).strip()
    for target in ("arm64-apple-macos27", "x86_64-apple-macos27"):
        ast = json.loads(h.run(["clang", "-target", target, "-isysroot", sdk, "-x", "c++", "-std=c++17", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter", "-Xclang", "CodesignBuilderResearch", "-"], unit))
        methods = [n for n in h.walk(ast) if n.get("kind") == "CXXMethodDecl" and n.get("name") in ("fixedSize", "size", "build") and any(c.get("kind") == "CompoundStmt" for c in n.get("inner", []))]
        if len(methods) != 3:
            raise ValueError("Incomplete builder AST")
        result["targets"][target] = [{"name": n["name"], "nodes": dict(sorted(collections.Counter(c["kind"] for c in h.walk(n) if "kind" in c).items()))} for n in methods]
    if args.check:
        baseline = json.loads(Path("spec/apple-dmg-builder.json").read_text())
        for key in result.keys() - {"compiler"}:
            if result[key] != baseline[key]:
                raise ValueError("Builder AST changed: " + key)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print("Wrote", args.output)


if __name__ == "__main__":
    main()
