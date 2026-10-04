#!/usr/bin/env python3
"""Compile pinned Apple held-file header/signature readers; research only."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import urllib.request

spec = importlib.util.spec_from_file_location("hashing", Path(__file__).with_name("extract-hashing.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", default="spec/apple-source-ranges.json")
    args = parser.parse_args()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    excerpts, sources = [], {}
    for name, method in (("diskimagerep.cpp", "bool DiskImageRep::readHeader"), ("machorep.cpp", "EmbeddedSignatureBlob *MachORep::signingData")):
        url = "https://raw.githubusercontent.com/apple-oss-distributions/Security/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/" + name
        path = Path(".research/apple") / name
        if path.is_file():
            source = path.read_bytes()
        else:
            with urllib.request.urlopen(url, timeout=60) as response:
                source = response.read()
        match = re.search(re.escape(method) + r"\([^\n]*\)\n\{.*?\n\}", source.decode(), re.S)
        if not match:
            raise ValueError("Missing complete Apple method: " + method)
        excerpts.append(match.group())
        sources[name] = {"url": url, "sha256": sha(source)}
    name = "codedirectory.h"
    url = "https://raw.githubusercontent.com/apple-oss-distributions/Security/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/" + name
    path = Path(".research/apple") / name
    if path.is_file():
        source = path.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=60) as response:
            source = response.read()
    limit = re.search(r"size_t signingLimit\(\) const\s+\{[^}]+\}", source.decode()).group()
    sources[name] = {"url": url, "sha256": sha(source)}
    excerpts.append(limit)
    unit = '''
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <mach-o/loader.h>
namespace CodesignSourceResearch {
using std::unique_ptr;
struct FileDesc { size_t fileSize(); size_t read(void *, size_t, size_t); };
// Declaration shims: this does not derive or validate the UDIF wire layout.
struct UDIFFileHeader { uint32_t fUDIFSignature, fUDIFVersion; char opaque[504]; };
struct BlobCore { uint32_t magic, length; };
uint32_t n2h(uint32_t);
const uint32_t kUDIFSignature = 0x6b6f6c79;
const int32_t udifVersion = 4;
struct DiskImageRep { static bool readHeader(FileDesc&, UDIFFileHeader&); };
struct Architecture { const char *name(); };
struct MachO { const linkedit_data_command *findCodeSignature(); uint32_t flip(uint32_t); FileDesc &fd(); size_t offset(); Architecture architecture(); };
struct Universal { MachO *architecture(); };
struct EmbeddedSignatureBlob { static EmbeddedSignatureBlob *readBlob(FileDesc&, size_t, size_t); size_t length(); int count(); };
struct MachORep { EmbeddedSignatureBlob *mSigningData; Universal *mainExecutableImage(); std::string mainExecutablePath(); EmbeddedSignatureBlob *signingData(); };
void secinfo(const char *, const char *, ...);
struct MacOSError { static void throwMe(int); };
const int errSecCSSignatureInvalid = -67061;
''' + '\n'.join(excerpts[:2]) + '\nstruct CodeDirectory { uint32_t version, codeLimit; uint64_t codeLimit64; static const uint32_t supportsCodeLimit64 = 0x20300;\n' + limit + '\n};\n}\n'
    result = {"schema": 1, "scope": "two complete verbatim Apple held-file reader methods and inline CodeDirectory signingLimit with declaration-only shims; not full translation units, runtime execution or UDIF layout derivation",
              "sources": sources, "driver_sha256": sha(Path(__file__).read_bytes()),
              "helper_sha256": sha(Path(__file__).with_name("extract-hashing.py").read_bytes()),
              "excerpt_sha256": [sha(e.encode()) for e in excerpts], "translation_unit_sha256": sha(unit.encode()),
              "compiler": helpers.run(["clang", "--version"]).splitlines()[0], "targets": {}}
    sdk = helpers.run(["xcrun", "--show-sdk-path"]).strip()
    for target in ("arm64-apple-macos27", "x86_64-apple-macos27"):
        ast = json.loads(helpers.run(["clang", "-target", target, "-isysroot", sdk, "-x", "c++", "-std=c++17", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter", "-Xclang", "CodesignSourceResearch", "-"], unit))
        methods = [n for n in helpers.walk(ast) if n.get("kind") == "CXXMethodDecl" and n.get("name") in ("readHeader", "signingData", "signingLimit") and any(c.get("kind") == "CompoundStmt" for c in n.get("inner", []))]
        if len(methods) != 3:
            raise ValueError("Incomplete reader AST")
        result["targets"][target] = [{"name": n["name"], "type": n["type"]["qualType"], "nodes": dict(sorted(collections.Counter(c["kind"] for c in helpers.walk(n)).items()))} for n in methods]
    if args.check:
        baseline = json.loads(Path("spec/apple-source-ranges.json").read_text())
        for key in ("sources", "driver_sha256", "helper_sha256", "excerpt_sha256", "translation_unit_sha256", "targets"):
            if result[key] != baseline[key]:
                raise ValueError("Source range AST changed: " + key)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print("Wrote", args.output)


if __name__ == "__main__":
    main()
