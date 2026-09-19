#!/usr/bin/env python3
"""Research only: extract CMS SDK declarations and Apple requirement enums with Clang."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

REVISION = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
SOURCE = "OSX/libsecurity_codesigning/lib/requirement.h"


def run(args, source=None):
    return subprocess.run(args, input=source, text=True, capture_output=True, check=True).stdout


def walk(node):
    yield node
    for child in node.get("inner", []):
        yield from walk(child)


def enum_values(ast, prefixes):
    values = {}
    for node in walk(ast):
        if node.get("kind") != "EnumDecl":
            continue
        previous = -1
        for child in node.get("inner", []):
            if child.get("kind") != "EnumConstantDecl":
                continue
            explicit = [n["value"] for n in walk(child)
                        if n.get("kind") == "ConstantExpr" and "value" in n]
            previous = int(explicit[0]) if explicit else previous + 1
            if child.get("name", "").startswith(prefixes):
                values[child["name"]] = previous
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk")
    parser.add_argument("--requirement-header", default=".research/apple/requirement.h")
    parser.add_argument("--output", default="spec/apple-cms.json")
    args = parser.parse_args()
    sdk = pathlib.Path(args.sdk or run(["xcrun", "--show-sdk-path"]).strip())
    headers = ["System/Library/Frameworks/Security.framework/Versions/A/Headers/" + h
               for h in ("CMSEncoder.h", "CMSDecoder.h")]
    source = pathlib.Path(args.requirement_header).read_text()
    # Preserve these declarations verbatim. Clang evaluates the C++ enumerators;
    # this does not pretend the omitted private Apple dependencies were compiled.
    excerpts = [re.search(r"enum " + name + r"\s*\{.*?\};", source, re.S).group()
                for name in ("ExprOp", "MatchOperation")]
    fragment = "\n".join(excerpts)
    result = {
        "schema": 1,
        "compiler": run(["clang", "--version"]).splitlines()[0],
        "sdk": sdk.resolve().name,
        "headers": {h: hashlib.sha256((sdk / h).read_bytes()).hexdigest() for h in headers},
        "requirement_source": {
            "url": f"https://github.com/apple-oss-distributions/Security/blob/{REVISION}/{SOURCE}",
            "sha256": hashlib.sha256(source.encode()).hexdigest(),
            "excerpt_sha256": hashlib.sha256(fragment.encode()).hexdigest(),
            "declarations": ["ExprOp", "MatchOperation"],
            "scope": "verbatim standalone enum excerpts; not the full C++ translation unit",
        },
        "targets": {},
    }
    for target in ("arm64-apple-macos27", "x86_64-apple-macos27"):
        base = ["clang", "-target", target, "-isysroot", str(sdk), "-fsyntax-only", "-Xclang", "-ast-dump=json"]
        sdk_source = "#include <Security/CMSEncoder.h>\n#include <Security/CMSDecoder.h>\n"
        ast = json.loads(run(base + ["-fblocks", "-x", "c", "-"], sdk_source))
        functions = {n["name"]: n["type"]["qualType"] for n in walk(ast)
                     if n.get("kind") == "FunctionDecl"
                     and n.get("name", "").startswith(("CMSEncoder", "CMSDecoder"))}
        cpp = json.loads(run(base + ["-x", "c++", "-std=c++17", "-"], fragment))
        result["targets"][target] = {
            "cms_enums": enum_values(ast, ("kCMS",)),
            "cms_functions": functions,
            "requirement_enums": enum_values(cpp, ("op", "expr", "match")),
        }
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {output}: CMS declarations and Apple C++ requirement enums for two targets")


if __name__ == "__main__":
    main()
