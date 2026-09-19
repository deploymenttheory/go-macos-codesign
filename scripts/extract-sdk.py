#!/usr/bin/env python3
"""Extract facts using Clang, never by treating C structs as wire encodings.

Development tool only. No SDK, Clang or Python is needed to build the Go binary.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess


def run(args, source=None):
    return subprocess.run(args, input=source, text=True, capture_output=True, check=True).stdout


def walk(node):
    yield node
    for child in node.get("inner", []):
        yield from walk(child)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk", default=None)
    p.add_argument("--output", default="spec/apple-sdk.json")
    args = p.parse_args()
    sdk = pathlib.Path(args.sdk or run(["xcrun", "--show-sdk-path"]).strip())
    relative = "System/Library/Frameworks/Kernel.framework/Versions/A/Headers/kern/cs_blobs.h"
    header = sdk / relative
    source = '#include "' + str(header) + '"\n'
    result = {"schema": 1, "compiler": run(["clang", "--version"]).splitlines()[0],
              "sdk": sdk.resolve().name, "header": relative,
              "header_sha256": hashlib.sha256(header.read_bytes()).hexdigest(), "targets": {}}
    for target in ("arm64-apple-macos27", "x86_64-apple-macos27"):
        base = ["clang", "-target", target, "-isysroot", str(sdk), "-x", "c"]
        ast = json.loads(run(base + ["-fsyntax-only", "-Xclang", "-ast-dump=json", "-"], source))
        enums, records = {}, {}
        for node in walk(ast):
            name = node.get("name", "")
            if node.get("kind") == "EnumConstantDecl" and name.startswith(("CS", "kSec")):
                values = [n["value"] for n in walk(node) if n.get("kind") == "ConstantExpr" and "value" in n]
                if values:
                    enums[name] = int(values[0])
            if node.get("kind") == "RecordDecl" and name.startswith(("__Code", "__Blob", "__SC_")):
                records[name] = [{"name": n["name"], "type": n["type"]["qualType"]}
                                 for n in node.get("inner", []) if n.get("kind") == "FieldDecl"]
        macros = run(base + ["-E", "-dM", "-"], source)
        macros = [s for s in macros.splitlines() if re.match(r"#define CS_", s)]
        layout = run(base + ["-fsyntax-only", "-Xclang", "-fdump-record-layouts-complete", "-"], source)
        layout = [s.strip() for s in layout.split("*** Dumping AST Record Layout")
                  if re.search(r"struct __(Code|Blob|SC_)", s)]
        result["targets"][target] = {"enums": enums, "macros": macros, "records": records, "layouts": layout}
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {out}: {len(enums)} explicit enum values, {len(records)} records, two targets")


if __name__ == "__main__":
    main()
