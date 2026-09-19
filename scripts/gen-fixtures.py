#!/usr/bin/env python3
"""Generate our own small Mach-O fixtures and record Apple's observations."""
import hashlib
import json
import pathlib
import shutil
import subprocess


def run(args):
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"{args}: {p.stderr}")
    return {"argv": args, "exit": p.returncode, "stdout": p.stdout, "stderr": p.stderr}


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    out = root / "testdata" / "macho"
    out.mkdir(parents=True, exist_ok=True)
    manifest = {"schema": 1, "macos": run(["sw_vers"])["stdout"],
                "clang": run(["clang", "--version"])["stdout"],
                "codesign_sha256": hashlib.sha256(pathlib.Path("/usr/bin/codesign").read_bytes()).hexdigest(),
                "fixtures": {}}
    for arch in ("arm64", "x86_64"):
        dst = out / ("unsigned-" + arch)
        run(["clang", "-target", arch + "-apple-macos11", "-Wl,-no_adhoc_codesign",
             "-o", str(dst), str(root / "testdata" / "src" / "hello.c")])
    run(["lipo", "-create", str(out / "unsigned-arm64"), str(out / "unsigned-x86_64"),
         "-output", str(out / "unsigned-universal")])
    for arch in ("arm64", "x86_64", "universal"):
        src = out / ("unsigned-" + arch)
        signed = out / ("adhoc-" + arch)
        shutil.copyfile(src, signed)
        run(["/usr/bin/codesign", "-s", "-", "-i", "org.example.fixture", "--timestamp=none", str(signed)])
        for path in (src, signed):
            entry = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}
            if path == signed:
                for op, argv in (("display", ["-d", "--verbose=4"]), ("verify", ["--verify", "--strict", "--verbose=4"])):
                    evidence = run(["/usr/bin/codesign"] + argv + [str(path)])
                    for key in ("stdout", "stderr"):
                        evidence[key] = evidence[key].replace(str(out), "<fixtures>")
                    evidence["argv"][-1] = path.name
                    entry[op] = evidence
            manifest["fixtures"][path.name] = entry
    for arch in ("arm64", "x86_64", "universal"):
        for mode, flags in (("entitlements", ["--entitlements", str(root / "testdata/entitlements.plist")]),
                            ("runtime", ["-o", "runtime"]),
                            ("requirement", ['-r=designated => identifier "org.example.fixture"'])):
            path = out / (mode + "-" + arch)
            shutil.copyfile(out / ("unsigned-" + arch), path)
            run(["/usr/bin/codesign", "-s", "-", "-i", "org.example.fixture", "--timestamp=none"] + flags + [str(path)])
            evidence = run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=4", str(path)])
            evidence["argv"][-1] = path.name
            evidence["stderr"] = evidence["stderr"].replace(str(out), "<fixtures>")
            manifest["fixtures"][path.name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                              "size": path.stat().st_size, "verify": evidence}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Generated {len(manifest['fixtures'])} fixtures from original hello.c")


if __name__ == "__main__":
    main()
