#!/usr/bin/env python3
"""Validate phase ownership, evidence references and immutable source contracts."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(plan, inventory):
    rows = plan["features"]
    require(len(rows) == len({r["id"] for r in rows}), "Duplicate research owner")
    require({r["id"]: r["baseline_status"] for r in rows} == {f["id"]: f["status"] for f in inventory["features"]},
            "Research inventory/status drift")
    require(plan["baseline"] == inventory["baseline"], "Native reference drift")
    families = {}
    for phase, value in plan["phases"].items():
        for case in value["native_cases"]:
            require(case["id"] not in families, "Duplicate case family")
            require(case["qualification"] == "specified-not-captured", "Case specification presented as observation")
            require(case["dimensions"] and case["failures"] and case["oracles"] and case["required_observations"], "Incomplete case contract")
            families[case["id"]] = int(phase)
    prerequisites = {p["id"]: p for p in plan["phase_prerequisites"]}
    require(len(prerequisites) == len(plan["phase_prerequisites"]), "Duplicate prerequisite")
    for row in rows:
        require(str(row["phase"]) in plan["phases"], "Missing phase")
        require(row["case_families"], "Missing case families")
        require(all(families.get(c) == row["phase"] for c in row["case_families"]), "Wrong case owner")
        require(all(p in prerequisites for p in row["prerequisites"]), "Missing prerequisite")
        require(row["baseline_status"] != "blocked" or row["prerequisites"], "Uninvestigated blocked feature")
        for path in row["source_manifests"]:
            require((ROOT / path).is_file(), f"Missing source manifest: {path}")
    for value in prerequisites.values():
        require(value["finding"] and value["resolution"], "Unexplained prerequisite")
        for path in value["evidence"]:
            require((ROOT / path).is_file(), f"Missing prerequisite evidence: {path}")


def validate_filesystem_discovery(capture, plan, inventory):
    require(capture["schema"] == 1, "Unexpected filesystem capture schema")
    expected = {(fs, operation) for fs in ("APFS", "HFS+") for operation in ("sign", "dryrun", "remove")}
    cases = capture["cases"]
    require(len(cases) == len(expected) and {(c["filesystem"], c["operation"]) for c in cases} == expected,
            "Incomplete or duplicate filesystem controls")
    paths = {"scripts/capture-filesystem-prerequisite.go", "testdata/removal/unsigned-arm64.macho",
             "spec/apple-writer.json", "go.mod", "go.sum"}
    require(set(capture["source_sha256"]) == paths | {"/usr/bin/codesign"}, "Missing filesystem provenance")
    for path in paths:
        require(sha(ROOT / path) == capture["source_sha256"][path], f"Stale filesystem capture: {path}")
    require(capture["source_sha256"]["/usr/bin/codesign"] == inventory["baseline"]["codesign_sha256"],
            "Unexpected filesystem oracle binary")
    sdk = json.loads(capture["provenance"]["go"])
    require(sdk["Version"] == plan["apfs_audit"]["version"] and sdk["Sum"] == plan["apfs_audit"]["sum"],
            "Stale filesystem SDK observation")
    for case in cases:
        family = case["filesystem"].lower().replace("+", "plus")
        require(case["id"] == f"p02.metadata.{family}.{case['operation']}", "Wrong filesystem case ID")
        require(case["native"]["exit"] == 0, "Native filesystem control failed")
        for key in ("input_sha256", "native_output_sha256", "go_output_sha256"):
            require(re.fullmatch(r"[0-9a-f]{64}", case[key]) is not None, "Invalid filesystem hash")
        require(case["output_bytes_match"] == (case["native_output_sha256"] == case["go_output_sha256"]),
                "Inconsistent filesystem byte comparison")
        require(isinstance(case["go_error"], str) and isinstance(case["sdk_prepare_error"], str),
                "Missing filesystem operation outcome")
        require(not case["go_error"] and not case["sdk_prepare_error"] and case["output_bytes_match"],
                "Released filesystem prerequisite regressed")


def validate_filesystem_history(plan):
    # Preserve the original failing observations byte-for-byte. Their source
    # hashes describe that old capture, not the current module or working tree.
    history = plan["apfs_audit"]["filesystem_history"]
    require(sha(ROOT / history["path"]) == history["sha256"], "Changed historical filesystem capture")
    capture = read(history["path"])
    sdk = json.loads(capture["provenance"]["go"])
    require(sdk["Version"] == history["version"] and sdk["Sum"] == history["sum"],
            "Changed historical filesystem SDK")
    require(len(capture["cases"]) == 6, "Missing historical filesystem cases")
    for case in capture["cases"]:
        require(case["native"]["exit"] == 0, "Lost historical native control")
        failed = case["filesystem"] == "HFS+"
        require(bool(case["go_error"]) == failed and bool(case["sdk_prepare_error"]) == failed,
                "Lost historical HFS+ failure")


def validate_large_source(large, inventory):
    require(len(large["cases"]) == 9 and {c["content_length"] for c in large["cases"]} ==
            {b + d for b in (1 << 30, 2 << 30, 4 << 30) for d in (-1, 0, 1)}, "Incomplete large-source capture")
    for path, expected in large["source_sha256"].items():
        if path != "/usr/bin/codesign":
            require(sha(ROOT / path) == expected, "Stale large-source capture: " + path)
    require(large["source_sha256"]["/usr/bin/codesign"] == inventory["baseline"]["codesign_sha256"], "Unexpected large-source oracle")
    for case in large["cases"]:
        require(case.get("dry_signature") and case.get("dry_trailer"), "Missing native large-source dry-run tail")
        require(case["display"].splitlines()[0] == "Executable=<image>",
                "Large-source display retains a host path prefix")
        require(case["verify"].splitlines() == ["<image>: valid on disk", "<image>: satisfies its Designated Requirement"],
                "Large-source verification retains a host path or changed diagnostics")


def validate_large_macho(capture, inventory):
    names = {str(b + d) for b in (1 << 30, 2 << 30, 4 << 30) for d in (-1, 0, 1)}
    names |= {"universal-1073741825", "universal-2147483649", "populated-1073741825"}
    require(len(capture["cases"]) == 12 and {c["name"] for c in capture["cases"]} == names,
            "Incomplete Mach-O boundary capture")
    paths = {"scripts/probe-large-macho.go", "spec/apple-writer.json", "spec/apple-removal.json",
             "spec/apple-macho-allocation.json", "testdata/removal/unsigned-arm64.macho",
             "testdata/removal/unsigned-universal.macho", "/usr/bin/codesign"}
    require(set(capture["source_sha256"]) == paths, "Missing Mach-O provenance")
    for path, expected in capture["source_sha256"].items():
        actual = inventory["baseline"]["codesign_sha256"] if path == "/usr/bin/codesign" else sha(ROOT / path)
        require(actual == expected, "Stale Mach-O capture: " + path)
    for case in capture["cases"]:
        require(case["populated"] == case["name"].startswith("populated-"), "Lost populated Mach-O control")
        success = case["length"] < (1 << 32) - 1
        require(case["Sign"]["exit"] == (0 if success else 1), "Changed native signing boundary")
        require(case["Remove"]["exit"] == (0 if case["length"] < 1 << 32 else 1), "Changed native removal boundary")
        operations = ["Sign", "Remove"] + (["Resign", "DryRun", "Verify"] if success else [])
        for operation in operations:
            value = case[operation]
            require(value["size"] > 0 and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]), "Missing complete native hash")
            diagnostic = value["diagnostic"]
            allowed = {"", "<image>: replacing existing signature\n",
                       "<image>: internal error in Code Signing subsystem\n",
                       "<image>: valid on disk\n<image>: satisfies its Designated Requirement\n"}
            require(diagnostic in allowed, "Native Mach-O diagnostic retains host path or changed behavior")
        if success:
            require(case["Verify"]["exit"] == 0 and case["Resign"]["exit"] == 0 and case["DryRun"]["exit"] == 0,
                    "Missing native verification/re-sign/dry-run")
            require(len({case[k]["sha256"] for k in ("Sign", "Resign", "DryRun", "Verify")}) == 1,
                    "Native signing stability changed")


def validate_large_bundles(capture, inventory):
    names = {f"executable-{(1 << 30) + d}" for d in (-1, 0, 1)}
    names |= {f"resource-{(4 << 30) + d}" for d in (-1, 0, 1)}
    names |= {"nested-app", "nested-helper", "aggregate", "framework-universal-2147483649"}
    require(len(capture["cases"]) == 10 and {c["name"] for c in capture["cases"]} == names,
            "Incomplete native bundle boundaries")
    paths = {"scripts/probe-large-bundles.go", "testdata/research/large-macho.json",
             "testdata/removal/unsigned-arm64.macho", "spec/apple-writer.json",
             "spec/apple-hashing.json", "spec/apple-macho-allocation.json", "/usr/bin/codesign"}
    require(set(capture["source_sha256"]) == paths, "Missing bundle provenance")
    for path, expected in capture["source_sha256"].items():
        actual = inventory["baseline"]["codesign_sha256"] if path == "/usr/bin/codesign" else sha(ROOT / path)
        require(actual == expected, "Stale bundle capture: " + path)
    for case in capture["cases"]:
        require(set(case["operations"]) == {"sign", "verify", "resign", "dryrun", "remove"},
                "Incomplete bundle operation sequence")
        members = {m["name"]: m for m in case["members"]}
        require(len(members) == len(case["members"]) and case["executable"] in members, "Invalid bundle recipe")
        require(all(m["size"] > 0 and m["prefix"] for m in members.values()), "Incomplete bundle member")
        if case["name"].startswith("resource-"):
            resource = members["Contents/Resources/payload"]
            require(resource["size"] == int(case["name"].split("-")[1]) and resource["populated"],
                    "Lost populated resource boundary")
        if case["name"].startswith("executable-"):
            require(members[case["executable"]]["size"] == int(case["name"].split("-")[1]),
                    "Lost executable boundary")
        if case["name"] == "aggregate":
            require(sum(m["size"] for m in members.values()) > 4 << 30, "Lost aggregate bundle boundary")
        signed = case["operations"]["sign"]["files"]
        for operation, value in case["operations"].items():
            require(value["exit"] == 0, "Failed native bundle control")
            require(value["diagnostic"] == ("<bundle>: replacing existing signature\n" if operation in ("resign", "dryrun") else ""),
                    "Changed native bundle diagnostic")
            require(value["executable_same"] == (operation in ("verify", "dryrun")) and value["neighbour_same"],
                    "Lost native bundle inode behavior")
            require(set(value["files"]) >= set(members), "Missing native bundle members")
            for member in value["files"].values():
                require(member["size"] > 0 and re.fullmatch(r"[0-9a-f]{64}", member["sha256"]), "Invalid native bundle hash")
            if operation != "remove":
                require(value["files"] == signed, "Changed bundle signing stability")


def main():
    plan, inventory = read("spec/research-roadmap.json"), read("spec/compatibility.json")
    validate(plan, inventory)
    validate_large_bundles(read("testdata/research/large-bundles.json"), inventory)
    bundle_ast = read("spec/apple-bundle-streaming.json")
    require(bundle_ast["driver_sha256"] == sha(ROOT / "scripts/extract-bundle-streaming.go"), "Stale bundle streaming driver")
    require(len(bundle_ast["excerpt_sha256"]) == 3 and len(bundle_ast["sources"]) == 2, "Incomplete resource hashing bodies")
    require(set(bundle_ast["targets"]) == {"arm64-apple-macos27", "x86_64-apple-macos27"}, "Missing bundle Clang target")
    for methods in bundle_ast["targets"].values():
        require(len(methods) == 3 and sorted(m["name"] for m in methods) == ["hashFile", "hashFile", "multipleHashFileData"]
                and all(m["ast_kinds"].get("CompoundStmt") for m in methods), "Incomplete bundle AST")
    validate_filesystem_discovery(read("testdata/research/filesystem-prerequisite.json"), plan, inventory)
    validate_filesystem_history(plan)
    native = read("spec/apple-cli-inventory.json")
    for row in plan["features"]:
        probes = native["options"].get(row["id"], {}).get("applicability_probes", {})
        require(set(probes) == set(row["native_applicability"]), "Missing applicability cell")
        for operation, p in probes.items():
            expected = "unavailable-context" if p.get("unavailable") else "native-signal" if p.get("signal") else "single-probe-accepted" if p["exit"] == 0 else "single-probe-rejected"
            require(row["native_applicability"][operation]["classification"] == expected, "Misclassified native observation")
    ast = read("spec/apple-prerequisites.json")
    require(ast["driver_sha256"] == sha(ROOT / "scripts/extract-prerequisites.go"), "Stale AST driver")
    require(len(ast["excerpt_sha256"]) == 11, "Missing complete Apple bodies")
    require(set(ast["targets"]) == {"arm64-apple-macos27", "x86_64-apple-macos27"}, "Missing Clang target")
    for target in ast["targets"].values():
        require(set(target) == set(ast["excerpt_sha256"]), "Missing AST body")
        require(all(v["ast_kinds"].get("CompoundStmt", 0) for v in target.values()), "Declaration-only body")
    hashing = read("spec/apple-hashing.json")
    require(hashing["driver_sha256"] == sha(ROOT / "scripts/extract-hashing.py"), "Stale hashing AST driver")
    require(len(hashing["excerpt_sha256"]) == 4, "Missing hashing method bodies")
    require(set(hashing["targets"]) == {"arm64-apple-macos27", "x86_64-apple-macos27"}, "Missing hashing Clang target")
    for methods in hashing["targets"].values():
        require(len(methods) == 4 and all(m["nodes"].get("CompoundStmt") for m in methods), "Incomplete hashing AST")
        require(sorted(m["name"] for m in methods) == ["generateHash", "generateHash", "validateSlot", "validateSlot"], "Unexpected hashing methods")
    ranges = read("spec/apple-source-ranges.json")
    require(ranges["driver_sha256"] == sha(ROOT / "scripts/extract-source-ranges.py"), "Stale range AST driver")
    require(ranges["helper_sha256"] == sha(ROOT / "scripts/extract-hashing.py"), "Stale range AST helper")
    require(set(ranges["targets"]) == {"arm64-apple-macos27", "x86_64-apple-macos27"}, "Missing range Clang target")
    require(len(ranges["excerpt_sha256"]) == 3, "Missing range reader bodies")
    for methods in ranges["targets"].values():
        require(len(methods) == 3 and all(m["nodes"].get("CompoundStmt") for m in methods), "Incomplete range reader AST")
    builder = read("spec/apple-dmg-builder.json")
    require(builder["driver_sha256"] == sha(ROOT / "scripts/extract-dmg-builder.py"), "Stale builder AST driver")
    require(builder["helper_sha256"] == sha(ROOT / "scripts/extract-hashing.py"), "Stale builder AST helper")
    require(len(builder["targets"]) == 2 and len(builder["excerpt_sha256"]) == 3, "Missing builder AST targets or bodies")
    for methods in builder["targets"].values():
        require({m["name"] for m in methods} == {"fixedSize", "size", "build"} and all(m["nodes"].get("CompoundStmt") for m in methods), "Incomplete builder AST")
    validate_large_source(read("testdata/research/large-source.json"), inventory)
    allocation = read("spec/apple-macho-allocation.json")
    require(allocation["driver_sha256"] == sha(ROOT / "scripts/extract-macho-allocation.go"), "Stale allocation AST driver")
    require(set(allocation["targets"]) == {"arm64-apple-macos27", "x86_64-apple-macos27"}, "Missing allocation Clang target")
    for methods in allocation["targets"].values():
        require(set(methods) == {"get32", "get64", "assure_signature_space"}, "Missing allocation bodies")
        require(all(m["ast_kinds"].get("CompoundStmt") for m in methods.values()), "Declaration-only allocation body")
    validate_large_macho(read("testdata/research/large-macho.json"), inventory)
    process = read("testdata/research/process-context.json")
    for path, expected in process["source_sha256"].items():
        require(sha(ROOT / path) == expected, f"Stale SDK oracle: {path}")
    require(len({r["id"] for r in process["cases"]}) == len(process["cases"]) == 6, "Missing native process cases")
    require(process["codesign_sha256"] == inventory["baseline"]["codesign_sha256"], "Unexpected native binary")
    module = json.loads(subprocess.check_output(["go", "list", "-m", "-json", plan["apfs_audit"]["module"]], cwd=ROOT, text=True))
    require(module["Version"] == plan["apfs_audit"]["version"] and module["Sum"] == plan["apfs_audit"]["sum"], "Stale released APFS audit")
    for api in plan["apfs_audit"]["apis"]:
        require(sha(Path(module["Dir"]) / api["path"]) == api["sha256"], "Changed APFS API evidence")
    # Pin race/fuzz membership as well as worker success: a smaller matrix cannot
    # become green merely by leaving a package or fuzzer out of the workflow.
    workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    packages = subprocess.check_output(["go", "list", "./pkg/...", "./internal/..."], cwd=ROOT, text=True).splitlines()
    prefix = "github.com/deploymenttheory/go-macos-codesign/"
    wanted = {"./" + p.removeprefix(prefix) for p in packages}
    matrix = re.search(r"package: \[([^\]]+)\]", workflow)
    require(matrix and {p.strip() for p in matrix[1].split(",")} == wanted, "Incomplete race package matrix")
    fuzzers = {m for path in (ROOT / "pkg").rglob("*_test.go") for m in re.findall(r"^func (Fuzz\w+)\(", path.read_text(encoding="utf-8"), re.M)}
    commands = re.findall(r"-fuzz '\^(Fuzz\w+)\$'[^\n]+", workflow)
    require(len(commands) == len(set(commands)) and set(commands) == fuzzers, "Incomplete fuzz matrix")
    require(len(re.findall(r"-fuzz '\^Fuzz\w+\$'[^\n]*-fuzztime=60s", workflow)) == len(fuzzers), "Reduced fuzz duration")
    require("working-directory: third_party/rc2" in workflow, "Missing RC2 tests")
    print(f"Research map: {len(plan['features'])} owners, {sum(len(v['native_cases']) for v in plan['phases'].values())} case families; source/API/harness contracts pass")


if __name__ == "__main__":
    main()
