#!/usr/bin/env python3
"""Partition existing tests and reject incomplete evidence before merging coverage.

This orchestrates test binaries only. Production packaging remains in GoReleaser.
The monolithic scripts/verify.py entry point remains available for local validation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time

import verify

ROOT = verify.ROOT
PLAN = ROOT / "spec/ci-test-plan.json"
PARTS = ["unit", "0", "1", "2", "3"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def names_digest(names):
    return digest(("\n".join(sorted(names)) + "\n").encode())


def outcomes(path):
    """Retain every nested case and status; duplicate terminal events are invalid."""
    found = {}
    packages = {}
    groups = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        action = event.get("Action")
        if action not in ("pass", "skip", "fail"):
            continue
        package, test = event["Package"], event.get("Test")
        if test is None:
            require(package not in packages, f"Duplicate package outcome: {package}")
            packages[package] = action
            continue
        key = package + "/" + test
        require(key not in found, f"Duplicate test outcome: {key}")
        require(action != "fail", f"Failed test: {key}")
        found[key] = action
        top = package + "/" + test.split("/", 1)[0]
        groups.setdefault(top, []).append(key + "=" + action)
    require(packages and all(v == "pass" for v in packages.values()), "Missing/failed package completion")
    require(found, "No test outcomes")
    return {k: {"cases": len(v), "sha256": names_digest(v)} for k, v in sorted(groups.items())}


def files(root):
    """Hash every published file; reject symlinks rather than silently dereference."""
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"Symlink in evidence artifact: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    return result


def provenance():
    # Tracked bytes include workflow/research inputs and preserve OS checkout EOLs.
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    hashes = {name: digest((ROOT / name).read_bytes()) for name in names if name}
    result = {
        "run": os.environ.get("GITHUB_RUN_ID", "local"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_sha256": hashes,
        "go": subprocess.check_output(["go", "version"], text=True).strip(),
        "os": platform.system(), "machine": platform.machine(),
        "plan_sha256": digest(PLAN.read_bytes()),
        "instrumentation": "atomic;coverpkg=./...;CGO_ENABLED=0",
    }
    if platform.system() == "Darwin":
        result["macos"] = subprocess.check_output(["sw_vers"], text=True).strip()
        result["codesign_sha256"] = digest(Path("/usr/bin/codesign").read_bytes())
    return result


def expected_groups(plan, host, part):
    host_plan = plan["platforms"][host]
    if part == "unit":
        return host_plan["unit"]
    return {name: value for name, value in host_plan["acceptance"].items()
            if str(plan["assignment"][name.rsplit("/", 1)[1]]) == part}


def check_groups(actual, expected):
    require(actual == expected,
            "Case manifest mismatch: missing=" + str(sorted(set(expected) - set(actual))) +
            " extra=" + str(sorted(set(actual) - set(expected))) +
            " changed=" + str([k for k in actual.keys() & expected.keys() if actual[k] != expected[k]]))


def shard(part, output):
    require(part in PARTS, "Unknown shard")
    require(not output.exists(), f"Refuse stale shard directory: {output}")
    output.mkdir(parents=True)
    started = time.monotonic()
    plan, prov = load(PLAN), provenance()
    write_json(output / "provenance.json", prov)
    host = platform.system()
    expected = expected_groups(plan, host, part)
    env = dict(os.environ, CGO_ENABLED="0")
    require(not env.get("MACOSCODESIGN_IMPORT_DIR"), "Imports require their separate native verification job")
    if host == "Darwin":
        require(env.get("MACOSCODESIGN_REQUIRE_APPLE") == "1", "Native acceptance must be required")
    export, attestations = output / "export", output / "attestations"
    export.mkdir()
    attestations.mkdir()
    env["MACOSCODESIGN_EXPORT_DIR"] = str(export.resolve())
    env["MACOSCODESIGN_EVIDENCE_DIR"] = str(attestations.resolve())
    log = output / "tests.jsonl"
    if part == "unit":
        verify.run(["go", "test", "-count=1", "-json", "-covermode=atomic", "-coverpkg=./...",
                    "-coverprofile=" + str(output / "coverage.out"), "./pkg/...", "./internal/..."], env, log)
    else:
        listed = subprocess.check_output(["go", "test", "-list", "^Test", "./acceptance"],
                                         cwd=ROOT, env=env, text=True).splitlines()
        names_on_host = {name for name in listed if name.startswith("Test")}
        planned_names = {name.rsplit("/", 1)[1] for name in plan["platforms"][host]["acceptance"]}
        require(names_on_host == planned_names, "Compiled acceptance inventory differs from the shard plan")
        cli = output / "cli-coverage"
        cli.mkdir()
        env["MACOSCODESIGN_COVERAGE_DIR"] = str(cli.resolve())
        names = [name.rsplit("/", 1)[1] for name in expected]
        require(names, "Empty acceptance shard")
        pattern = "^(" + "|".join(re.escape(name) for name in sorted(names)) + ")$"
        verify.run(["go", "test", "-timeout=30m", "-count=1", "-json", "./acceptance", "-run", pattern], env, log)
        verify.run(["go", "tool", "covdata", "textfmt", "-i=" + str(cli),
                    "-o=" + str(output / "coverage.out")], env)
        shutil.rmtree(cli)
    actual = outcomes(log)
    check_groups(actual, expected)
    # Publish a receipt only after all tests, coverage and case checks succeeded.
    write_json(output / "receipt.json", {
        "schema": 1, "part": part, "provenance": prov, "outcomes": actual,
        "files": files(output), "elapsed_seconds": time.monotonic() - started,
    })


def inspect_shards(inputs, plan, prov):
    receipts = {}
    for directory in sorted(inputs.iterdir()):
        require(directory.is_dir(), f"Unexpected input: {directory}")
        receipt = load(directory / "receipt.json")
        part = receipt["part"]
        require(receipt.get("schema") == 1 and part in PARTS, "Invalid receipt")
        require(part not in receipts, f"Duplicate shard: {part}")
        require(receipt["provenance"] == prov, f"Stale/mixed OS, source or instrumentation: {part}")
        actual_files = files(directory)
        del actual_files["receipt.json"]
        require(receipt["files"] == actual_files, f"Missing/changed artifact: {part}")
        actual = outcomes(directory / "tests.jsonl")
        require(actual == receipt["outcomes"], f"Forged outcome summary: {part}")
        check_groups(actual, expected_groups(plan, prov["os"], part))
        receipts[part] = (directory, receipt)
    require(set(receipts) == set(PARTS), f"Missing shards: {set(PARTS) - set(receipts)}")
    return receipts


def copy_unique(source, destination, seen):
    for path in sorted(source.rglob("*")):
        require(not path.is_symlink(), f"Unexpected symlink: {path}")
        if path.is_file():
            relative = path.relative_to(source)
            name = relative.as_posix()
            require(name not in seen, f"Duplicate exported case/artifact: {name}")
            seen.add(name)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)


def aggregate(inputs, output):
    require(not output.exists(), f"Refuse stale aggregation directory: {output}")
    plan, prov = load(PLAN), provenance()
    receipts = inspect_shards(inputs, plan, prov)
    output.mkdir(parents=True)
    merged = verify.merge([receipts[p][0] / "coverage.out" for p in PARTS], output / "coverage.out")
    expected = subprocess.check_output(["go", "list", "./pkg/...", "./internal/...", "./cmd/..."],
                                      cwd=ROOT, env=dict(os.environ, CGO_ENABLED="0"), text=True).splitlines()
    require(set(merged) == set(expected), "Missing/unexpected instrumented production package")
    report = {}
    for package in expected:
        covered, total = merged[package]
        require(total and covered * 100 > total * 95, f"Coverage must exceed 95%: {package} {covered}/{total}")
        report[package] = {"covered": covered, "statements": total, "percent": 100 * covered / total}
    attestations, exported = set(), set()
    for directory, _ in receipts.values():
        copy_unique(directory / "attestations", output / "attestations", attestations)
        copy_unique(directory / "export", output / "export", exported)
    host = plan["platforms"][prov["os"]]
    require({"count": len(exported), "sha256": names_digest(exported)} == host["exports"],
            "Export case manifest mismatch")
    require({"count": len(attestations), "sha256": names_digest(attestations)} == host["attestations"],
            "Acceptance attestation manifest mismatch")
    write_json(output / "coverage.json", report)
    write_json(output / "provenance.json", prov)
    write_json(output / "acceptance.json", {Path(n).stem: load(output / "attestations" / n) for n in sorted(attestations)})
    verify.run(["go", "tool", "cover", "-html=" + str(output / "coverage.out"),
                "-o=" + str(output / "coverage.html")], dict(os.environ, CGO_ENABLED="0"))
    write_json(output / "producer.json", {"schema": 1, "provenance": prov,
                                          "files": files(output / "export")})
    write_json(output / "complete.json", {"schema": 1, "parts": PARTS, "provenance": prov,
               "outcomes": {key: value for _, receipt in receipts.values() for key, value in receipt["outcomes"].items()},
               "files": files(output), "shard_seconds": {p: r[1]["elapsed_seconds"] for p, r in receipts.items()}})


def foreign(inputs):
    plan, prov = load(PLAN), provenance()
    producers = {"signed-ubuntu-24.04": "Linux", "signed-windows-2025": "Windows"}
    require({p.name for p in inputs.iterdir()} == set(producers), "Require exactly the Linux and Windows producers")
    for directory, host in producers.items():
        source = inputs / directory
        receipt = load(source / "producer.json")
        require(receipt.get("schema") == 1, "Invalid producer receipt")
        origin = receipt["provenance"]
        for key in ("run", "attempt", "commit", "plan_sha256", "instrumentation"):
            require(origin[key] == prov[key], f"Stale foreign producer: {directory}/{key}")
        require(origin["os"] == host, f"Wrong foreign producer OS: {directory}")
        exported = files(source / "export")
        require(exported == receipt["files"], f"Missing/changed foreign artifact: {directory}")
        require({"count": len(exported), "sha256": names_digest(exported)} == plan["platforms"][host]["exports"],
                f"Incomplete foreign case manifest: {directory}")
    print("Both foreign producers have complete, current, hash-checked artifacts", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("shard")
    p.add_argument("part", choices=PARTS)
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("aggregate")
    p.add_argument("--inputs", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("foreign")
    p.add_argument("--inputs", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "shard":
        shard(args.part, args.output.resolve())
    elif args.command == "aggregate":
        aggregate(args.inputs.resolve(), args.output.resolve())
    else:
        foreign(args.inputs.resolve())


if __name__ == "__main__":
    main()
