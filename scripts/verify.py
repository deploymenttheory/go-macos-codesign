#!/usr/bin/env python3
"""Run unit and subprocess acceptance tests; merge real statement coverage."""
import json
import hashlib
import os
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = "github.com/deploymenttheory/go-macos-codesign"


def run(args, env, log=None):
    print("+", " ".join(str(a) for a in args), flush=True)
    if log is None:
        subprocess.run(args, cwd=ROOT, env=env, check=True)
    else:
        with log.open("w", encoding="utf-8") as output:
            result = subprocess.run(args, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT, text=True)
        print(f"  transcript: {log.relative_to(ROOT)}", flush=True)
        if result.returncode:
            # Keep every event in the artifact, but show the failed tests and
            # package/compiler output directly in the CI job log.
            events = []
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    print(line)
            failed = {(event.get("Package"), event.get("Test")) for event in events
                      if event.get("Action") == "fail"}
            for event in events:
                if "Output" in event and (not event.get("Test") or
                                          (event.get("Package"), event.get("Test")) in failed):
                    print(event["Output"], end="")
            result.check_returncode()


def merge(paths, output):
    blocks = {}
    for path in paths:
        lines = path.read_text().splitlines()
        if not lines or lines[0] != "mode: atomic":
            raise RuntimeError(f"Invalid coverage profile: {path}")
        for line in lines[1:]:
            location, count, hits = line.rsplit(" ", 2)
            count, hits = int(count), int(hits)
            if location in blocks and blocks[location][0] != count:
                raise RuntimeError(f"Incompatible instrumentation at {location}")
            blocks[location] = (count, max(hits, blocks.get(location, (0, 0))[1]))
    output.write_text("mode: atomic\n" + "".join(f"{key} {n} {hits}\n" for key, (n, hits) in sorted(blocks.items())))
    packages = {}
    for location, (count, hits) in blocks.items():
        filename = location.rsplit(":", 1)[0]
        package = filename.rsplit("/", 1)[0]
        covered, total = packages.get(package, (0, 0))
        packages[package] = (covered + (count if hits else 0), total + count)
    return packages


def main():
    dest = ROOT / "artifacts"
    dest.mkdir(exist_ok=True)
    env = dict(os.environ, CGO_ENABLED="0")
    source_files = sorted(p for base in ("cmd", "internal", "pkg", "acceptance", "scripts", "spec", "testdata", "third_party")
                          for p in (ROOT / base).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    source_files.extend([ROOT / "go.mod", ROOT / "go.sum", ROOT / ".gitattributes"])
    provenance = {"platform": platform.platform(), "machine": platform.machine(),
                  "go": subprocess.check_output(["go", "version"], text=True).strip(),
                  "source_sha256": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}}
    if platform.system() == "Darwin":
        provenance["macos"] = subprocess.check_output(["sw_vers"], text=True).strip()
        provenance["codesign_sha256"] = hashlib.sha256(pathlib.Path("/usr/bin/codesign").read_bytes()).hexdigest()
    (dest / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    # Each invocation gets a fresh directory so old passing runs cannot improve coverage.
    with tempfile.TemporaryDirectory(prefix="coverage-", dir=dest) as tmp:
        tmp = pathlib.Path(tmp)
        cli_dir = tmp / "cli"
        cli_dir.mkdir()
        env["MACOSCODESIGN_COVERAGE_DIR"] = str(cli_dir)
        evidence = tmp / "acceptance"
        env["MACOSCODESIGN_EVIDENCE_DIR"] = str(evidence)
        run(["go", "test", "-count=1", "-json", "-covermode=atomic", "-coverpkg=./...",
             "-coverprofile=" + str(tmp / "unit.out"), "./pkg/...", "./internal/..."], env, dest / "unit.jsonl")
        # The growing native matrix exceeds Go's default ten-minute deadline on
        # the hosted Mac. Keep a bounded suite budget below the 20-minute CI job.
        run(["go", "test", "-timeout=15m", "-count=1", "-json", "./acceptance"], env, dest / "acceptance.jsonl")
        attestations = {p.stem: json.loads(p.read_text()) for p in sorted(evidence.glob("*.json"))}
        (dest / "acceptance.json").write_text(json.dumps(attestations, indent=2) + "\n")
        run(["go", "tool", "covdata", "textfmt", "-i=" + str(cli_dir), "-o=" + str(tmp / "cli.out")], env)
        packages = merge([tmp / "unit.out", tmp / "cli.out"], dest / "coverage.out")
    expected = subprocess.check_output(["go", "list", "./pkg/...", "./internal/...", "./cmd/..."], cwd=ROOT, env=env, text=True).splitlines()
    errors = []
    report = {}
    for name in expected:
        covered, total = packages.get(name, (0, 0))
        percent = 100 * covered / total if total else 0
        report[name] = {"covered": covered, "statements": total, "percent": percent}
        print(f"{name}: {covered}/{total} ({percent:.2f}%)")
        if not total or covered * 100 <= total * 95:
            errors.append(name)
    (dest / "coverage.json").write_text(json.dumps(report, indent=2) + "\n")
    run(["go", "tool", "cover", "-html=" + str(dest / "coverage.out"), "-o=" + str(dest / "coverage.html")], env)
    if errors:
        print("Coverage must exceed 95% in every production package:", ", ".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
