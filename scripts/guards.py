#!/usr/bin/env python3
"""Check production dependencies, fixture provenance, and the full-parity gate."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    errors = []
    for directory in ("pkg", "internal", "cmd"):
        for path in (ROOT / directory).rglob("*.go"):
            if path.name.endswith("_test.go"):
                continue
            source = path.read_text()
            if re.search(r'"(?:C|os/exec|crypto/x509|crypto/tls|net/http|github.com/ebitengine/purego)"', source):
                errors.append(f"Forbidden production dependency: {path.relative_to(ROOT)}")
            if "go:linkname" in source or "go:cgo_" in source:
                errors.append(f"Native binding directive: {path.relative_to(ROOT)}")
    env = dict(os.environ, CGO_ENABLED="0")
    for goos in ("linux", "darwin", "windows"):
        output = subprocess.check_output(["go", "list", "-deps", "-f", "{{.ImportPath}}|{{join .CgoFiles \",\"}}", "./cmd/macoscodesign"],
                                         cwd=ROOT, env=dict(env, GOOS=goos, GOARCH="arm64"), text=True)
        for line in output.splitlines():
            name, cgo = line.split("|", 1)
            if cgo or name.startswith("crypto/x509/internal/macos") or name in ("crypto/x509", "crypto/tls", "net/http", "github.com/ebitengine/purego"):
                errors.append(f"Native dependency for {goos}: {line}")
    fixtures = ROOT / "testdata/macho"
    manifest = json.loads((fixtures / "manifest.json").read_text())
    for name, entry in manifest["fixtures"].items():
        path = fixtures / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            errors.append(f"Missing or changed Apple fixture: {name}")
    dependency = ROOT / "third_party/afero"
    certificate_fixtures = ROOT / "testdata/certificate-layout"
    records = sorted(certificate_fixtures.glob("*.json"))
    if len(records) != 12:
        errors.append("Expected twelve native Apple certificate fixtures")
    for record in records:
        entry = json.loads(record.read_text())
        path = record.with_suffix("")
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            errors.append(f"Missing or changed native certificate fixture: {path.name}")
    upstream = json.loads((dependency / "UPSTREAM.json").read_text())
    for name, expected in upstream["files"].items():
        if hashlib.sha256((dependency / name).read_bytes()).hexdigest() != expected:
            errors.append(f"Unrecorded third-party modification: afero/{name}")
    for directory, manifest_name in (("third_party/rc2", "UPSTREAM.json"),
                                     ("testdata/chains", "manifest.json"),
                                     ("testdata/pkcs12", "manifest.json"),
                                     ("testdata/timestamps", "manifest.json"),
                                     ("testdata/bundles", "manifest.json"),
                                     ("testdata/bundle-plists", "manifest.json"),
                                     ("testdata/nested", "manifest.json"),
                                     ("testdata/nested-apps", "manifest.json"),
                                     ("testdata/dmg", "manifest.json"),
                                     ("pkg/codesign/trust", "manifest.json")):
        base = ROOT / directory
        record = json.loads((base / manifest_name).read_text())
        for name, expected in record["files"].items():
            path = base / name
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                errors.append(f"Missing or changed pinned file: {directory}/{name}")
    spec = json.loads((ROOT / "spec/compatibility.json").read_text())
    identifiers = set()
    for feature in spec["features"]:
        if feature["id"] in identifiers:
            errors.append(f"Duplicate compatibility entry: {feature['id']}")
        identifiers.add(feature["id"])
        if feature["status"] not in ("verified", "partial", "not-implemented", "blocked"):
            errors.append(f"Invalid compatibility status: {feature['id']}")
        if feature["status"] == "verified" and not feature["evidence"]:
            errors.append(f"Verified feature has no evidence: {feature['id']}")
        for evidence in feature["evidence"]:
            if not (ROOT / evidence).is_file():
                errors.append(f"Missing evidence: {evidence}")
    pending = [x for x in spec["features"] if x["status"] != "verified"]
    print(f"Full parity: {len(spec['features'])-len(pending)}/{len(spec['features'])} verified inventory entries")
    if args.require_complete and pending:
        errors.append("Full-parity release blocked: " + ", ".join(x["id"] for x in pending))
    if args.require_complete and not spec["full_parity"]:
        errors.append("Full-parity release has not been declared complete")
    for error in errors:
        print(error, file=sys.stderr)
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
