"""Failure-injection tests for the required evidence gate (no native tools)."""
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import evidence as e
import verify


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.prov = {"os": "Linux", "commit": "commit", "instrumentation": "atomic", "run": "run"}
        self.plan = {"assignment": {}, "platforms": {"Linux": {"unit": {}, "acceptance": {}}}}
        for part in e.PARTS:
            directory = self.inputs / part
            directory.mkdir()
            (directory / "attestations").mkdir()
            (directory / "export").mkdir()
            (directory / "coverage.out").write_text("mode: atomic\np/a.go:1.1,2.2 1 1\n")
            name = "TestPart" + part
            events = [
                {"Action": "run", "Package": "p", "Test": name},
                {"Action": "run", "Package": "p", "Test": name + "/case"},
                {"Action": "pass", "Package": "p", "Test": name + "/case"},
                {"Action": "pass", "Package": "p", "Test": name},
                {"Action": "pass", "Package": "p"},
            ]
            (directory / "tests.jsonl").write_text("".join(json.dumps(v) + "\n" for v in events))
            groups = e.outcomes(directory / "tests.jsonl")
            self.plan["platforms"]["Linux"]["unit" if part == "unit" else "acceptance"].update(groups)
            if part != "unit":
                self.plan["assignment"][name] = int(part)
            e.write_json(directory / "receipt.json", {"schema": 1, "part": part, "provenance": self.prov,
                         "outcomes": groups, "files": e.files(directory), "elapsed_seconds": 1})
        host = self.plan["platforms"]["Linux"]
        host["exports"] = host["attestations"] = {"count": 0, "sha256": e.names_digest([])}

    def inspect(self):
        return e.inspect_shards(self.inputs, self.plan, self.prov)

    def test_complete_manifest(self):
        self.assertEqual(set(self.inspect()), set(e.PARTS))

    def test_archive_round_trip_preserves_every_byte_and_receipt(self):
        packages = self.root / "packages"
        for part in e.PARTS:
            e.pack(self.inputs / part, packages / part / "evidence.tar")
        output = self.root / "unpacked"
        e.unpack(packages, output)
        self.assertEqual(e.files(output), e.files(self.inputs))
        self.assertEqual(set(e.inspect_shards(output, self.plan, self.prov)), set(e.PARTS))
        with self.assertRaisesRegex(ValueError, "stale extraction"):
            e.unpack(packages, output)
        with self.assertRaisesRegex(ValueError, "stale archive"):
            e.pack(self.inputs / "0", packages / "0/evidence.tar")

    def test_archive_rejects_unsafe_duplicate_and_missing_entries(self):
        packages = self.root / "packages"
        (packages / "0").mkdir(parents=True)
        archive_path = packages / "0/evidence.tar"
        cases = [("../outside", tarfile.REGTYPE), ("/outside", tarfile.REGTYPE),
                 ("a/../outside", tarfile.REGTYPE), ("a\\outside", tarfile.REGTYPE),
                 ("a", tarfile.SYMTYPE), ("a", tarfile.LNKTYPE), ("a", tarfile.FIFOTYPE),
                 ("a", tarfile.DIRTYPE), ("duplicate", tarfile.REGTYPE)]
        for i, (name, kind) in enumerate(cases):
            with self.subTest(name=name, kind=kind):
                with tarfile.open(archive_path, "w") as archive:
                    member = tarfile.TarInfo(name); member.type = kind
                    archive.addfile(member, io.BytesIO())
                    if name == "duplicate":
                        archive.addfile(member, io.BytesIO())
                with self.assertRaises(ValueError):
                    e.unpack(packages, self.root / ("rejected-" + str(i)))
        archive_path.unlink()
        with self.assertRaisesRegex(ValueError, "Missing/extra"):
            e.unpack(packages, self.root / "missing")

    def test_archive_preserves_native_colons_without_renaming(self):
        packages = self.root / "packages"
        (packages / "0").mkdir(parents=True)
        name = "attestations/TestTimestamp_http:__127.0.0.1:1.json"
        payload = b'{"native":true}\n'
        with tarfile.open(packages / "0/evidence.tar", "w") as archive:
            member = tarfile.TarInfo(name); member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        output = self.root / "native"
        if e.os.name == "nt":
            # This OS consumes Windows evidence; never create an NTFS alternate stream.
            with self.assertRaisesRegex(ValueError, "Unrepresentable Windows"):
                e.unpack(packages, output)
        else:
            e.unpack(packages, output)
            self.assertEqual((output / "0" / name).read_bytes(), payload)

    def test_every_missing_shard_fails(self):
        for part in e.PARTS:
            with self.subTest(part=part):
                src, dst = self.inputs / part, self.root / part
                src.rename(dst)
                with self.assertRaisesRegex(ValueError, "Missing shards"):
                    self.inspect()
                dst.rename(src)

    def test_duplicate_shard_fails(self):
        shutil.copytree(self.inputs / "0", self.inputs / "duplicate")
        with self.assertRaisesRegex(ValueError, "Duplicate shard"):
            self.inspect()

    def test_cancelled_or_incomplete_shard_fails(self):
        (self.inputs / "1/receipt.json").unlink()
        with self.assertRaises(FileNotFoundError):
            self.inspect()

    def test_stale_or_cross_os_receipts_fail(self):
        p = self.inputs / "0/receipt.json"
        original = e.load(p)
        for field in self.prov:
            with self.subTest(field=field):
                mutated = copy.deepcopy(original)
                mutated["provenance"][field] = "different"
                e.write_json(p, mutated)
                with self.assertRaisesRegex(ValueError, "Stale/mixed"):
                    self.inspect()
        e.write_json(p, original)

    def test_missing_extra_or_changed_artifacts_fail(self):
        p = self.inputs / "1/coverage.out"
        original = p.read_bytes()
        p.unlink()
        with self.assertRaisesRegex(ValueError, "Missing/changed artifact"):
            self.inspect()
        p.write_bytes(original + b"p/b.go:1.1,2.2 1 1\n")
        with self.assertRaisesRegex(ValueError, "Missing/changed artifact"):
            self.inspect()
        p.write_bytes(original)
        (self.inputs / "1/extra").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "Missing/changed artifact"):
            self.inspect()

    def test_forged_summary_fails(self):
        p = self.inputs / "1/receipt.json"
        value = e.load(p)
        value["outcomes"] = {}
        e.write_json(p, value)
        with self.assertRaisesRegex(ValueError, "Forged outcome"):
            self.inspect()

    def test_case_removal_rename_new_skip_and_duplicate_fail(self):
        path = self.inputs / "2/tests.jsonl"
        original = [json.loads(l) for l in path.read_text().splitlines()]
        expected = e.outcomes(path)
        mutations = [original[:2] + original[3:],
                     [{**v, "Test": "TestRenamed"} if v.get("Test") else v for v in original],
                     [{**v, "Action": "skip"} if v.get("Test") and v["Action"] == "pass" else v for v in original],
                     original + [original[2]], original[:-1],
                     [{**v, "Action": "fail"} if v.get("Test") and v["Action"] == "pass" else v for v in original]]
        for i, events in enumerate(mutations):
            with self.subTest(mutation=i):
                path.write_text("".join(json.dumps(v) + "\n" for v in events))
                with self.assertRaises(ValueError):
                    e.check_groups(e.outcomes(path), expected)

    def test_export_collision_fails_even_for_identical_bytes(self):
        one, two = self.root / "one", self.root / "two"
        one.mkdir(); two.mkdir()
        (one / "case.json").write_text("{}")
        (two / "case.json").write_text("{}")
        seen = set()
        e.copy_unique(one, self.root / "copied", seen)
        with self.assertRaisesRegex(ValueError, "Duplicate exported"):
            e.copy_unique(two, self.root / "copied", seen)

    def test_fuzz_seed_cases_and_nested_test_names(self):
        p = self.root / "fuzz.jsonl"
        events = [{"Action": "pass", "Package": "p", "Test": n}
                  for n in ["FuzzX/seed#0", "FuzzX", "TestRoot/TestChild", "TestRoot"]]
        events.append({"Action": "pass", "Package": "p"})
        p.write_text("".join(json.dumps(v) + "\n" for v in events))
        self.assertEqual({k: v["cases"] for k, v in e.outcomes(p).items()}, {"p/FuzzX": 2, "p/TestRoot": 2})

    def aggregate(self, covered=96):
        out = self.root / "complete"
        merged = {"p": (covered, 100)}
        with patch.object(e, "PLAN", self.root / "plan.json"), patch.object(e, "provenance", return_value=self.prov), \
             patch.object(e.subprocess, "check_output", return_value="p\n"), \
             patch.object(verify, "merge", return_value=merged), patch.object(verify, "run"):
            e.write_json(self.root / "plan.json", self.plan)
            e.aggregate(self.inputs, out)
        return out

    def test_aggregation_and_strict_coverage_boundary(self):
        for covered in (0, 94, 95):
            with self.subTest(covered=covered), self.assertRaisesRegex(ValueError, "Coverage must exceed"):
                self.aggregate(covered)
            shutil.rmtree(self.root / "complete")
        out = self.aggregate()
        self.assertEqual(e.load(out / "complete.json")["parts"], e.PARTS)
        with self.assertRaisesRegex(ValueError, "stale aggregation"):
            self.aggregate()

    def test_missing_export_contract_fails(self):
        self.plan["platforms"]["Linux"]["exports"]["count"] = 1
        with self.assertRaisesRegex(ValueError, "Export case manifest"):
            self.aggregate()

    def test_coverage_union_and_incompatible_blocks(self):
        a, b, out = (self.root / n for n in ("a.out", "b.out", "merged.out"))
        a.write_text("mode: atomic\np/a.go:1.1,2.2 2 0\np/a.go:3.1,4.2 1 1\n")
        b.write_text("mode: atomic\np/a.go:1.1,2.2 2 1\np/a.go:3.1,4.2 1 0\n")
        self.assertEqual(verify.merge([a, b], out), {"p": (3, 3)})
        b.write_text("mode: atomic\np/a.go:1.1,2.2 3 1\n")
        with self.assertRaisesRegex(RuntimeError, "Incompatible instrumentation"):
            verify.merge([a, b], out)

    def test_foreign_producers_missing_duplicate_stale_and_tampered(self):
        imports = self.root / "imports"
        imports.mkdir()
        prov = {"run": "r", "attempt": "1", "commit": "c", "plan_sha256": "p", "instrumentation": "atomic"}
        plan = {"platforms": {}}
        for name, host in [("signed-ubuntu-24.04", "Linux"), ("signed-windows-2025", "Windows")]:
            directory = imports / name
            export = directory / "export"
            export.mkdir(parents=True)
            (export / "signed-fixture").write_bytes(b"independent output")
            e.write_json(directory / "producer.json", {"schema": 1, "provenance": dict(prov, os=host), "files": e.files(export)})
            plan["platforms"][host] = {"exports": {"count": 1, "sha256": e.names_digest(["signed-fixture"])}}
        plan_path = self.root / "foreign-plan.json"
        e.write_json(plan_path, plan)
        with patch.object(e, "PLAN", plan_path), patch.object(e, "provenance", return_value=prov):
            e.foreign(imports)
            windows = imports / "signed-windows-2025"
            windows.rename(self.root / "windows")
            with self.assertRaisesRegex(ValueError, "exactly"):
                e.foreign(imports)
            (self.root / "windows").rename(windows)
            receipt = windows / "producer.json"
            original = e.load(receipt)
            for field in [*prov, "os"]:
                with self.subTest(field=field):
                    changed = copy.deepcopy(original)
                    changed["provenance"][field] = "wrong"
                    e.write_json(receipt, changed)
                    with self.assertRaises(ValueError):
                        e.foreign(imports)
            e.write_json(receipt, original)
            (windows / "export/signed-fixture").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "changed foreign artifact"):
                e.foreign(imports)

    def test_shard_invocations_preserve_all_tests_and_deadline(self):
        plan_path = self.root / "plan.json"
        e.write_json(plan_path, self.plan)
        for part in e.PARTS:
            with self.subTest(part=part):
                output = self.root / ("worker-" + part)
                expected = self.inputs / part
                commands = []
                def run(args, env, log=None):
                    commands.append(args)
                    self.assertEqual(env["CGO_ENABLED"], "0")
                    if log is not None:
                        shutil.copyfile(expected / "tests.jsonl", log)
                    if "-covermode=atomic" in args or "covdata" in args:
                        shutil.copyfile(expected / "coverage.out", output / "coverage.out")
                names = "\n".join("TestPart" + p for p in e.PARTS if p != "unit")
                with patch.object(e, "PLAN", plan_path), patch.object(e, "provenance", return_value=self.prov), \
                     patch.object(e.platform, "system", return_value="Linux"), \
                     patch.object(e.subprocess, "check_output", return_value=names), patch.object(verify, "run", side_effect=run):
                    e.shard(part, output)
                    self.assertTrue((output / "receipt.json").exists())
                    if part == "unit":
                        self.assertEqual(commands[0][-2:], ["./pkg/...", "./internal/..."])
                    else:
                        self.assertIn("-timeout=30m", commands[0])
                        self.assertEqual(commands[0][-1], "^(TestPart" + part + ")$")
                    with self.assertRaisesRegex(ValueError, "stale shard"):
                        e.shard(part, output)

    def test_shard_refuses_missing_compiled_tests(self):
        plan_path = self.root / "plan.json"
        e.write_json(plan_path, self.plan)
        with patch.object(e, "PLAN", plan_path), patch.object(e, "provenance", return_value=self.prov), \
             patch.object(e.platform, "system", return_value="Linux"), \
             patch.object(e.subprocess, "check_output", return_value="TestUnplanned\n"):
            with self.assertRaisesRegex(ValueError, "Compiled acceptance inventory"):
                e.shard("0", self.root / "bad-worker")
            self.assertFalse((self.root / "bad-worker/receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
