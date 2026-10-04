"""Reject accidental inventory pruning and unqualified research claims."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("research_check", Path(__file__).with_name("check-research.py"))
research = importlib.util.module_from_spec(spec)
spec.loader.exec_module(research)


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.plan = research.read("spec/research-roadmap.json")
        self.inventory = research.read("spec/compatibility.json")

    def test_complete_mapping(self):
        research.validate(self.plan, self.inventory)

    def test_missing_duplicate_wrong_status_and_phase(self):
        mutations = []
        missing = copy.deepcopy(self.plan)
        missing["features"].pop()
        mutations.append(missing)
        duplicate = copy.deepcopy(self.plan)
        duplicate["features"].append(duplicate["features"][0])
        mutations.append(duplicate)
        promoted = copy.deepcopy(self.plan)
        promoted["features"][0]["baseline_status"] = "verified"
        mutations.append(promoted)
        wrong = copy.deepcopy(self.plan)
        wrong["features"][0]["phase"] = 99
        mutations.append(wrong)
        for i, plan in enumerate(mutations):
            with self.subTest(mutation=i), self.assertRaises(ValueError):
                research.validate(plan, self.inventory)

    def test_unexecuted_case_cannot_become_observation(self):
        self.plan["phases"]["2"]["native_cases"][0]["qualification"] = "verified"
        with self.assertRaisesRegex(ValueError, "specification presented as observation"):
            research.validate(self.plan, self.inventory)

    def test_blocker_cannot_lose_prerequisite(self):
        row = next(r for r in self.plan["features"] if r["baseline_status"] == "blocked")
        row["prerequisites"] = []
        with self.assertRaisesRegex(ValueError, "Uninvestigated blocked"):
            research.validate(self.plan, self.inventory)

    def test_filesystem_discovery(self):
        capture = research.read("testdata/research/filesystem-prerequisite.json")
        research.validate_filesystem_discovery(capture, self.plan, self.inventory)
        self.assertTrue(all(not c["go_error"] and not c["sdk_prepare_error"] and c["output_bytes_match"]
                            for c in capture["cases"]))

    def test_filesystem_history(self):
        research.validate_filesystem_history(self.plan)
        capture = research.read(self.plan["apfs_audit"]["filesystem_history"]["path"])
        # A dry run can retain identical bytes while failing operationally.
        case = next(c for c in capture["cases"] if c["id"] == "p02.metadata.hfsplus.dryrun")
        self.assertTrue(case["output_bytes_match"])
        self.assertTrue(case["go_error"])

    def test_filesystem_history_rejects_changes(self):
        for key, value in (("sha256", "0" * 64), ("version", "unreleased"), ("sum", "invalid")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                plan = copy.deepcopy(self.plan)
                plan["apfs_audit"]["filesystem_history"][key] = value
                research.validate_filesystem_history(plan)

    def test_filesystem_discovery_rejects_lost_or_stale_evidence(self):
        original = research.read("testdata/research/filesystem-prerequisite.json")
        mutations = [
            lambda c: c["cases"].pop(),
            lambda c: c["cases"].__setitem__(0, c["cases"][1]),
            lambda c: c["cases"][0].__setitem__("id", "wrong"),
            lambda c: c["cases"][0]["native"].__setitem__("exit", 1),
            lambda c: c["source_sha256"].pop("go.mod"),
            lambda c: c["source_sha256"].__setitem__("go.mod", "0" * 64),
            lambda c: c["source_sha256"].__setitem__("/usr/bin/codesign", "0" * 64),
            lambda c: c["cases"][0].__setitem__("input_sha256", "invalid"),
            lambda c: c["cases"][0].__setitem__("output_bytes_match", not c["cases"][0]["output_bytes_match"]),
            lambda c: c["cases"][0].__setitem__("go_error", None),
            lambda c: c["cases"][0].__setitem__("go_error", "operation not supported"),
            lambda c: c["cases"][0].__setitem__("sdk_prepare_error", "operation not supported"),
            lambda c: c["provenance"].__setitem__("go", '{"Version":"unreleased","Sum":"invalid"}'),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                capture = copy.deepcopy(original)
                mutate(capture)
                research.validate_filesystem_discovery(capture, self.plan, self.inventory)


if __name__ == "__main__":
    unittest.main()
