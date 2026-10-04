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


if __name__ == "__main__":
    unittest.main()
