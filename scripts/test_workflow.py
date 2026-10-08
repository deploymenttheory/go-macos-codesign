"""Keep CI scheduling changes from dropping required native work."""
import copy
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent


def job(workflow, name):
    return re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [\w-]+:|\Z)",
                     workflow, re.M | re.S).group(1)


def capture_commands(workflow):
    block = job(workflow, "native-capture")
    groups = re.search(r"^        group: \[(.+)\]$", block, re.M).group(1).split(", ")
    probes = {}
    for step in re.split(r"(?=^      - name: )", block, flags=re.M)[1:]:
        name = step.splitlines()[0].split(": ", 1)[1]
        if name in ("Enforce pure Go and fixture provenance", "Collect native failure diagnostics",
                    "Upload fresh native capture evidence"):
            continue
        if name in probes:
            raise ValueError("Duplicate native probe")
        condition = re.search(r"^        if: matrix.group == '([\w-]+)'$", step, re.M)
        command = re.search(r"^        run: (.+)$", step, re.M)
        if not condition or not command or "continue-on-error:" in step:
            raise ValueError("Missing or optional native probe")
        probes[name] = {"group": condition.group(1), "command": command.group(1)}
    return {"schema": 1, "groups": groups, "probes": probes}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/test.yml").read_text()
        self.plan = json.loads((ROOT / "spec/ci-native-capture-plan.json").read_text())

    def test_every_original_native_command_runs_in_one_required_group(self):
        self.assertEqual(capture_commands(self.workflow), self.plan)
        self.assertEqual(len(self.plan["probes"]), 36)
        self.assertEqual(set(self.plan["groups"]), {p["group"] for p in self.plan["probes"].values()})
        block = job(self.workflow, "native-capture")
        self.assertIn("fail-fast: false", block)
        self.assertIn("timeout-minutes: 35", block)
        self.assertIn("name: native-capture-${{ matrix.group }}", block)
        for name in ("verify-foreign-signatures", "verify-foreign-bundles", "verify-foreign-plists"):
            self.assertIn("needs: [test, macos-test, native-capture]", job(self.workflow, name))

    def test_plist_readback_keeps_every_native_case_and_both_producers(self):
        block = job(self.workflow, "verify-foreign-plists")
        self.assertIn("runs-on: xcode-27", block)
        self.assertIn("timeout-minutes: 10", block)
        self.assertIn("scripts/evidence.py foreign --inputs artifacts/import", block)
        self.assertIn("-run '^TestVerifyImportedRemovalPlists$'", block)
        self.assertIn("MACOSCODESIGN_REQUIRE_APPLE: '1'", block)
        self.assertNotIn("continue-on-error:", block)
        source = (ROOT / "acceptance/removal_test.go").read_text()
        corpus = source.split("func TestVerifyImportedRemovalPlists(t *testing.T) {", 1)[1]
        cases = re.findall(r'removalPlistCases\(t, "([^"]+)", (\d+)\), "([^"]+)"', corpus)
        self.assertEqual(cases, [
            ("plist-interpretation.json", "180", "plist-interpretation-"),
            ("plist-encodings.json", "120", "plist-encodings-"),
            ("plist-xml-characters.json", "192", "plist-xml-characters-"),
            ("plist-utf32-grammar.json", "36", "plist-xml-grammar-"),
            ("plist-iso2022-extensions.json", "2100", "plist-iso2022-extensions-"),
            ("plist-iso2022-jp.json", "1836", "plist-iso2022-jp-"),
            ("plist-euc-jp.json", "1488", "plist-euc-jp-"),
            ("plist-shift-jis.json", "912", "plist-shift-jis-"),
            ("plist-legacy.json", "792", "plist-legacy-"),
            ("plist-unmarked.json", "408", "plist-unmarked-"),
            ("plist-utf32.json", "276", "plist-utf32-"),
        ])

    def test_missing_duplicate_and_weakened_native_probes_are_rejected(self):
        for mutation in ("missing", "duplicate", "optional", "group", "command"):
            with self.subTest(mutation=mutation):
                step = ("      - name: Check exhaustive native EUC-JP streams\n"
                        "        if: matrix.group == 'legacy'\n"
                        "        run: go run scripts/probe-plist-euc-jp.go -check -out artifacts/plist-euc-jp-values.json\n")
                replacement = {"missing": "", "duplicate": step + step,
                               "optional": step + "        continue-on-error: true\n",
                               "group": step.replace("'legacy'", "'absent'"),
                               "command": step.replace(" -check", "")}[mutation]
                changed = self.workflow.replace(step, replacement)
                self.assertNotEqual(changed, self.workflow)
                try:
                    result = capture_commands(changed)
                except ValueError:
                    continue
                self.assertNotEqual(result, self.plan)

    def test_macos_receipts_and_aggregation_share_one_host(self):
        block = job(self.workflow, "macos-test")
        self.assertIn("name: test (xcode-27)", block)
        self.assertIn("runs-on: xcode-27", block)
        self.assertIn("MACOSCODESIGN_REQUIRE_APPLE: '1'", block)
        parts = re.findall(r"timeout-minutes: 35\n        run: python3 scripts/evidence.py shard (\w+) --output artifacts/shards/(\w+)", block)
        self.assertEqual(parts, [(p, p) for p in ("unit", "0", "1", "2", "3")])
        self.assertIn("scripts/evidence.py aggregate --inputs artifacts/shards --output artifacts/complete", block)
        self.assertNotIn("actions/download-artifact", block)
        for name in ("test-shards", "test"):
            self.assertIn("os: [ubuntu-24.04, windows-2025]", job(self.workflow, name))
