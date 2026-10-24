"""Focused ownership, source and integration regressions for the B37 pair."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import re
import runpy
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

audit = load("index_period_audit", ROOT / "scripts/index-period-editions.py")
publisher = load("index_period_publisher", ROOT / "scripts/publish-pdfs.py")
helpers = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))


class IndexPeriodEditionTests(unittest.TestCase):
    def test_all_original_statements_stay_in_main_with_exact_metadata_and_targets(self):
        rows = copy.deepcopy(audit.MANIFEST["canonical_registry"])
        aux = {key: tuple(value) for key, value in audit.MANIFEST["canonical_aux"].items()}
        audit.check_owner(rows, aux, proofs=False)
        self.assertEqual(len(audit.IDENTITIES), 16)
        self.assertEqual(len(audit.PROOF_TARGETS), 17)
        for column in (-1, -2):
            changed = copy.deepcopy(rows)
            changed[0][column] += "changed"
            with self.subTest(column=column), self.assertRaises(ValueError):
                audit.check_owner(changed, aux, proofs=False)
        for column in (0, 1):
            changed_aux = copy.deepcopy(aux)
            label = next(iter(audit.PUBLIC_LABELS))
            value = list(changed_aux[label]); value[column] += "changed"
            changed_aux[label] = tuple(value)
            with self.subTest(aux=column), self.assertRaises(ValueError):
                audit.check_owner(rows, changed_aux, proofs=False)
        with self.assertRaises(ValueError):
            audit.check_owner(rows[:-1], aux, proofs=False)
        with self.assertRaises(ValueError):
            audit.check_owner(rows + rows[:1], aux, proofs=False)

    def test_only_allowlisted_new_37i_statements_can_be_local(self):
        key, label, number = "B37IPFixture", "thm:auto:37I.1.1.1", "37I.1.1.1"
        rows = [["1", label, "theorem", number, "hash", "formula", "Private", "P", "D"],
                ["ID", key, "theorem", label, number, "P", "D"]]
        aux = {label: (number, "section*.1")}
        with patch.object(audit, "PRIVATE_IDS", {key}):
            audit.check_owner(rows, aux, proofs=True)
            for changed in (rows[:-1], rows + rows[:1], rows + audit.MANIFEST["canonical_registry"][:1]):
                with self.subTest(rows=changed), self.assertRaises(ValueError):
                    audit.check_owner(changed, aux, proofs=True)
            with self.assertRaises(ValueError):
                audit.check_owner(rows, aux | {next(iter(audit.PUBLIC_LABELS)): ("37.1.1.1", "section*.2")}, proofs=True)
            with self.assertRaises(ValueError):
                audit.check_owner(rows, {label: ("37.1.1.1", "section*.1")}, proofs=True)

    def test_authored_ids_and_public_statement_repetitions_match_the_contract(self):
        found = []
        for path in (ROOT / "tex/b37/index-period").glob("*.tex"):
            source = helpers["mask_comments"](path.read_text(encoding="utf-8-sig"))
            for match in re.finditer(r"\\Formula(?:Def|Thm)DeltaK\b", source):
                _, pos = audit.group(source, match.end(), "[")
                formula, pos = audit.group(source, pos)
                key, pos = audit.group(source, pos)
                self.assertIsNotNone(formula, str(path))
                self.assertIsNotNone(key, str(path))
                found.append(source[slice(*key)].strip())
        self.assertEqual(set(found), audit.PRIVATE_IDS)
        self.assertEqual(len(found), len(set(found)))
        source = (ROOT / "tex/b37/index-period/proofs.tex").read_text(encoding="utf-8-sig")
        repetitions = re.findall(r"\\IndexPeriodStatement(?:\[[^\]]*\])?\{([^}]+)\}", source)
        self.assertTrue(audit.PROOF_TARGETS <= set(repetitions))
        self.assertEqual(len(repetitions), len(set(repetitions)))
        for key in audit.PROOF_TARGETS:
            self.assertIn("index-period.proof." + key, source)

    def test_build_order_keeps_b37_and_both_companions_ready_before_overview(self):
        builder = (ROOT / "scripts/build-index-period-editions.ps1").read_text(encoding="utf-8-sig")
        stages = ["-Source $graph['B37'].Source", "'index-period-editions.py') prepare\n",
                  "-Source 'editions/b37-index-period-proofs.tex'", "'index-period-editions.py') prepare-reading",
                  "-Source 'editions/b37-index-period-reading.tex'", "'index-period-editions.py') audit"]
        locations = [builder.index(stage) for stage in stages]
        self.assertEqual(locations, sorted(locations))
        self.assertIn("-EditionsOnly -SkipIndexPeriodBuild", builder)
        all_builds = (ROOT / "scripts/build-all.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("$indexPeriodTriggerBand = $nullproductsTriggerBand", all_builds)
        for first, last in [("if ($needsIndexPeriod -and -not $indexPeriodTriggerBand)", "if ($needsNullproducts -and -not $nullproductsTriggerBand)"),
                            ("if ($band -eq $indexPeriodTriggerBand)", "if ($band -eq $nullproductsTriggerBand)")]:
            self.assertLess(all_builds.index(first), all_builds.index(last))
        null_calls = [line for line in all_builds.splitlines() if "'build-nullproducts-editions.ps1')" in line]
        self.assertTrue(null_calls)
        self.assertTrue(all("-SkipIndexPeriodBuild" in line for line in null_calls))

    def test_publisher_keeps_both_regular_editions_in_their_b37_topic(self):
        self.assertEqual(len(publisher.INDEX_PERIOD_NAMES), 2)
        for key, name in publisher.INDEX_PERIOD_NAMES.items():
            self.assertEqual(publisher.SUPPLEMENT_NAMES[key], name)
            self.assertNotIn(name, publisher.EXPERIMENTAL_NAMES)
            path = publisher.publication_path(name)
            self.assertEqual(path.parent.name, "Index und Periode")
            self.assertEqual(path.parent.parent.name, "Bd. 37 Endliche Halbgruppen")


if __name__ == "__main__":
    unittest.main()
