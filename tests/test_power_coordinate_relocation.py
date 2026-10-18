"""The B28 power audit permits exactly the reviewed coordinate relocation."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("power_coordinate_audit", ROOT / "scripts/power-editions.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class PowerCoordinateRelocationTests(unittest.TestCase):
    def setUp(self):
        self.data = audit.manifest()
        relocation = json.loads(audit.COORDINATE_RELOCATION_PATH.read_text(encoding="utf-8"))
        self.rows = deepcopy(relocation["relocated_registry"])

    def test_source_phase_needs_no_compiled_target_registry(self):
        with patch.object(audit, "registry", side_effect=AssertionError("compiled registry read")):
            audit.verify_coordinate_relocation_source(self.data)

    def test_tampered_source_premise_is_rejected_before_b31_build(self):
        source = (ROOT / "Bd. 31 - Rechtecksbänder.tex").read_text(encoding="utf-8-sig")
        start = source.index("}{SemigroupCoordinateIsoCriterion}{")
        premise = source.index(r"\DeltaRow", start)
        damaged = source[:premise] + source[premise:].replace("Mengen", "ChangedPremise", 1)
        with self.assertRaisesRegex(ValueError, "formula/ID/title/premise differs"):
            audit.verify_coordinate_relocation_source(self.data, damaged)

    def test_reviewed_relocation_matches_all_historical_formulas(self):
        audit.verify_coordinate_relocation(self.data, self.rows)

    def test_missing_relocated_identity_is_rejected(self):
        self.rows = [row for row in self.rows if not (row[0] == "ID" and row[1] == "SemigroupCoordinateIsoCriterion")]
        with self.assertRaisesRegex(ValueError, "missing relocated coordinate identity"):
            audit.verify_coordinate_relocation(self.data, self.rows)

    def test_changed_premise_is_rejected(self):
        row = next(row for row in self.rows if row[0] != "ID" and len(row) >= 9)
        row[8] += " changed premise"
        with self.assertRaisesRegex(ValueError, "display/premise metadata changed"):
            audit.verify_coordinate_relocation(self.data, self.rows)

    def test_other_coordinate_product_results_remain_in_b28(self):
        ids = audit.id_map(audit.active_canonical_registry(self.data))
        self.assertIn("SemigroupCoordinateProductMapsDef", ids)
        self.assertIn("SemigroupCoordinateProductForwardFacts", ids)
        self.assertIn("SemigroupCoordinateProductInverseFacts", ids)
        self.assertNotIn("SemigroupCoordinateIsoCriterion", ids)
        self.assertEqual(len(audit.migrated_coordinate_identities(self.data)), 25)


if __name__ == "__main__":
    unittest.main(verbosity=2)
