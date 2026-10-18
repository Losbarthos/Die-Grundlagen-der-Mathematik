"""Canonical target counters may change; protected identities must not."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("power_audit", ROOT / "scripts/power-isomorphisms-editions.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class CanonicalPowerTargetTests(unittest.TestCase):
    def setUp(self):
        self.rows = audit.MANIFEST["canonical_registry"]
        self.identifiers = {key: item["label"] for key, item in audit.IDENTITIES.items()}
        self.aux = {item["label"]: (item["number"], item["destination"])
                    for item in audit.IDENTITIES.values()}
        self.current = "section*.137"
        self.aux[audit.MAIN_LABEL] = (audit.IDENTITIES[audit.MAIN_ID]["number"], self.current)

    def check(self, expected_ids=None):
        audit.check_numbers(self.rows, self.identifiers, self.aux,
                            expected_ids or {audit.MAIN_ID}, "test",
                            canonical_main_target=self.current)

    def test_relocated_canonical_counter_preserves_original_identity(self):
        self.check()

    def test_changed_canonical_number_is_rejected(self):
        self.aux[audit.MAIN_LABEL] = ("28.2.14.99", self.current)
        with self.assertRaisesRegex(ValueError, "identity/number/destination changed"):
            self.check()

    def test_changed_private_destination_is_still_rejected(self):
        key = "PowerHomImagesOfFactors"
        label = audit.IDENTITIES[key]["label"]
        self.aux[label] = (audit.IDENTITIES[key]["number"], "proofpartnr.wrong")
        with self.assertRaisesRegex(ValueError, "identity/number/destination changed"):
            self.check({key})

    def test_semantic_pdf_target_must_identify_same_page(self):
        class Reader:
            named_destinations = {"section*.137": 4, "power-isomorphisms.main.isomorphism": 5}
            def get_destination_page_number(self, destination):
                return destination
        with self.assertRaisesRegex(ValueError, "disagrees with its semantic PDF target"):
            audit.check_main_pdf_target(Reader(), self.current)


if __name__ == "__main__":
    unittest.main(verbosity=2)
