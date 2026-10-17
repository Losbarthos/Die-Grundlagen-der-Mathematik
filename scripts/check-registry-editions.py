"""Regression checks for legacy edition manifests and current registry metadata.

Run python scripts/check-registry-editions.py. No TeX build or registry write.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
COMPARE = runpy.run_path(str(ROOT / "scripts/registry-editions.py"))["registry_records"]


def with_metadata(rows):
    result = []
    for row in rows:
        if row[0] == "ID":
            result.append(list(row[:4]) + ["1.2.3", r"P\vdash Q", r"\DeltaPrem{Given}{P}"])
        else:
            prefix = (list(row) + [""] * 7)[:7]
            result.append(prefix + [r"P\vdash Q", r"\DeltaPrem{Given}{P}"])
    return result


class RegistryEditionsTest(unittest.TestCase):
    def test_all_historical_manifests_accept_metadata_without_mutation(self):
        for name, keys in {
            "differences": ("public_records", "private_records"),
            "integers": ("public_records", "private_records"),
            "reconstruction": ("canonical_registry", "additional_registry"),
            "semilattice": ("canonical_registry",),
            "frankl": ("canonical_registry",),
        }.items():
            module = runpy.run_path(str(ROOT / f"scripts/{name}-editions.py"))
            manifest = json.loads((ROOT / f"scripts/{name}-manifest.json").read_text(encoding="utf-8"))
            for key in keys:
                with self.subTest(edition=name, records=key):
                    historical = manifest.get(key, [])
                    current = with_metadata(historical)
                    before = copy.deepcopy(current)
                    module["records_equal"](current, historical, "fixture", legacy_manifest=True)
                    self.assertEqual(current, before)
                    # Current import audits must still detect lost metadata.
                    if current:
                        with self.assertRaises(ValueError):
                            module["records_equal"](current, historical, "fixture")

    def test_identity_formula_title_number_and_multiplicity_remain_checked(self):
        original = [
            ["1", "thm:fixture", "theorem", "1.2.3", "key", "P implies Q", "Title"],
            ["ID", "Fixture", "theorem", "thm:fixture"],
        ]
        for row_index, field in ((0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6), (1, 1), (1, 2), (1, 3)):
            with self.subTest(row=row_index, field=field):
                changed = with_metadata(original)
                changed[row_index][field] += " changed"
                self.assertNotEqual(COMPARE(changed, legacy_manifest=True), COMPARE(original, legacy_manifest=True))
        self.assertNotEqual(COMPARE(with_metadata(original * 2), legacy_manifest=True), COMPARE(original, legacy_manifest=True))

    def test_empty_titles_and_current_metadata(self):
        historical = [["1", "thm:fixture", "theorem", "1.2.3", "key", "P implies Q"]]
        current = with_metadata(historical)
        self.assertEqual(COMPARE(current, legacy_manifest=True), COMPARE(historical, legacy_manifest=True))
        for field in (7, 8):
            changed = copy.deepcopy(current)
            changed[0][field] += " changed"
            self.assertNotEqual(COMPARE(changed), COMPARE(current))
        self.assertEqual(COMPARE(current), COMPARE(copy.deepcopy(current)))

    def test_subset_manifest_call_sites_keep_full_returned_rows(self):
        historical = [["1", "thm:fixture", "theorem", "1.2.3", "key", "P implies Q"],
                      ["ID", "Fixture", "theorem", "thm:fixture"]]
        for name in ("nullproducts", "compactness"):
            module = runpy.run_path(str(ROOT / f"scripts/{name}-editions.py"))
            function = module["main_records"]
            current = with_metadata(historical)
            if name == "nullproducts":
                current += [["ID", module["MAIN_ID"], "theorem", "thm:added", "1.2.4", "Q", ""]]
            data = {"canonical_registry": historical, "canonical_aux": {}, "public_ids": ["Fixture"]}
            with self.subTest(edition=name), patch.dict(function.__globals__, {
                "manifest": lambda: data, "registry": lambda path: current, "aux_labels": lambda path: {},
            }):
                returned = function()
                self.assertIs(returned[0], current)
                self.assertEqual(returned[0][0][7:], current[0][7:])
                current[0][3] = "changed number"
                with self.assertRaises(ValueError):
                    function()


if __name__ == "__main__":
    unittest.main()
