"""Regression checks for the B37 split; all writes use isolated import fixtures."""
from __future__ import annotations

import copy
import importlib.util
import re
import runpy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = load("table_isomorphisms_audit", ROOT / "scripts/table-isomorphisms-editions.py")
publisher = load("table_isomorphisms_publisher", ROOT / "scripts/publish-pdfs.py")
DECLARED_PRIVATE_IDS = frozenset(audit.PRIVATE_IDS)
SOURCE_HELPERS = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))


class TableIsomorphismEditionTests(unittest.TestCase):
    def setUp(self):
        # Historical fixtures contain only the protected extraction; new
        # private declarations are covered separately below.
        self.private_ids = patch.object(audit, "PRIVATE_IDS", set())
        self.private_ids.start()
        self.addCleanup(self.private_ids.stop)

    def owner(self, proofs):
        rows = copy.deepcopy(audit.baseline_rows(proofs=proofs))
        labels = {audit.row_label(row) for row in rows}
        aux = {label: tuple(audit.MANIFEST["canonical_aux"][label]) for label in labels}
        return rows, aux

    def test_private_allowlist_matches_authored_declarations(self):
        found = []
        for path in (ROOT / "tex/b37/table-isomorphisms").glob("*.tex"):
            source = SOURCE_HELPERS["mask_comments"](path.read_text(encoding="utf-8-sig"))
            for match in re.finditer(r"\\Formula(?:Def|Thm)DeltaK\b", source):
                _, position = audit.group(source, match.end(), "[")
                formula, position = audit.group(source, position)
                key, position = audit.group(source, position)
                self.assertIsNotNone(formula, str(path))
                self.assertIsNotNone(key, str(path))
                found.append(source[slice(*key)].strip())
        self.assertEqual(set(found), DECLARED_PRIVATE_IDS)
        self.assertEqual(len(found), len(set(found)), "Duplicate local statement declaration")

    def test_original_declarations_are_partitioned_without_loss(self):
        public, public_aux = self.owner(False)
        proofs, proof_aux = self.owner(True)
        audit.check_owner(public, public_aux, proofs=False)
        audit.check_owner(proofs, proof_aux, proofs=True)
        self.assertFalse(set(audit.id_map(public)) & set(audit.id_map(proofs)))
        self.assertEqual(audit.registry_records(public + proofs),
                         audit.registry_records(audit.MANIFEST["canonical_registry"]))
        self.assertEqual(len(audit.id_map(proofs)), 7)
        self.assertEqual(len(audit.PUBLIC_IDS), 18)

    def test_old_main_cannot_keep_extracted_h_results(self):
        old = copy.deepcopy(audit.MANIFEST["canonical_registry"])
        aux = {key: tuple(value) for key, value in audit.MANIFEST["canonical_aux"].items()}
        with self.assertRaises(ValueError):
            audit.check_owner(old, aux, proofs=False)

    def test_proof_owner_rejects_public_redeclarations_and_missing_h(self):
        public, public_aux = self.owner(False)
        proofs, proof_aux = self.owner(True)
        with self.assertRaises(ValueError):
            audit.check_owner(proofs + public[:1], proof_aux | public_aux, proofs=True)
        with self.assertRaises(ValueError):
            audit.check_owner(proofs[:-1], proof_aux, proofs=True)
        with self.assertRaises(ValueError):
            audit.check_owner(proofs + proofs[:1], proof_aux, proofs=True)

    def test_number_destination_formula_and_display_metadata_remain_protected(self):
        for proofs in (False, True):
            original_rows, original_aux = self.owner(proofs)
            label = next(iter(original_aux))
            for column in (0, 1):
                aux = copy.deepcopy(original_aux)
                value = list(aux[label])
                value[column] += "changed"
                aux[label] = tuple(value)
                with self.subTest(proofs=proofs, field=column), self.assertRaises(ValueError):
                    audit.check_owner(original_rows, aux, proofs=proofs)
            for column in (-1, -2):
                rows = copy.deepcopy(original_rows)
                rows[0][column] += "changed"
                with self.subTest(proofs=proofs, metadata=column), self.assertRaises(ValueError):
                    audit.check_owner(rows, original_aux, proofs=proofs)

    def test_private_additions_need_explicit_ids_and_37t_numbers(self):
        rows, aux = self.owner(True)
        label, number, key = "thm:auto:37T.1.1.1", "37T.1.1.1", "B37TFixture"
        addition = [["1", label, "theorem", number, "key", key, "Private", "P", ""],
                    ["ID", key, "theorem", label, number, "P", ""]]
        extra_aux = aux | {label: (number, "section*.100")}
        with patch.object(audit, "PRIVATE_IDS", {key}):
            audit.check_owner(rows + addition, extra_aux, proofs=True)
            with self.assertRaises(ValueError):
                audit.check_owner(rows, aux, proofs=True)
            with self.assertRaises(ValueError):
                audit.check_owner(rows + addition * 2, extra_aux, proofs=True)
            wrong = copy.deepcopy(addition)
            wrong[0][3] = "37.1.1.1"
            with self.assertRaises(ValueError):
                audit.check_owner(rows + wrong, extra_aux, proofs=True)
            with self.assertRaises(ValueError):
                audit.check_owner(rows + addition, aux | {label: ("37.1.1.1", "section*.100")}, proofs=True)

    def test_private_formula_lookup_and_name_alias_share_one_declaration(self):
        rows, aux = self.owner(True)
        label, number, key = "def:auto:37T.1.1.1", "37T.1.1.1", "B37TFixture"
        formula = ["1", label, "definition", number, "formula-hash", "normalized formula", "Private", "P", "premises"]
        alias = ["1", label, "definition", number, "alias-hash", key, "Private", "P", "premises"]
        identity = ["ID", key, "definition", label, number, "P", "premises"]
        extra_aux = aux | {label: (number, "section*.100")}
        with patch.object(audit, "PRIVATE_IDS", {key}):
            audit.check_owner(rows + [formula, alias, identity], extra_aux, proofs=True)
            audit.check_owner(rows + [formula, identity], extra_aux, proofs=True)
            for column in (2, 3, 6, 7, 8):
                changed = copy.deepcopy(alias)
                changed[column] += "changed"
                with self.subTest(metadata=column), self.assertRaises(ValueError):
                    audit.check_owner(rows + [formula, changed, identity], extra_aux, proofs=True)
            for column in (4, 5):
                changed = copy.deepcopy(alias)
                changed[column] = formula[column]
                with self.subTest(duplicate_lookup=column), self.assertRaises(ValueError):
                    audit.check_owner(rows + [formula, changed, identity], extra_aux, proofs=True)
            for repeated in (formula, alias, identity):
                with self.subTest(repeated=repeated[0:2]), self.assertRaises(ValueError):
                    audit.check_owner(rows + [formula, alias, identity, repeated], extra_aux, proofs=True)
            with self.assertRaises(ValueError):
                audit.check_owner(rows + [identity], extra_aux, proofs=True)

    def test_clean_build_bootstrap_and_import_staleness(self):
        with tempfile.TemporaryDirectory(prefix="table-imports-", dir=ROOT / "tmp") as temporary:
            directory = Path(temporary)
            with patch.object(audit, "DIRECTORY", directory):
                audit.prepare_main()
                expected, expected_aux = self.owner(True)
                audit.check_import("proofs-main", expected, expected_aux)
                self.assertEqual(set(audit.id_map(audit.registry(directory / "proofs-main.registry.tsv"))), audit.PROOF_IDS)
                path = directory / "proofs-main.aux"
                original = path.read_text(encoding="utf-8")
                old = next(iter(expected_aux.values()))[1]
                path.write_text(original.replace(old, "missing-target", 1), encoding="utf-8")
                with self.assertRaises(ValueError):
                    audit.check_import("proofs-main", expected, expected_aux)
                path.write_text(original, encoding="utf-8")
                registry = directory / "proofs-main.registry.tsv"
                registry.write_text("\n".join(registry.read_text(encoding="utf-8").splitlines()[1:]), encoding="utf-8")
                with self.assertRaises(ValueError):
                    audit.check_import("proofs-main", expected, expected_aux)

    def test_reciprocal_navigation_requires_each_target(self):
        required = {
            (Path("proofs.pdf"), "table-isomorphisms.proofs"),
            (Path("reading.pdf"), "table-isomorphisms.reading"),
            (Path("b37.pdf"), "table-isomorphisms.main"),
        }
        audit.require_links(required, required, "fixture")
        for omitted in required:
            with self.subTest(target=omitted), self.assertRaises(ValueError):
                audit.require_links(required - {omitted}, required, "fixture")

    def test_publisher_catalogues_both_as_regular_b37_companions(self):
        self.assertEqual(len(publisher.TABLE_ISOMORPHISMS_NAMES), 2)
        for key, name in publisher.TABLE_ISOMORPHISMS_NAMES.items():
            self.assertEqual(publisher.SUPPLEMENT_NAMES[key], name)
            self.assertNotIn(name, publisher.EXPERIMENTAL_NAMES)
            path = publisher.publication_path(name)
            self.assertEqual(path.parent.name, "Multiplikationstafeln und Isomorphie")
            self.assertEqual(path.parent.parent.name, "Bd. 37 Endliche Halbgruppen")

    def test_build_bootstraps_before_b37_and_builds_pair_before_nullproducts(self):
        source = (ROOT / "scripts/build-all.ps1").read_text(encoding="utf-8-sig")
        self.assertLess(source.index("'table-isomorphisms-editions.py') prepare-main"),
                        source.index("    foreach ($band in $bands)"))
        self.assertIn("$tableIsomorphismsTriggerBand = $nullproductsTriggerBand", source)
        self.assertLess(source.index("if ($needsTableIsomorphisms -and -not $tableIsomorphismsTriggerBand)"),
                        source.index("if ($needsNullproducts -and -not $nullproductsTriggerBand)"))
        self.assertLess(source.index("if ($band -eq $tableIsomorphismsTriggerBand)"),
                        source.index("if ($band -eq $nullproductsTriggerBand)"))
        null_calls = [line for line in source.splitlines() if "'build-nullproducts-editions.ps1')" in line]
        self.assertTrue(null_calls)
        self.assertTrue(all("-SkipTableIsomorphismsBuild" in line for line in null_calls))
        builder = (ROOT / "scripts/build-table-isomorphisms-editions.ps1").read_text(encoding="utf-8-sig")
        self.assertLess(builder.index("'table-isomorphisms-editions.py') prepare-main"),
                        builder.index("-Source $graph['B37'].Source"))
        self.assertLess(builder.index("-Source 'editions/b37-table-isomorphisms-proofs.tex'"),
                        builder.index("'table-isomorphisms-editions.py') prepare-reading"))
        self.assertLess(builder.index("'table-isomorphisms-editions.py') prepare-reading"),
                        builder.index("-Source 'editions/b37-table-isomorphisms-reading.tex'"))


if __name__ == "__main__":
    unittest.main()
