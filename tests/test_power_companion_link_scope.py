"""Exercise the actual power-audit link collector without compiling documents."""
from __future__ import annotations

import ast
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]


class PowerCompanionLinkScopeTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="power-link-scope-test-", dir=ROOT / "tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "registry/power"
        self.directory.mkdir(parents=True)
        self.canonical = self.root / "registry/_B28.pdf"
        self.actions = []
        # Extract the production nested collector itself. Mock its surrounding
        # audit dependencies, preserving its real filtering and validation.
        tree = ast.parse((ROOT / "scripts/power-editions.py").read_text(encoding="utf-8-sig"))
        auditor = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "audit")
        collector = next(node for node in auditor.body if isinstance(node, ast.FunctionDef) and node.name == "links")
        isolated = ast.Module(body=[collector], type_ignores=[])
        ast.fix_missing_locations(isolated)
        self.read_pdf = Mock(return_value=SimpleNamespace(named_destinations={"power.proofs": None}))
        namespace = {
            "ROOT": self.root, "DIRECTORY": self.directory, "cache": {}, "PdfReader": self.read_pdf,
            "publisher": {"remote_actions": lambda reader: iter(self.actions), "file_name": lambda action: action["/F"]},
        }
        exec(compile(isolated, str(ROOT / "scripts/power-editions.py"), "exec"), namespace)
        self.links = namespace["links"]

    def test_canonical_own_link_audit_skips_unbuilt_b31_before_opening(self):
        self.actions = [{"/F": "_B31.pdf", "/D": "coordinates.main"}]
        self.assertEqual(self.links(self.canonical, object(), own_companions_only=True), set())
        self.read_pdf.assert_not_called()

    def test_canonical_own_link_audit_still_rejects_missing_own_proofs(self):
        self.actions = [{"/F": "power/_B28-power-proofs.pdf", "/D": "power.proofs"}]
        with self.assertRaisesRegex(ValueError, "missing/outside PDF target"):
            self.links(self.canonical, object(), own_companions_only=True)

    def test_companion_full_link_audit_still_rejects_missing_other_volume(self):
        self.actions = [{"/F": "../_B31.pdf", "/D": "coordinates.main"}]
        with self.assertRaisesRegex(ValueError, "missing/outside PDF target"):
            self.links(self.directory / "_B28-power-reading.pdf", object())

    def test_existing_own_pdf_destination_is_checked(self):
        target = self.directory / "_B28-power-proofs.pdf"
        target.touch()
        self.actions = [{"/F": "power/_B28-power-proofs.pdf", "/D": "missing.destination"}]
        with self.assertRaisesRegex(ValueError, "missing/unsupported destination"):
            self.links(self.canonical, object(), own_companions_only=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
