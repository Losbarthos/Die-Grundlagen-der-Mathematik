"""Reference-scope regressions; no manuscript PDF is built or published."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("coordinate_audit", ROOT / "scripts/coordinates-proofs.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class CoordinateReferenceAuditTests(unittest.TestCase):
    def setUp(self):
        temporary_root = ROOT / "tmp"
        temporary_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="coordinate-reference-test-", dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name) / "proofs"
        self.patch = patch.object(audit, "BASE", self.base)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.manifest = [dict(id=f"Proof{index}") for index in range(1, 17)]
        self.identities = {item["id"]: "own:" + item["id"] for item in self.manifest}
        self.records = {
            "first": dict(kind="theorem", number="2.1", display="P", delta=""),
            "second": dict(kind="definition", number="3.1", display="Q", delta="Premise"),
        }
        self.events = []
        for index in range(1, 17):
            self.events.extend([
                f"begin\t{index}", f"use\t{index}\tfirst", f"use\t{index}\tsecond",
                f"use\t{index}\tfirst", f"closed\t{index}",
                f"entry\t{index}\tfirst\ttheorem\t2.1\t1\t0",
                f"entry\t{index}\tsecond\tdefinition\t3.1\t1\t7",
            ])

    def check(self):
        self.base.with_suffix(".proof-references.tsv").write_text("\n".join(self.events) + "\n", encoding="utf-8")
        return audit.audit_events(self.manifest, self.records, self.identities)

    def test_complete_deduplicated_overviews_keep_proof_scopes(self):
        self.assertEqual(self.check(), 32)

    def test_missing_actual_entry_is_rejected(self):
        self.events.remove("entry\t13\tsecond\tdefinition\t3.1\t1\t7")
        with self.assertRaisesRegex(ValueError, "missing, duplicated or reordered"):
            self.check()

    def test_criterion_entry_before_full_proof_close_is_rejected(self):
        begin = self.events.index("closed\t13")
        self.events[begin], self.events[begin + 1] = self.events[begin + 1], self.events[begin]
        with self.assertRaisesRegex(ValueError, "before full proof closure"):
            self.check()

    def test_wrong_original_number_is_rejected(self):
        index = self.events.index("entry\t13\tfirst\ttheorem\t2.1\t1\t0")
        self.events[index] = "entry\t13\tfirst\ttheorem\t9.9\t1\t0"
        with self.assertRaisesRegex(ValueError, "incorrect kind/number"):
            self.check()

    def test_missing_original_context_is_rejected(self):
        index = self.events.index("entry\t13\tsecond\tdefinition\t3.1\t1\t7")
        self.events[index] = "entry\t13\tsecond\tdefinition\t3.1\t1\t0"
        with self.assertRaisesRegex(ValueError, "premises/context were lost"):
            self.check()

    def test_self_statement_header_is_not_a_dependency(self):
        self.identities["Proof13"] = "first"
        with self.assertRaisesRegex(ValueError, "own statement header"):
            self.check()


if __name__ == "__main__":
    unittest.main(verbosity=2)
