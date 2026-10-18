"""Coordinate relocation publication guards; real manuscripts stay untouched."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pypdf import PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, NumberObject, TextStringObject

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("coordinate_publisher", ROOT / "scripts/publish-pdfs.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class CoordinatePublicationMigrationTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="coordinate-publication-test-", dir=ROOT / "tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "output"
        self.output.mkdir()
        (self.root / "band-dependencies.tsv").write_text(
            "band\tsource\tartifact_base\n"
            "B31\tBd. 31 - Rechtecksbänder.tex\tregistry/_B31\n", encoding="utf-8")
        for name, value in (("ROOT", self.root), ("OUTPUT", self.output)):
            active = patch.object(publisher, name, value)
            active.start()
            self.addCleanup(active.stop)
        publisher.publication_band_folders.cache_clear()
        self.addCleanup(publisher.publication_band_folders.cache_clear)
        self.old_directory = (self.output / "07 Halbgruppen und Monoide" / "Ergänzungen" /
                              "Bd. 28 Halbgruppen" / "e-Koordinatenabbildung")
        self.old_directory.mkdir(parents=True)
        self.old = [self.old_directory / name for name in sorted(publisher.LEGACY_COORDINATE_NAMES)
                    if name.startswith("Bd.")]
        for path in self.old:
            path.write_bytes(b"original")
        self.new = [publisher.publication_path(name) for name in publisher.COORDINATES_NAMES.values()]
        for path in self.new:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"replacement")

    def test_partial_new_pair_preserves_originals(self):
        self.new[1].unlink()
        with self.assertRaisesRegex(FileNotFoundError, "Missing new coordinate publication"):
            publisher.remove_legacy_coordinate_publications()
        self.assertTrue(all(path.read_bytes() == b"original" for path in self.old))

    def test_replaced_pair_cleanup_preserves_new_editions_and_neighbors(self):
        neighbor = self.old_directory / "notes.txt"
        neighbor.write_text("retain", encoding="utf-8")
        publisher.remove_legacy_coordinate_publications()
        self.assertTrue(all(not path.exists() for path in self.old))
        self.assertTrue(all(path.read_bytes() == b"replacement" for path in self.new))
        self.assertEqual(neighbor.read_text(encoding="utf-8"), "retain")

    def test_existing_old_target_cannot_hide_stale_incoming_link(self):
        source = self.output / "incoming.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.add_annotation(0, DictionaryObject({
            NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): ArrayObject([NumberObject(value) for value in (0, 0, 20, 20)]),
            NameObject("/A"): DictionaryObject({NameObject("/S"): NameObject("/GoToR"),
                NameObject("/F"): TextStringObject(self.old[0].relative_to(self.output).as_posix()),
                NameObject("/D"): TextStringObject("coordinates.reading")})}))
        writer.write(source)
        writer.close()
        with self.assertRaisesRegex(ValueError, "obsolete B28 coordinate link"):
            publisher.audit([source], root=self.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
