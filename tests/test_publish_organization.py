"""Isolated publication-layout tests; never modify the real output PDFs."""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import importlib.util
from io import StringIO
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (ArrayObject, DecodedStreamObject, DictionaryObject,
                           NameObject, NumberObject, TextStringObject)

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("organization_publisher", PROJECT / "scripts/publish-pdfs.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


def link(kind, destination, filename=None):
    action = DictionaryObject({NameObject("/S"): NameObject(kind),
                               NameObject("/D"): TextStringObject(destination)})
    if filename is not None:
        action[NameObject("/F")] = TextStringObject(filename)
    return DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([NumberObject(n) for n in (10, 20, 100, 35)]),
        NameObject("/A"): action,
    })


def contents(path):
    reader = PdfReader(path)
    return {
        "pages": [
            (page.get_contents().get_data(), list(page.mediabox),
             list(page.cropbox), page.get("/Rotate", 0),
             dict(page["/Resources"]["/Font"]["/F1"]))
            for page in reader.pages
        ],
        "metadata": dict(reader.metadata),
        "destinations": {
            name: (reader.get_destination_page_number(destination),
                   {str(key): str(value) for key, value in destination.items()
                    if str(key) not in {"/Page", "/Title"}})
            for name, destination in reader.named_destinations.items()
        },
        "annotation_rectangles": [
            list(annotation.get_object()["/Rect"])
            for page in reader.pages for annotation in page.get("/Annots", [])
        ],
    }


def digests(paths):
    return {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


class PublicationOrganizationTests(unittest.TestCase):
    def setUp(self):
        temporary_root = PROJECT / "tmp"
        temporary_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="publication-layout-test-", dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "output"
        self.output.mkdir()
        (self.root / "band-dependencies.tsv").write_text(
            "band\tsource\tartifact_base\n"
            "B28\tBd. 28 - Halbgruppen.tex\tregistry/_B28\n"
            "B37\tBd. 37 - Endliche Halbgruppen.tex\tregistry/_B37\n",
            encoding="utf-8")
        self.patch_root = patch.object(publisher, "ROOT", self.root)
        self.patch_output = patch.object(publisher, "OUTPUT", self.output)
        self.patch_root.start()
        self.patch_output.start()
        self.addCleanup(self.patch_root.stop)
        self.addCleanup(self.patch_output.stop)
        publisher.publication_band_folders.cache_clear()
        self.addCleanup(publisher.publication_band_folders.cache_clear)
        # audit's default argument was bound when the module was imported.
        # Keep every production audit inside this isolated fixture tree.
        original_audit = publisher.audit
        self.patch_audit = patch.object(
            publisher, "audit", side_effect=lambda paths, root=None:
            original_audit(paths, root=self.output if root is None else root))
        self.patch_audit.start()
        self.addCleanup(self.patch_audit.stop)
        self.names = {
            "b28": "Bd. 28 - Halbgruppen.pdf",
            "b37": "Bd. 37 - Endliche Halbgruppen.pdf",
            "power": publisher.POWER_NAMES["_B28-power-reading.pdf"],
            "null": publisher.NULLPRODUCTS_NAMES["_B37-nullproducts-reading.pdf"],
            "three": publisher.THREE_PRODUCTS_NAMES["_B37-three-products-reading.pdf"],
            "context": publisher.MANUAL_READING_NAMES["context-equivalence-reading.pdf"],
        }
        group = self.output / "07 Halbgruppen und Monoide"
        additions = group / "Ergänzungen"
        self.old = {
            key: group / name if key in {"b28", "b37"} else
            additions / ("experimentell" if key in {"three", "context"} else "") /
            publisher.SUPPLEMENT_TOPICS[name] / name
            for key, name in self.names.items()
        }
        self.expected = {
            "b28": group / self.names["b28"],
            "b37": group / self.names["b37"],
            "power": additions / "Bd. 28 Halbgruppen" / "Halbgruppenbeweis der Potenzhalbgruppe" / self.names["power"],
            "null": additions / "Bd. 37 Endliche Halbgruppen" / "Nullprodukt-Rekonstruktion" / self.names["null"],
            "three": additions / "Bd. 37 Endliche Halbgruppen" / "experimentell" / "Dreiprodukt-Rekonstruktion" / self.names["three"],
            "context": additions / "Bd. 28 Halbgruppen" / "experimentell" / "Kontextäquivalenz" / self.names["context"],
        }
        self.edges = {
            "b28": ("power", "context"), "b37": ("null", "three"),
            "power": ("b28", "three"), "null": ("b37", "power"),
            "three": ("b37", "context"), "context": ("b28", "null"),
        }
        for key, path in self.old.items():
            writer = PdfWriter()
            writer.add_metadata({"/Title": "Fixture " + key, "/Author": "Organization test"})
            for index in range(2):
                page = writer.add_blank_page(width=200 + index * 10, height=300 + index * 10)
                page[NameObject("/Resources")] = DictionaryObject({
                    NameObject("/Font"): DictionaryObject({
                        NameObject("/F1"): DictionaryObject({
                            NameObject("/Type"): NameObject("/Font"),
                            NameObject("/Subtype"): NameObject("/Type1"),
                            NameObject("/BaseFont"): NameObject("/Helvetica"),
                        })})})
                stream = DecodedStreamObject()
                stream.set_data(f"BT /F1 12 Tf 20 250 Td ({key} page {index + 1}) Tj ET\n".encode("ascii"))
                page[NameObject("/Contents")] = writer._add_object(stream)
                if index:
                    page[NameObject("/Rotate")] = NumberObject(90)
            writer.add_named_destination("target", 1)
            writer.add_named_destination("first", 0)
            writer.add_annotation(0, link("/GoTo", "target"))
            for target in self.edges[key]:
                relative = Path(os.path.relpath(self.old[target], path.parent)).as_posix()
                writer.add_annotation(0, link("/GoToR", "target", relative))
            path.parent.mkdir(parents=True, exist_ok=True)
            writer.write(path)
            writer.close()
        self.neighbor = self.old["null"].parent / "keep.txt"
        self.neighbor.write_text("Keep this non-PDF neighbor.\n", encoding="utf-8")
        self.name_map = {"_B28.pdf": self.names["b28"], "_B37.pdf": self.names["b37"],
                         **publisher.SUPPLEMENT_NAMES}

    def organize(self):
        with redirect_stdout(StringIO()):
            publisher.organize_existing(self.name_map)

    def test_band_titles_and_experimental_directory_order(self):
        self.assertEqual(publisher.publication_band_folders(self.root),
                         {28: "Bd. 28 Halbgruppen", 37: "Bd. 37 Endliche Halbgruppen"})
        for key, name in self.names.items():
            self.assertEqual(publisher.publication_path(name), self.expected[key])

    def test_migration_preserves_pages_links_and_neighbors_and_is_idempotent(self):
        before = {key: contents(path) for key, path in self.old.items()}
        self.organize()
        self.assertEqual(set(self.output.rglob("*.pdf")), set(self.expected.values()))
        for key, path in self.expected.items():
            self.assertEqual(contents(path), before[key])
            reader = PdfReader(path)
            actual = [publisher.file_name(action) for action in publisher.remote_actions(reader)]
            expected = [Path(os.path.relpath(self.expected[target], path.parent)).as_posix()
                        for target in self.edges[key]]
            self.assertEqual(actual, expected)
            self.assertEqual(reader.pages[0]["/Annots"][0].get_object()["/A"]["/D"], "target")
        for key in ("power", "null", "three", "context"):
            self.assertFalse(self.old[key].exists())
        for key in ("power", "three", "context"):
            self.assertFalse(self.old[key].parent.exists())
        self.assertTrue(self.output.is_dir())
        self.assertEqual(self.neighbor.read_text(encoding="utf-8"), "Keep this non-PDF neighbor.\n")
        self.assertFalse(list((self.root / "tmp").glob("pdf-organization-*")))
        hashes = digests(self.expected.values())
        timestamps = {path: path.stat().st_mtime_ns for path in self.expected.values()}
        self.organize()
        self.assertEqual(digests(self.expected.values()), hashes)
        self.assertEqual({path: path.stat().st_mtime_ns for path in self.expected.values()}, timestamps)
        self.assertEqual(set(self.output.rglob("*.pdf")), set(self.expected.values()))

    def test_install_failure_restores_original_pdf_set(self):
        hashes = digests(self.old.values())
        real_replace = publisher.os.replace
        calls = 0

        def fail_fourth(source, destination):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise PermissionError("Simulated locked publication")
            return real_replace(source, destination)

        with patch.object(publisher.os, "replace", side_effect=fail_fourth):
            with self.assertRaisesRegex(RuntimeError, "Previous layout restored"):
                self.organize()
        self.assertEqual(calls, 4)
        self.assertEqual(set(self.output.rglob("*.pdf")), set(self.old.values()))
        self.assertEqual(digests(self.old.values()), hashes)
        self.assertTrue(self.neighbor.is_file())
        recovery = list((self.root / "tmp").glob("pdf-organization-*/originals"))
        self.assertEqual(len(recovery), 1)
        self.assertEqual(len(list(recovery[0].rglob("*.pdf"))), len(self.old))

    def test_cleanup_refuses_parent_outside_output(self):
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        with self.assertRaisesRegex(ValueError, "outside output"):
            publisher.remove_empty_publication_folders([unrelated / self.names["power"]])
        self.assertTrue(unrelated.is_dir())
        self.assertTrue(self.output.is_dir())


if __name__ == "__main__":
    unittest.main(verbosity=2)
