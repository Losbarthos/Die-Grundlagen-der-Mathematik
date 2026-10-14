"""Focused compatibility tests; no manuscript PDF is built or published."""
from __future__ import annotations

import importlib.util
from io import BytesIO
from pathlib import Path
import unittest

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (ArrayObject, DictionaryObject, NameObject,
                           NumberObject, TextStringObject)

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publish_pdfs", ROOT / "scripts/publish-pdfs.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


def action(kind, destination):
    return DictionaryObject({NameObject("/S"): NameObject(kind),
                             NameObject("/D"): destination})


def annotation(**fields):
    result = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([NumberObject(v) for v in (20, 30, 90, 45)]),
    })
    for key, value in fields.items():
        result[NameObject("/" + key)] = value
    return result


def fixture():
    source = PdfWriter()
    # Orphan source objects deliberately shift all page-object numbers.
    # Cloning the reachable catalog drops them, exposing source-ref mistakes.
    for number in range(40):
        source._add_object(DictionaryObject({NameObject("/FixtureUnused"): NumberObject(number)}))
    for _ in range(3):
        source.add_blank_page(width=200, height=300)
    source.add_named_destination("slreading:target", 2)
    source.add_named_destination("slreading:secondary", 1)
    source.add_named_destination("ordinary:keep", 1)
    source.add_annotation(0, annotation(A=action("/GoTo", TextStringObject("slreading:target"))))
    source.add_annotation(0, annotation(A=action("/GoTo", TextStringObject("ordinary:keep"))))
    remote = action("/GoToR", TextStringObject("slreading:remote"))
    remote[NameObject("/F")] = TextStringObject("other.pdf")
    source.add_annotation(0, annotation(A=remote))
    # add_annotation's convenience /Dest input expects its own page-index
    # schema; append this standards-level named /Dest directly for the fixture.
    source.pages[0]["/Annots"].append(source._add_object(
        annotation(Dest=TextStringObject("slreading:secondary"))))
    source.add_annotation(0, annotation(A=action("/GoTo", ArrayObject([
        source.pages[0].indirect_reference, NameObject("/FitH"), NumberObject(240),
    ]))))
    source.add_annotation(0, annotation(A=DictionaryObject({
        NameObject("/S"): NameObject("/URI"),
        NameObject("/URI"): TextStringObject("https://example.test/slreading:keep"),
    })))
    buffer = BytesIO()
    source.write(buffer)
    reader = PdfReader(BytesIO(buffer.getvalue()))
    return reader, PdfWriter(clone_from=reader)


def links(document):
    return [reference.get_object() for reference in document.pages[0]["/Annots"]]


def reread(writer):
    buffer = BytesIO()
    writer.write(buffer)
    return PdfReader(BytesIO(buffer.getvalue()))


class ReadingLinkPublicationTests(unittest.TestCase):
    def test_explicit_fit_uses_cloned_page_and_preserves_other_links(self):
        source, writer = fixture()
        original_names = set(source.named_destinations)
        original_rectangles = [list(link["/Rect"]) for link in links(source)]
        self.assertNotEqual(source.pages[2].indirect_reference.idnum,
                            writer.pages[2].indirect_reference.idnum)
        self.assertEqual(publisher.rewrite_reading_legend_links(writer), 2)
        result = reread(writer)
        self.assertEqual(set(result.named_destinations), original_names)
        self.assertEqual([list(link["/Rect"]) for link in links(result)], original_rectangles)
        first, ordinary, remote, direct, explicit, uri = links(result)
        self.assertEqual(first["/A"]["/S"], "/GoTo")
        self.assertEqual(first["/A"]["/D"][1:], ["/Fit"])
        self.assertEqual(first["/A"]["/D"][0], result.pages[2].indirect_reference)
        self.assertEqual(direct["/Dest"][1:], ["/Fit"])
        self.assertEqual(direct["/Dest"][0], result.pages[1].indirect_reference)
        self.assertEqual(ordinary["/A"]["/D"], "ordinary:keep")
        self.assertEqual(remote["/A"]["/D"], "slreading:remote")
        self.assertEqual(remote["/A"]["/S"], "/GoToR")
        self.assertEqual(remote["/A"]["/F"], "other.pdf")
        self.assertEqual(explicit["/A"]["/D"][1:], ["/FitH", 240])
        self.assertEqual(uri["/A"]["/URI"], "https://example.test/slreading:keep")
        self.assertEqual(publisher.audit_local_targets(result, Path("fixture.pdf")), 4)
        self.assertEqual(publisher.rewrite_reading_legend_links(writer), 0)

    def test_missing_name_fails_before_changing_any_action(self):
        _, writer = fixture()
        writer.add_annotation(0, annotation(A=action("/GoTo", TextStringObject("slreading:missing"))))
        with self.assertRaisesRegex(ValueError, "Missing reading introduction destination"):
            publisher.rewrite_reading_legend_links(writer)
        self.assertEqual(links(writer)[0]["/A"]["/D"], "slreading:target")

    def test_audit_rejects_explicit_reference_to_nonpage_object(self):
        _, writer = fixture()
        publisher.rewrite_reading_legend_links(writer)
        not_a_page = writer._add_object(DictionaryObject({NameObject("/Fixture"): NumberObject(1)}))
        links(writer)[0]["/A"][NameObject("/D")] = ArrayObject([not_a_page, NameObject("/Fit")])
        with self.assertRaisesRegex(ValueError, "not a document page"):
            publisher.audit_local_targets(reread(writer), Path("fixture.pdf"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
