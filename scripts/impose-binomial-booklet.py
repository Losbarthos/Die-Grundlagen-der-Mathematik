"""Impose either B10 landscape booklet as an unscaled, vector A5 print PDF.

Print the output at actual size on landscape A4, duplex short-edge, without
an additional printer booklet setting. Fold the A4 sheets together centrally.
The source remains the normal reading/flat-binding PDF.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from pypdf import PageObject, PdfReader, PdfWriter, Transformation
from pypdf.generic import DictionaryObject, NameObject, RectangleObject

ROOT = Path(__file__).resolve().parent.parent
MM = 72 / 25.4
A4_WIDTH = 297 * MM
A4_HEIGHT = 210 * MM
HALF_WIDTH = A4_WIDTH / 2
GENERATOR = "impose-binomial-booklet.py (pypdf vector imposition; not a TeX build)"
EDITIONS = {
    "reading": {
        "source": "_B10-binomial-reading.pdf",
        "output": "_B10-binomial-booklet.pdf",
        "plan": "booklet-page-plan.json",
        "title": "Band 10 - Binomialkoeffizienten und das Pascalsche Dreieck - Druckbroschüre",
    },
    "exercises": {
        "source": "_B10-binomial-exercises.pdf",
        "output": "_B10-binomial-exercises-booklet.pdf",
        "plan": "exercises-booklet-page-plan.json",
        "title": "Band 10 - Binomialkoeffizienten - Übungsheft - Druckbroschüre",
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_plan(source_count: int) -> dict:
    if source_count < 1:
        raise ValueError("The reading must contain a cover page.")
    logical = [{"source_page": 1, "half": "left", "role": "front-cover"}]
    for source_page in range(2, source_count + 1):
        logical.extend([
            {"source_page": source_page, "half": "left", "role": "text"},
            {"source_page": source_page, "half": "right", "role": "notes"},
        ])
    padding = (-len(logical)) % 4
    logical.extend({"source_page": None, "half": None, "role": "blank"}
                   for _ in range(padding))
    # The odd number of content pages always leaves a blank back cover.
    logical[-1]["role"] = "back-cover"
    for number, page in enumerate(logical, 1):
        page["logical_page"] = number
    count = len(logical)
    sheets = []
    for sheet in range(count // 4):
        sheets.append({
            "sheet": sheet + 1,
            "front": {"print_page": 2 * sheet + 1,
                      "left": count - 2 * sheet, "right": 1 + 2 * sheet},
            "back": {"print_page": 2 * sheet + 2,
                     "left": 2 + 2 * sheet, "right": count - 1 - 2 * sheet},
        })
    return {
        "source_pages": source_count,
        "text_note_spreads": source_count - 1,
        "content_a5_pages": count - padding,
        "padding_a5_pages": padding,
        "a5_pages": count,
        "a5_leaves": count // 2,
        "print_pages": count // 2,
        "sheets": count // 4,
        "logical_pages": logical,
        "sheet_plan": sheets,
    }


def validate_source(reader: PdfReader) -> None:
    for number, page in enumerate(reader.pages, 1):
        if page.rotation % 360:
            raise ValueError(f"Source page {number}: rotation must be 0.")
        if abs(float(page.get('/UserUnit', 1)) - 1) > 1e-9:
            raise ValueError(f"Source page {number}: nonstandard PDF UserUnit.")
        box = page.mediabox
        if abs(float(box.width) - A4_WIDTH) > .1 or abs(float(box.height) - A4_HEIGHT) > .1:
            raise ValueError(f"Source page {number}: expected landscape A4 (297 x 210 mm), "
                             f"got {float(box.width)/MM:.3f} x {float(box.height)/MM:.3f} mm.")


def merge_half(destination: PageObject, source: PageObject, half: str, slot: int) -> None:
    # Copy the page dictionary before changing its boxes or annotations.
    # merge_transformed_page clips to the cropbox before translating. Set the
    # other page boxes as well so the clip stays explicit across pypdf versions.
    clipped = copy.copy(source)
    clipped.pop(NameObject('/Annots'), None)
    x = float(source.mediabox.left) + (HALF_WIDTH if half == 'right' else 0)
    y = float(source.mediabox.bottom)
    rectangle = (x, y, x + HALF_WIDTH, y + A4_HEIGHT)
    for key in ('/CropBox', '/TrimBox', '/BleedBox', '/ArtBox'):
        clipped[NameObject(key)] = RectangleObject(rectangle)
    translation = Transformation().translate(tx=slot * HALF_WIDTH - x, ty=-y)
    destination.merge_transformed_page(clipped, translation, expand=False)
    destination.pop(NameObject('/Annots'), None)


def impose(source: Path, output: Path, plan_path: Path, title: str = EDITIONS["reading"]["title"]) -> dict:
    source = source.resolve()
    output = output.resolve()
    if source == output:
        raise ValueError("Source and imposed output must be different files.")
    source_hash = sha256(source)
    reader = PdfReader(source)
    validate_source(reader)
    plan = make_plan(len(reader.pages))
    plan.update({
        "generator": GENERATOR,
        "title": title,
        "source": str(source),
        "source_sha256": source_hash,
        "output": str(output),
        "paper_mm": [297, 210],
        "logical_page_mm": [148.5, 210],
        "scale": 1,
        "duplex": "short-edge",
        "additional_booklet_setting": False,
    })
    writer = PdfWriter()
    for sheet in plan['sheet_plan']:
        for side in ('front', 'back'):
            print_page = PageObject.create_blank_page(width=A4_WIDTH, height=A4_HEIGHT)
            for slot, position in enumerate(('left', 'right')):
                item = plan['logical_pages'][sheet[side][position] - 1]
                if item['source_page'] is not None:
                    merge_half(print_page, reader.pages[item['source_page'] - 1], item['half'], slot)
            print_page.pop(NameObject('/Annots'), None)
            writer.add_page(print_page)
    writer.add_metadata({
        '/Title': title,
        '/Author': 'Martin Kunze',
        '/Subject': 'A4 quer; tatsächliche Größe 100%; Duplex kurze Kante; keine zusätzliche Broschürenfunktion; mittig falten und heften.',
        '/Creator': GENERATOR,
    })
    writer.root_object[NameObject('/ViewerPreferences')] = DictionaryObject({
        NameObject('/PrintScaling'): NameObject('/None'),
        NameObject('/Duplex'): NameObject('/DuplexFlipShortEdge'),
    })
    if sha256(source) != source_hash:
        raise ValueError("Reading PDF changed during imposition; rerun after its build has finished.")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix('.pdf.tmp')
    with temporary.open('wb') as file:
        writer.write(file)
    writer.close()
    verification = PdfReader(temporary)
    if len(verification.pages) != plan['print_pages']:
        raise ValueError("Unexpected number of imposed pages.")
    if any(page.get('/Annots') for page in verification.pages):
        raise ValueError("The print PDF must not contain source annotations.")
    for page in verification.pages:
        if abs(float(page.mediabox.width) - A4_WIDTH) > .01 or abs(float(page.mediabox.height) - A4_HEIGHT) > .01:
            raise ValueError("Unexpected imposed page dimensions.")
    temporary.replace(output)
    plan['output_sha256'] = sha256(output)
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    diagnostics = [
        f"Generator: {GENERATOR}",
        f"Title: {title}",
        "Status: complete",
        f"Source: {source}",
        f"Source SHA256: {source_hash}",
        f"Output SHA256: {plan['output_sha256']}",
        f"Source pages: {plan['source_pages']}",
        f"Text-note spreads: {plan['text_note_spreads']}",
        f"A5 pages (including padding): {plan['a5_pages']}",
        f"A5 leaves: {plan['a5_leaves']}",
        f"Padding A5 pages: {plan['padding_a5_pages']}",
        f"Print pages: {plan['print_pages']}",
        f"A4 sheets: {plan['sheets']}",
        "Dimensions: A4 landscape 297 x 210 mm; each half 148.5 x 210 mm",
        "Content transform: translation only; scale 1; vector content retained",
        "Annotations: none",
        "Print: actual size 100%; A4 landscape; duplex short-edge; no further booklet setting",
        f"Page plan: {plan_path.resolve()}",
    ]
    output.with_suffix('.log').write_text('\n'.join(diagnostics) + '\n', encoding='utf-8')
    print('\n'.join(diagnostics))
    return plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--edition', choices=EDITIONS, default='reading',
                        help='Choose reading or separate exercises/solutions booklet.')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--plan', type=Path)
    args = parser.parse_args()
    edition = EDITIONS[args.edition]
    source = args.source or ROOT / 'registry/binomial' / edition['source']
    output = args.output or ROOT / 'registry/binomial' / edition['output']
    plan = args.plan or ROOT / 'tmp/binomial-reading' / edition['plan']
    impose(source, output, plan, edition['title'])


if __name__ == '__main__':
    main()
