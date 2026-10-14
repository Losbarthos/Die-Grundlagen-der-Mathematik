"""Independent PDF and shipout tests for the opt-in symbol legend.

Requires LuaLaTeX, pdftotext and pypdf; color-state and reading tap-area checks
also need pdftoppm and Pillow. Builds only tests/symbol-legend sources
into tmp/symbol-legend-tests; no main-document registry or PDF is modified.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/symbol-legend"
OUTPUT = ROOT / "tmp/symbol-legend-tests"
EXPECTATIONS = {
    "core": [["alpha", "gamma"], [], ["beta"], ["beta"],
             ["alpha", "beta"], ["gamma"], ["alpha"]],
    "twoside": [[], ["alpha"], ["alpha"]],
    "disabled": [[], []],
    "baseline": [[], []],
    "discretionary": [["replace"], ["pre", "post"]],
    "local-reference": [["localref"]],
    "discarded-page": [["alpha"]],
    "color-state": [["alpha", "beta", "gamma"], ["alpha", "beta", "gamma"]],
    "reading-links": [[], ["ra"], ["ra", "rb"], [], ["rm", "rc"], ["rm"], ["rd"]],
    "reading-compact": [[], ["ra"], ["ra", "rb"], [], ["rm", "rc"], ["rm"], ["rd"]],
}
EXPECTED_ERRORS = {
    "overflow-height": "Legend too tall",
    "overflow-width": "exceeds the legend width",
    "nondefinition-id": "missing definition ID FixtureTheorem",
    "leaders": "marked leaders are unsupported",
    "leaders-zero": "marked leaders are unsupported",
}
EXPECTED_UNRESOLVED = {"missing-label": "Unresolved definition label"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def build(name, output):
    directory = output / name
    directory.mkdir(parents=True, exist_ok=True)
    # This case must really start without its local definition label on every
    # invocation, even when the rest of the test output is reused.
    if name == "local-reference":
        auxiliary = directory / f"{name}.aux"
        if auxiliary.exists():
            auxiliary.unlink()
    command = ["lualatex", "-no-shell-escape", "-interaction=nonstopmode",
               "-halt-on-error", "-file-line-error", f"-jobname={name}",
               f"-output-directory={directory}", str(FIXTURES / f"{name}.tex")]
    environment = dict(os.environ, MIKTEX_ENABLE_INSTALLER="0")
    for run in (1, 2):
        result = subprocess.run(command, cwd=ROOT, env=environment,
                                capture_output=True, timeout=90)
        console = result.stdout.decode("utf-8", errors="replace")
        console += result.stderr.decode("utf-8", errors="replace")
        (directory / f"console-{run}.log").write_text(console, encoding="utf-8")
        if name in EXPECTED_ERRORS:
            require(result.returncode != 0, f"{name}: expected an explicit build failure")
            require(EXPECTED_ERRORS[name].lower() in console.lower(),
                    f"{name}: failed for another reason:\n{console[-3500:]}")
            return directory
        require(result.returncode == 0, f"{name}: build failed:\n{console[-3500:]}")
    return directory


def words(pdf):
    result = subprocess.run(["pdftotext", "-bbox", str(pdf), "-"],
                            capture_output=True, check=True, timeout=30)
    root = ET.fromstring(result.stdout)
    pages = []
    for page in root.iter():
        if page.tag.rsplit("}", 1)[-1] != "page":
            continue
        pages.append([dict(text=node.text or "", **{
            key: float(value) for key, value in node.attrib.items()})
            for node in page.iter()
            if node.tag.rsplit("}", 1)[-1] == "word"])
    return pages


def word(page, text):
    found = [item for item in page if item["text"] == text]
    require(len(found) == 1, f"expected exactly one PDF word {text!r}, found {len(found)}")
    return found[0]


def check_pdf(name, directory):
    pdf = directory / f"{name}.pdf"
    reader = PdfReader(pdf)
    expected = EXPECTATIONS[name]
    require(len(reader.pages) == len(expected),
            f"{name}: expected {len(expected)} actual PDF pages, got {len(reader.pages)}")
    for number, (page, entries) in enumerate(zip(reader.pages, expected), 1):
        text = page.extract_text() or ""
        actual = Counter(match.lower() for match in re.findall(r"SLENTRY([A-Z]+)", text))
        require(actual == Counter(entries),
                f"{name} PDF page {number}: expected {entries}, got {dict(actual)}")
        require(text.count("Symbole dieser Seite") == bool(entries),
                f"{name} PDF page {number}: wrong number of legend headings")
        linked_definitions = 0
        for reference in page.get("/Annots", []):
            annotation = reference.get_object()
            action = annotation.get("/A", {})
            destination = annotation.get("/Dest", action.get("/D"))
            if isinstance(destination, str) and (destination == "sl.fixture-definition"
                                                 or destination.startswith("fixturedef.")
                                                 or destination.startswith("slreading:")):
                require(destination in reader.named_destinations,
                        f"{name}: definition link has no PDF destination")
                linked_definitions += 1
        require(linked_definitions >= len(entries),
                f"{name} PDF page {number}: missing linked original definitions")
    return words(pdf)


def check_audit(name, directory):
    if name == "baseline":
        return None
    audit = json.loads((directory / f"{name}.symbol-legend.json").read_text(encoding="utf-8"))
    if name == "disabled":
        require(audit["absolute_page_count"] == 0 and audit["pages"] == [],
                "disabled: collection must stay off")
        return audit
    expected = EXPECTATIONS[name]
    require(audit["absolute_page_count"] == len(expected), f"{name}: wrong audit page count")
    for number, (page, entries) in enumerate(zip(audit["pages"], expected), 1):
        require(page["absolute_page"] == number, f"{name}: wrong physical page number")
        require(page["visible"] == entries,
                f"{name} audit page {number}: expected {entries}, got {page['visible']}")
        require(not ({"ghost", "suppressed"} & set(page["used"])),
                f"{name}: discarded or suppressed content was collected")
    if name == "core":
        pages = audit["pages"]
        require(pages[0]["use_counts"].get("alpha") == 3,
                "core: repeated real uses were not retained in the audit")
        require(pages[0]["unintroduced"] == ["beta"], "core: pre-introduction use leaked")
        require(pages[0]["introductions_on_page"] == ["gamma"],
                "core: discarded measurement box introduced delta")
        require(pages[3]["unintroduced"] == ["delta"],
                "core: discarded introduction became persistent")
        require(pages[5]["used"] == ["gamma"] and pages[6]["used"] == ["alpha"],
                "core: a box was assigned to its construction page instead of its shipout page")
    elif name == "twoside":
        require([page["tex_page"] for page in audit["pages"]] == [1, 1, 2],
                "twoside: printed and physical page counters were confused")
    elif name == "discarded-page":
        require(audit["pages"][0]["unintroduced"] == ["delta"],
                "discarded-page: an introduction on a discarded page survived")
        require(audit["pages"][0]["introductions_on_page"] == [],
                "discarded-page: discarded nodes entered the surviving page audit")
    elif name == "local-reference":
        first_pass = (directory / "console-1.log").read_text(encoding="utf-8", errors="replace")
        require("Unresolved definition label sl:new-local-label" in first_pass,
                "local-reference: fixture did not exercise an unresolved first pass")
    elif name in {"reading-links", "reading-compact"}:
        pages = audit["pages"]
        require(pages[0]["unintroduced"] == ["ra", "rb"],
                "reading-links: unchosen mathchoice branch introduced a symbol")
        require(pages[3]["unintroduced"] == ["rm"],
                "reading-links: introduction was assigned to the box construction page")
        require(pages[5]["unintroduced"] == ["rd"],
                "reading-links: discarded whole-page introduction survived")
        introductions = {entry["id"]: entry["introduced_page"] for entry in audit["declarations"]
                         if entry["id"] in {"ra", "rb", "rm", "rc", "rd", "rg"}}
        require(introductions == {"ra": 2, "rb": 3, "rm": 5, "rc": 5, "rd": 7, "rg": None},
                f"reading-links: wrong first physical introduction pages {introductions}")
    return audit


def check_layout(name, page_words):
    if name == "twoside":
        odd, even = page_words[1], page_words[2]
        require(word(odd, "SLENTRYALPHA")["xMin"] > word(odd, "RIGHTODD")["xMax"] + 3,
                "twoside: odd-page legend is not outside the right text edge")
        require(word(even, "SLENTRYALPHA")["xMax"] < word(even, "BODYEVEN")["xMin"] - 3,
                "twoside: even-page legend is not outside the left text edge")
    elif name == "core":
        require(any(item["text"] == "AUTOBEFORE" for item in page_words[5]),
                "core: automatic-break source paragraph moved unexpectedly")
        require(any(item["text"] == "AUTOAFTER" for item in page_words[6]),
                "core: the delayed box did not actually move to the next PDF page")


def normalized_words(pages):
    return [[(item["text"], *(round(item[key], 3) for key in
              ("xMin", "yMin", "xMax", "yMax"))) for item in page] for page in pages]


def check_reading_links(name, directory, page_words):
    reader = PdfReader(directory / f"{name}.pdf")
    rendered = {}

    def ink_box(page_index, item):
        # pdftotext uses the font-wide ascent/descent, which can exceed the
        # visible capitals by several points. Resolve only such ambiguous
        # bounding boxes against real rendered ink, rather than loosening the
        # click-area tolerance and potentially accepting clipped letters.
        from PIL import Image
        if page_index not in rendered:
            prefix = directory / f"tap-{page_index + 1}"
            subprocess.run(["pdftoppm", "-f", str(page_index + 1), "-l", str(page_index + 1),
                            "-singlefile", "-r", "144", "-png",
                            str(directory / f"{name}.pdf"), str(prefix)],
                           capture_output=True, check=True, timeout=30)
            rendered[page_index] = Image.open(prefix.with_suffix(".png")).convert("L")
        x, y = math.floor(item["xMin"] * 2), math.floor(item["yMin"] * 2)
        crop = rendered[page_index].crop((x, y, math.ceil(item["xMax"] * 2),
                                         math.ceil(item["yMax"] * 2)))
        bounds = crop.point(lambda value: 255 if value < 128 else 0).getbbox()
        require(bounds, f"{name}: no visible ink for {item['text']!r}")
        return dict(xMin=(x + bounds[0]) / 2, yMin=(y + bounds[1]) / 2,
                    xMax=(x + bounds[2]) / 2, yMax=(y + bounds[3]) / 2)
    targets = {
        "ra": (1, "ALPHAINTRO", "2"),
        "rb": (2, "RETAINEDTABLE", "3"),
        "rm": (4, "MOVEDINTRO", "5"),
        "rc": (4, "CHOSENINTRO", "5"),
        "rd": (6, "RETAINEDINTRO", "vii"),
    }
    actual = {name for name in reader.named_destinations if name.startswith("slreading:")}
    require(actual == {f"slreading:{name}" for name in targets},
            f"reading-links: missing/spurious reading destinations {actual}")
    auxiliary = (directory / f"{name}.aux").read_text(encoding="utf-8")
    for symbol_id, (page_number, nearby_word, printed_page) in targets.items():
        destination = reader.named_destinations[f"slreading:{symbol_id}"]
        require(reader.get_destination_page_number(destination) == page_number,
                f"reading-links: {symbol_id} destination is on the wrong physical page")
        nearby = word(page_words[page_number], nearby_word)
        top = float(reader.pages[page_number].mediabox.height) - float(destination.top)
        require(nearby["yMin"] - 6 <= top <= nearby["yMax"] + 6,
                f"reading-links: {symbol_id} destination is not beside its introduction line")
        require(nearby["xMin"] - 2 <= float(destination.left) < 430,
                f"reading-links: {symbol_id} destination was placed outside its body math atom")
        record = (f"\\newlabel{{slreading:{symbol_id}}}"
                  f"{{{{}}{{{printed_page}}}{{Einführung}}{{slreading:{symbol_id}}}{{}}}}")
        require(auxiliary.count(record) == 1,
                f"reading-links: wrong/duplicate AUX label for {symbol_id}: expected {record}")
    require("slreading:rg" not in auxiliary,
            "reading-links: a discarded measurement/choice generated a label")
    for index, (page, entries) in enumerate(zip(reader.pages, EXPECTATIONS["reading-links"])):
        text = page.extract_text() or ""
        require("Def." not in text, "reading-links: reading entries invent definition numbers")
        require(text.count("Einführung, S.") == len(entries),
                f"reading-links: page {index + 1} is missing introduction link text")
        expected_pages = Counter(targets[name][2] for name in entries)
        actual_pages = Counter(re.findall(r"Einführung, S\.\s*(\d+|[ivxlcdm]+)", text))
        require(actual_pages == expected_pages,
                f"reading-links: page {index + 1} has wrong printed introduction pages")
        linked, tap_rectangles = [], {}
        for reference in page.get("/Annots", []):
            annotation = reference.get_object()
            action = annotation.get("/A", {})
            destination = annotation.get("/Dest", action.get("/D"))
            if isinstance(destination, str) and destination.startswith("slreading:"):
                require(annotation.get("/Subtype") == "/Link",
                        f"{name}: a reading destination has no clickable link annotation")
                symbol_id = destination.removeprefix("slreading:")
                linked.append(symbol_id)
                left, bottom, right, top = map(float, annotation["/Rect"])
                height = float(page.mediabox.height)
                tap_rectangles[symbol_id] = (left, height - top, right, height - bottom)
        require(Counter(linked) == Counter(entries),
                f"reading-links: page {index + 1} has wrong local link destinations")
        # Check the real annotation area independently of its destination.
        # Previously only the final reference line was clickable; checking a
        # valid target alone could not catch missing symbol/meaning tap areas.
        symbols = {"ra": "A", "rb": "B", "rm": "M", "rc": "C", "rd": "D"}
        fixture_width = 42 * 72 / 25.4  # the fixture's 42 mm, in PDF points
        for symbol_id in entries:
            rectangle = tap_rectangles[symbol_id]
            left, top, right, bottom = rectangle
            context = f"{name} page {index + 1}, entry {symbol_id}"
            require(0 <= left < right <= float(page.mediabox.width)
                    and 0 <= top < bottom <= float(page.mediabox.height),
                    f"{context}: tap area is outside the physical PDF page")
            require(right - left >= fixture_width * 0.95,
                    f"{context}: tap area does not span the legend entry width")
            symbol = word(page_words[index], symbols[symbol_id])
            meaning = word(page_words[index], f"SLENTRY{symbol_id.upper()}")
            reference_lines = [item for item in page_words[index]
                               if item["text"] == "Einführung,"
                               and item["yMin"] > max(symbol["yMin"], meaning["yMin"]) + 3]
            require(reference_lines, f"{context}: no following introduction reference line")
            reference = min(reference_lines, key=lambda item: item["yMin"])
            line = [item for item in page_words[index]
                    if abs(item["yMin"] - reference["yMin"]) < 1
                    and reference["xMin"] - 1 <= item["xMin"]
                    < reference["xMin"] + fixture_width]
            require(" ".join(item["text"] for item in line)
                    == f"Einführung, S. {targets[symbol_id][2]}",
                    f"{context}: could not identify the complete page-reference line")
            for item in [symbol, meaning, *line]:
                def enclosed(box):
                    return (left - 0.5 <= box["xMin"] and box["xMax"] <= right + 0.5
                            and top - 0.5 <= box["yMin"] and box["yMax"] <= bottom + 0.5)
                require(enclosed(item) or enclosed(ink_box(index, item)),
                        f"{context}: {item['text']!r} lies outside its tap rectangle")
        for position, symbol_id in enumerate(entries):
            a = tap_rectangles[symbol_id]
            for following_id in entries[position + 1:]:
                b = tap_rectangles[following_id]
                require(min(a[2], b[2]) <= max(a[0], b[0])
                        or min(a[3], b[3]) <= max(a[1], b[1]),
                        f"{name} page {index + 1}: tap areas for {symbol_id} and {following_id} overlap")
    if name == "reading-compact":
        symbol = word(page_words[1], "A")
        meaning = word(page_words[1], "SLENTRYRA")
        link = word(page_words[1], "Einführung,")
        require(abs(symbol["yMax"] - meaning["yMax"]) < 2
                and symbol["xMax"] < meaning["xMin"],
                "reading-compact: symbol and meaning do not share one line")
        require(link["yMin"] > meaning["yMin"] + 7,
                "reading-compact: introduction link has no separate line")
    else:
        require(word(page_words[1], "SLENTRYRA")["yMin"]
                > word(page_words[1], "A")["yMin"] + 7,
                "reading-links: default legacy layout became compact")


def check_disabled_reading(directory):
    reader = PdfReader(directory / "disabled.pdf")
    require(not any(name.startswith("slreading:") for name in reader.named_destinations),
            "disabled: reading introductions generated PDF destinations")
    require("slreading:" not in (directory / "disabled.aux").read_text(encoding="utf-8"),
            "disabled: reading introductions generated AUX labels")


def check_color_state(directory, page_words):
    """Inspect actual ink, since text extraction/audits cannot detect white text."""
    from PIL import Image, ImageChops

    log = (directory / "color-state.log").read_text(encoding="utf-8", errors="replace")
    require("FIXTURE WHITE SHIPOUT RGB=1,1,1" in log,
            "color-state: the second page did not ship while white was active")
    require(shutil.which("pdftoppm"), "color-state: missing pdftoppm")
    subprocess.run(["pdftoppm", "-f", "1", "-l", "2", "-r", "144", "-png",
                    str(directory / "color-state.pdf"), str(directory / "ink")],
                   capture_output=True, check=True, timeout=30)
    images = [Image.open(directory / f"ink-{number}.png").convert("RGB")
              for number in (1, 2)]
    # pdftotext coordinates and the rendered image share the top-left origin.
    def crop(image, boxes, padding=2):
        return image.crop((math.floor(min(box["xMin"] for box in boxes) * 2) - padding,
                           math.floor(min(box["yMin"] for box in boxes) * 2) - padding,
                           math.ceil(max(box["xMax"] for box in boxes) * 2) + padding,
                           math.ceil(max(box["yMax"] for box in boxes) * 2) + padding))

    def pixels_of(image):
        return list(getattr(image, "get_flattened_data", image.getdata)())

    legend_left = word(page_words[0], "SLENTRYALPHA")["xMin"] - 1
    legend_words = [[item for item in page if item["xMin"] >= legend_left]
                    for page in page_words]
    require(normalized_words(legend_words[:1]) == normalized_words(legend_words[1:]),
            "color-state: the reference and white-state legends differ geometrically")
    require(len(legend_words[0]) >= 20,
            "color-state: the legend inspection omitted expected text components")
    for number, (page, image) in enumerate(zip(legend_words, images), 1):
        # Check each extracted word separately, including all three symbols,
        # the heading, the meanings, and every definition/page-reference part.
        for item in page:
            pixels = pixels_of(crop(image, [item], padding=0))
            require(any(max(pixel) <= 32 for pixel in pixels),
                    f"color-state page {number}: no black ink for {item['text']!r}")
        pixels = pixels_of(crop(image, page))
        require(all(max(pixel) - min(pixel) <= 2 for pixel in pixels),
                f"color-state page {number}: colored rather than black/gray legend ink")
    reference = crop(images[0], legend_words[0])
    white_state = crop(images[1], legend_words[1])
    require(reference.size == white_state.size
            and ImageChops.difference(reference, white_state).getbbox() is None,
            "color-state: some legend ink differs when white is active at shipout")
    body_ink = [pixels_of(crop(image, [word(page, "COLORBODY")]))
                for image, page in zip(images, page_words)]
    require(any(max(pixel) <= 32 for pixel in body_ink[0]),
            "color-state: the black control body is not visible")
    require(all(min(pixel) >= 250 for pixel in body_ink[1]),
            "color-state: the legend reset leaked into the deliberately white body")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", choices=list(EXPECTATIONS) + list(EXPECTED_ERRORS) + list(EXPECTED_UNRESOLVED))
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to((ROOT / "tmp").resolve()), "test output must stay inside repository tmp/")
    for executable in ("lualatex", "pdftotext"):
        require(shutil.which(executable), f"missing executable: {executable}")
    require((ROOT / "tex/impl/symbol-legend.lua").is_file(), "symbol-legend.lua is not present yet")
    results, layouts = [], {}
    cases = args.case or list(EXPECTATIONS) + list(EXPECTED_ERRORS) + list(EXPECTED_UNRESOLVED)
    for name in cases:
        try:
            directory = build(name, output)
            if name in EXPECTED_UNRESOLVED:
                log = (directory / f"{name}.log").read_text(encoding="utf-8", errors="replace")
                require(EXPECTED_UNRESOLVED[name] in log,
                        f"{name}: unresolved-reference diagnostic missing after two passes")
                text = "\n".join(page.extract_text() or "" for page in PdfReader(directory / f"{name}.pdf").pages)
                require("??" in text, f"{name}: final PDF does not expose the unresolved reference")
            elif name not in EXPECTED_ERRORS:
                layouts[name] = check_pdf(name, directory)
                check_audit(name, directory)
                check_layout(name, layouts[name])
                if name == "color-state":
                    check_color_state(directory, layouts[name])
                elif name in {"reading-links", "reading-compact"}:
                    check_reading_links(name, directory, layouts[name])
                elif name == "disabled":
                    check_disabled_reading(directory)
                log = (directory / f"{name}.log").read_text(encoding="utf-8", errors="replace")
                require(not re.search(r"Overfull|undefined references|Reference .* undefined|"
                                      r"duplicate.*destination|destination.*duplicate", log,
                                      flags=re.IGNORECASE),
                        f"{name}: layout or reference warning in final log")
            results.append({"case": name, "passed": True})
            print(f"PASS {name}")
        except (AssertionError, subprocess.SubprocessError, OSError, ValueError) as exc:
            results.append({"case": name, "passed": False, "error": str(exc)})
            print(f"FAIL {name}: {exc}")
    if "disabled" in layouts and "baseline" in layouts:
        same = normalized_words(layouts["disabled"]) == normalized_words(layouts["baseline"])
        results.append({"case": "disabled-layout-preservation", "passed": same})
        print(f"{'PASS' if same else 'FAIL'} disabled-layout-preservation")
    output.mkdir(parents=True, exist_ok=True)
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return int(any(not result["passed"] for result in results))


if __name__ == "__main__":
    sys.exit(main())
