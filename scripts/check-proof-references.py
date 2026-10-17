"""Build and inspect isolated automatic proof-reference integration fixtures.

Requires LuaLaTeX, pdftotext, pypdf and pdfplumber. Outputs stay in tmp/proof-references-tests;
no manuscript source, production registry or published PDF is modified.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from importlib.util import find_spec
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import unicodedata
import xml.etree.ElementTree as ET

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/proof-references"
OUTPUT = ROOT / "tmp/proof-references-tests"
IDENTITY = "thm:auto:91.1.1.1"
CONJUNCTION = "thm:auto:91.1.1.2"
DEFINITION = "def:auto:91.1.1.1"
AXIOM = "ax:auto:91.1.1.1"
HELPER = "thm:pp:91.1.1.90:1"
DELTA_HELPER = "thm:pp:91.1.1.91:1"
FORWARD = "thm:auto:91.1.1.4"
LAYOUT_AUDITOR = None
EXPECTED = {
    "core": {
        "normal": [DEFINITION, IDENTITY],
        "wide": [CONJUNCTION, AXIOM],
        "paired": [DEFINITION],
        "split": [IDENTITY, HELPER, DEFINITION],
        "splitwide": [CONJUNCTION, DELTA_HELPER],
        "nested": [DEFINITION, IDENTITY],
        "classical": ["def:fixture-classical", "thm:fixture-classical", "ax:fixture-classical"],
        "bare": [DEFINITION, IDENTITY],
        "ordinary": [],
        "empty": [],
        "disabled": [],
        "enabled": [IDENTITY],
        "forward": [FORWARD],
    },
    "producer": {},
    "consumer": {"import": ["thm:auto:92.1.1.1", "def:auto:92.1.1.1"]},
    "pagination": {"pagination": [f"thm:auto:91.1.1.{i}" for i in range(1, 21)]},
    "tall-context": {"tall-context": ["thm:auto:91.1.1.1"]},
    "overflow": {
        "wide-formula": ["thm:overflow:wide-formula"],
        "wide-context": ["def:overflow:wide-context"],
        "tall-formula": ["thm:overflow:tall-formula"],
        "tall-context-row": ["def:overflow:tall-context"],
    },
    # This boundary regression drives the table renderer directly; it does not
    # resolve statements or call the instrumented ProofReferenceEntry macro.
    "table-tail": {},
    "graphics-state": {
        "scaled": ["thm:graphics:scaled", "thm:graphics:scaled-follow"],
        "rotated": ["thm:graphics:rotated", "thm:graphics:rotated-follow"],
        "color": ["thm:graphics:color", "thm:graphics:color-follow"],
        "linked-context": ["thm:graphics:linked-context", "thm:graphics:linked-follow"],
    },
}
OVERFLOW_MARKERS = [
    "WIDEFORMULAMARKER", "WIDECONTEXTMARKER", "WIDECONTEXTNOTEMARKER",
    "WIDECONTEXTCONCLUSION", "TALLCONTEXTTITLE", "TALLCONTEXTNOTEMARKER",
    "TALLCONTEXTCONCLUSION", "AFTEROVERFLOWMARKER",
] + [f"{prefix}{number:02}" for prefix in ("TALLFORMULAROW", "TALLCONTEXTROW")
     for number in range(1, 73)]
GRAPHICS_MARKERS = [
    "REFERENCECONTROL", "SCALEDBEGIN", "SCALEDROWONE", "SCALEDROWTWO",
    "SCALEDROWTHREE", "SCALEDEND", "SCALEDFOLLOW", "AFTERSCALED",
    "ROTATEDBEGIN", "ROTATEDROWONE", "ROTATEDROWTWO", "ROTATEDROWTHREE",
    "ROTATEDEND", "ROTATEDFOLLOW", "AFTERROTATED", "COLORBEGIN", "COLOREND",
    "COLORFOLLOW", "AFTERCOLOR", "LINKCONTEXT", "LINKCONCLUSION", "LINKFOLLOW",
    "AFTERLINK",
] + [f"LINKROW{number:02}" for number in range(1, 73)]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def build(name: str, output: Path) -> None:
    environment = dict(os.environ, MIKTEX_ENABLE_INSTALLER="0",
                       PROOF_REFERENCES_TEST_OUTPUT=output.as_posix())
    # Start cold each invocation; the second run must supply genuine forward
    # reference/persistence coverage rather than reuse an earlier test result.
    for extension in ("aux", "out", "registry.tsv", "debug.log", "events.tsv"):
        path = output / f"{name}.{extension}"
        if path.exists():
            path.unlink()
    command = ["lualatex", "-no-shell-escape", "-interaction=nonstopmode",
               "-halt-on-error", "-file-line-error", f"-jobname={name}",
               f"-output-directory={output}", str(FIXTURES / f"{name}.tex")]
    for run in (1, 2):
        result = subprocess.run(command, cwd=ROOT, env=environment,
                                capture_output=True, timeout=120)
        console = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        (output / f"{name}-console-{run}.log").write_text(console, encoding="utf-8")
        require(result.returncode == 0,
                f"{name}, run {run}: LuaLaTeX failed:\n{console[-5000:]}")


def entries(name: str, output: Path) -> dict[str, list[dict[str, str]]]:
    result: dict[str, list[dict[str, str]]] = defaultdict(list)
    for line in (output / f"{name}.events.tsv").read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        require(len(fields) == 6, f"{name}: malformed renderer event {line!r}")
        case, env, label, number, display, delta = fields
        result[case].append(dict(env=env, label=label, number=number,
                                 display=display, delta=delta))
    return result


def check_events(name: str, output: Path) -> None:
    observed = entries(name, output)
    require(set(observed) <= set(EXPECTED[name]),
            f"{name}: reference table escaped its proof scope: {set(observed)}")
    for case, expected in EXPECTED[name].items():
        actual = [entry["label"] for entry in observed.get(case, [])]
        require(actual == expected,
                f"{name}/{case}: expected first-use order {expected}, got {actual}")
    for group in observed.values():
        for entry in group:
            require(entry["number"] not in {"", "?"},
                    f"{name}: missing number for {entry['label']}")
            require(entry["display"].strip(), f"{name}: empty displayed statement")

    if name == "core":
        normal = observed["normal"]
        require(compact(normal[0]["display"]) == r"D\coloneqqP\landQ",
                "core: definition was replaced with its ID or lookup key")
        require(compact(normal[1]["display"]) == r"P\rightarrowP",
                "core: theorem display changed")
        for case in ("wide", "splitwide"):
            item = observed[case][0]
            require(r"\begin{aligned}" in compact(item["display"])
                    and r"P\rightarrowR" in compact(item["display"])
                    and r"P\rightarrow(Q\landR)" in compact(item["display"]),
                    f"core/{case}: original multiline premise/conclusion display was lost")
            require(all(marker in item["delta"] for marker in
                        ("Declaration", "PREMISEMARKER", "Side condition", "FixtureIdentity")),
                    f"core/{case}: incomplete original Delta context")
        require("HELPERPREMISE" in observed["splitwide"][1]["delta"],
                "core: a referenced helper lost its Delta premise")
        require(observed["split"][1]["number"] == "91.1.1.90(H1)",
                "core: helper reference number differs from its proof-table number")
        require(observed["wide"][1]["env"] == "axiom", "core: axiom type was lost")
        require(compact(observed["forward"][0]["display"]) == r"P\lorQ\vdashQ\lorP",
                "core: forward reference failed to recover the original statement")
        require(all(marker in observed["classical"][0]["display"] for marker in
                    ("CLASSICPREMISE", "CLASSICCONCLUSION", r"\exists", r"\iota")),
                "core: classical definition lost its prose premise or a displayed formula")
        for index, prefix, env in ((1, "CLASSICTHEOREM", "theorem"), (2, "CLASSICAXIOM", "axiom")):
            item = observed["classical"][index]
            require(item["env"] == env
                    and prefix + "PREMISE" in item["display"]
                    and prefix + "CONCLUSION" in item["display"],
                    f"core: classical {env} lost its original prose or formulas")
    elif name == "consumer":
        theorem, definition = observed["import"]
        require(theorem["number"] == "92.1.1.1" and definition["number"] == "92.1.1.1",
                "consumer: imported registry numbers were lost")
        require(r"B\subseteqC" in compact(theorem["display"])
                and "IMPORTEDPREMISE" in theorem["delta"]
                and "IMPORTEDDECLARATION" in theorem["delta"],
                "consumer: persistence retained only the structural lookup key")
        require(compact(definition["display"]) == r"X\coloneqqA\cupB"
                and "IMPORTEDDEFINITION" in definition["delta"],
                "consumer: imported definition display/context was lost")
    elif name == "tall-context":
        statement = observed["tall-context"][0]
        require("TALLCONCLUSIONMARKER" in statement["display"],
                "tall-context: conclusion missing from the renderer")
        for number in range(1, 45):
            require(f"TALLROW{number:02}" in statement["delta"],
                    f"tall-context: context row {number} missing from the original statement")
        require(all(marker in statement["delta"] for marker in
                    ("DeltaDecl", "DeltaPrem", "DECLNOTEMARKER", "PREMNOTEMARKER",
                     "BLOCKTWOMARKER", "BLOCKTHREEMARKER", "BLOCKFOURMARKER",
                     "RAWHEADINGMARKER", "multicolumn", "DeltaContext")),
                "tall-context: original context structure was lost")


def check_context_layout(name: str, output: Path) -> None:
    """Reject text collisions even when TeX emits no overfull-box warning."""
    result = subprocess.run(["pdftotext", "-bbox", str(output / f"{name}.pdf"), "-"],
                            capture_output=True, check=True, timeout=30)
    (output / f"{name}.bbox.html").write_bytes(result.stdout)
    document = ET.fromstring(result.stdout)
    markers_checked = 0
    collisions: list[str] = []
    for number, page in enumerate(document.findall(".//{*}page"), 1):
        words = [dict(text=node.text or "", **{
            key: float(value) for key, value in node.attrib.items()})
            for node in page.findall(".//{*}word")]
        for marker in words:
            if not re.fullmatch(r"TALLROW\d{2}:?|BLOCK(?:TWO|THREE|FOUR)MARKER|RAWHEADINGMARKER",
                                marker["text"]):
                continue
            markers_checked += 1
            for other in words:
                if other is marker:
                    continue
                overlap_x = min(marker["xMax"], other["xMax"]) - max(marker["xMin"], other["xMin"])
                overlap_y = min(marker["yMax"], other["yMax"]) - max(marker["yMin"], other["yMin"])
                if overlap_x > 1 and overlap_y > 1:
                    collisions.append(
                        f"PDF page {number}: {marker['text']} overlaps {ascii(other['text'])} "
                        f"by {overlap_x:.2f} x {overlap_y:.2f} pt")
    require(markers_checked == 96,
            f"{name}: expected 96 original/overview row and block labels, found {markers_checked}")
    require(not collisions,
            f"{name}: {len(collisions)} label collisions:\n" + "\n".join(collisions[:12]))


def check_overflow_layout(name: str, output: Path) -> None:
    """Distinguish readable reflow from shrinking or clipping a whole statement."""
    result = subprocess.run(["pdftotext", "-bbox", str(output / f"{name}.pdf"), "-"],
                            capture_output=True, check=True, timeout=30)
    (output / f"{name}.bbox.html").write_bytes(result.stdout)
    document = ET.fromstring(result.stdout)
    words = []
    for number, page in enumerate(document.findall(".//{*}page"), 1):
        for node in page.findall(".//{*}word"):
            words.append(dict(text=compact(unicodedata.normalize("NFKC", node.text or "")),
                              page=number, page_width=float(page.attrib["width"]),
                              page_height=float(page.attrib["height"]), **{
                                  key: float(value) for key, value in node.attrib.items()}))

    def position(word: dict) -> tuple[int, float]:
        return word["page"], word["yMin"]

    markers = {}
    for marker in OVERFLOW_MARKERS:
        matches = [word for word in words if word["text"].rstrip(":") == marker]
        require(len(matches) == 1,
                f"{name}: expected one visible {marker}, found {len(matches)}")
        word = markers[marker] = matches[0]
        require(0 <= word["xMin"] < word["xMax"] <= word["page_width"]
                and 0 <= word["yMin"] < word["yMax"] <= word["page_height"] - 20,
                f"{name}: {marker} is clipped or extends into the bottom page margin")
        # Normal 10 pt overview text has a roughly 14 pt PDF font rectangle.
        # This deliberately leaves font-metric tolerance but rejects scaling a
        # 72-line aligned statement into one table cell.
        require(word["yMax"] - word["yMin"] >= 9,
                f"{name}: {marker} was reduced below a readable overview text size")

    for prefix in ("TALLFORMULAROW", "TALLCONTEXTROW"):
        rows = [markers[f"{prefix}{number:02}"] for number in range(1, 73)]
        require(len({word["page"] for word in rows}) >= 2,
                f"{name}: {prefix} must continue across pages instead of shrinking")
        require(all(position(before) < position(after) for before, after in zip(rows, rows[1:])),
                f"{name}: {prefix} rows were reordered or overprinted")

    require(position(markers["TALLCONTEXTROW72"])
            < position(markers["TALLCONTEXTNOTEMARKER"])
            < position(markers["TALLCONTEXTCONCLUSION"])
            < position(markers["AFTEROVERFLOWMARKER"]),
            f"{name}: the final context note, conclusion or following paragraph is misplaced")

    # Look at the actual P/Q glyphs, not only the leading text labels: a renderer
    # could keep a label readable while scaling its entire formula separately.
    case_starts = [word for word in words if word["text"] == "CASE"]
    require(len(case_starts) == 4, f"{name}: expected four visible proof-case headings")
    for letter, start_marker, end_marker in (
            ("P", "WIDEFORMULAMARKER", None),
            ("Q", "WIDECONTEXTMARKER", "WIDECONTEXTNOTEMARKER")):
        start = position(markers[start_marker])
        boundaries = ([position(markers[end_marker])] if end_marker else
                      [position(word) for word in case_starts if position(word) > start])
        require(boundaries, f"{name}: {start_marker} appears outside its proof case")
        end = min(boundaries)
        glyphs = [word for word in words
                  if start <= position(word) < end
                  and re.fullmatch(rf"{letter}(?:\d{{2}})?", word["text"])]
        require(len(glyphs) == 60,
                f"{name}: expected 60 visible {letter} terms, found {len(glyphs)}")
        require(all(word["yMax"] - word["yMin"] >= 7 for word in glyphs),
                f"{name}: the wide {letter} formula was scaled to unreadable glyphs")
        line_positions = []
        for word in sorted(glyphs, key=position):
            if not line_positions or word["page"] != line_positions[-1][0] \
                    or abs(word["yMin"] - line_positions[-1][1]) > 2:
                line_positions.append(position(word))
        require(len(line_positions) >= 2,
                f"{name}: the wide {letter} formula did not wrap onto multiple lines")

        for word in glyphs:
            page_words = [other for other in words if other["page"] == word["page"]]
            left_edges = [other["xMin"] for other in page_words if other["text"] == "Aussage"]
            right_edges = [other["xMin"] for other in page_words if other["text"] == "Verweis"]
            require(left_edges and right_edges,
                    f"{name}: formula page {word['page']} has no table column headers")
            require(min(left_edges) - .5 <= word["xMin"]
                    and word["xMax"] <= min(right_edges) - 1,
                    f"{name}: a {letter} term exceeds the formula column on page {word['page']}")


def check_table_page_headers(name: str, output: Path) -> dict[int, str]:
    """Catch a final table row shipped to a new page without its longtable head."""
    pages = {}
    for number, page in enumerate(PdfReader(output / f"{name}.pdf").pages, 1):
        content = page.get_contents()
        if content is None:
            continue
        tags = [str(operands[0]) for operands, operator in content.operations
                if operator in (b"BDC", b"BMC") and operands
                and str(operands[0]) in {"/ProofReferenceHeader", "/ProofReferenceCell"}]
        if not tags:
            continue
        require(tags[0] == "/ProofReferenceHeader",
                f"{name}: PDF page {number} starts with a reference cell without its table header")
        text = compact(unicodedata.normalize("NFKC", page.extract_text() or ""))
        require("VerwendeteSätzeundDefinitionen" in text,
                f"{name}: PDF page {number} has header tags but no visible reference-table title")
        pages[number] = text
    return pages


def check_table_tail(text: str, table_pages: dict[int, str]) -> None:
    normalized = compact(text)
    expected = [f"{number:02}" for number in range(25)]
    for prefix in ("TEST", "TAILCASE", "AFTERTEST"):
        # Keep the separator before a page footer: joining whitespace could
        # turn AFTERTEST00 followed by page 1 into the different token 001.
        found = re.findall(rf"(?<![A-Z]){prefix}(\d{{2}})(?!\d)", text)
        require(sorted(found) == expected,
                f"table-tail: {prefix} markers are missing or duplicated")
    fillers = re.findall(r"P(\d+)→Q\1(?!\d)", normalized)
    require(sorted(map(int, fillers)) == sorted(list(range(1, 21)) * 25),
            "table-tail: the twenty short rows preceding each final formula are incomplete")
    for number in expected:
        marker = f"TAILCASE{number}"
        matches = [(page, content) for page, content in table_pages.items() if marker in content]
        require(len(matches) == 1,
                f"table-tail: {marker} is not on exactly one page with a table header")
        page, content = matches[0]
        before_marker = content.split(marker)[0]
        require(all(before_marker.count(part) == count for part, count in
                    (("¬P", 2), ("a,fallsP", 1), ("b,falls¬P", 1), ("=b", 1))),
                f"table-tail: {marker} on page {page} lost part of its final cases formula")


def check_graphics_scopes(reader: PdfReader) -> None:
    """Each cell must restore PDF scale/rotation, color and its q/Q stack."""
    checked = 0
    for number, page in enumerate(reader.pages, 1):
        state = {"matrix": (1., 0., 0., 1., 0., 0.),
                 "fill": (0., 0., 0.), "stroke": (0., 0., 0.)}
        saved, marked = [], []
        content = page.get_contents()
        if content is None:
            continue
        for operands, operator in content.operations:
            if operator == b"q":
                saved.append(state.copy())
            elif operator == b"Q":
                require(bool(saved), f"graphics-state: unmatched Q on page {number}")
                state = saved.pop()
            elif operator == b"cm":
                a, b, c, d, e, f = state["matrix"]
                aa, bb, cc, dd, ee, ff = map(float, operands)
                state["matrix"] = (a * aa + c * bb, b * aa + d * bb,
                                   a * cc + c * dd, b * cc + d * dd,
                                   a * ee + c * ff + e, b * ee + d * ff + f)
            elif operator in (b"g", b"G", b"rg", b"RG", b"k", b"K"):
                values = tuple(map(float, operands))
                if operator.lower() == b"g":
                    rgb = values * 3
                elif operator.lower() == b"rg":
                    rgb = values
                else:
                    rgb = tuple(1 - min(1, channel + values[3]) for channel in values[:3])
                state["fill" if operator.islower() else "stroke"] = rgb
            elif operator in (b"BDC", b"BMC"):
                marked.append((str(operands[0]), state.copy(), len(saved)))
            elif operator == b"EMC":
                require(bool(marked), f"graphics-state: unmatched EMC on page {number}")
                tag, initial, depth = marked.pop()
                if tag not in {"/ProofReferenceCell", "/ProofReferenceHeader"}:
                    continue
                checked += 1
                require(len(saved) == depth,
                        f"graphics-state: q/Q scope escapes {tag} on page {number}")
                for key, expected in initial.items():
                    # LuaTeX may defer cancelling an origin translation until
                    # the next glyph. Its linear transform must already be
                    # restored here; actual glyph positions are checked below.
                    values = state[key][:4] if key == "matrix" else state[key]
                    expected = expected[:4] if key == "matrix" else expected
                    require(all(abs(a - b) < 1e-6 for a, b in zip(values, expected)),
                            f"graphics-state: {key} leaks out of {tag} on page {number}")
        require(not saved and not marked,
                f"graphics-state: unclosed graphics or marked-content scope on page {number}")
    require(checked >= 16, "graphics-state: expected marked formula and reference cells")


def check_graphics_layout(name: str, output: Path) -> None:
    global LAYOUT_AUDITOR
    reader = PdfReader(output / f"{name}.pdf")
    check_graphics_scopes(reader)
    # Content-stream extraction preserves text order even inside rotated boxes.
    text = compact(unicodedata.normalize("NFKC", "\n".join(page.extract_text() or "" for page in reader.pages)))
    for marker in GRAPHICS_MARKERS:
        require(text.count(marker) == 1,
                f"graphics-state: {marker} was lost or duplicated")
    for prefix in ("SCALED", "ROTATED"):
        formula = text.split(prefix + "BEGIN")[1].split(prefix + "END")[0]
        rows = "".join(f"X{i}=Y{i}+{prefix}ROW{suffix}"
                       for i, suffix in enumerate(("ONE", "TWO", "THREE"), 1))
        # The TeX symbol font's ToUnicode map may expose vdash as either of
        # these turnstiles; all other decoded formula content must match exactly.
        require(re.fullmatch(re.escape("U(M)∧{a,b}∈M") + "[⊢⊣]" + re.escape(rows), formula) is not None,
                f"graphics-state: {prefix} lost or changed its premises/conclusions")
    require(text.split("COLORBEGIN")[1].split("COLOREND")[0]
            == "∨".join(f"C{i:02}" for i in range(1, 25)),
            "graphics-state: the colored formula lost or changed a term/operator")
    for number in range(1, 73):
        require(f"LINKROW{number:02}=A{number}" in text,
                f"graphics-state: linked context row {number} lost its formula")
    subtypes = dict(line.split("\t") for line in
                    (output / f"{name}.graphics.tsv").read_text(encoding="utf-8").splitlines())
    for subtype in ("pdf_save", "pdf_setmatrix", "pdf_restore", "pdf_colorstack",
                    "pdf_start_link", "pdf_end_link"):
        require(int(subtypes.get(subtype, "0")) > 0,
                f"graphics-state: the fixture did not exercise {subtype} nodes")

    result = subprocess.run(["pdftotext", "-bbox", str(output / f"{name}.pdf"), "-"],
                            capture_output=True, check=True, timeout=30)
    (output / f"{name}.bbox.html").write_bytes(result.stdout)
    document = ET.fromstring(result.stdout)
    words = []
    for number, page in enumerate(document.findall(".//{*}page"), 1):
        words.extend(dict(text=node.text or "", page=number, **{
            key: float(value) for key, value in node.attrib.items()})
            for node in page.findall(".//{*}word"))

    def unique(marker: str) -> dict:
        matches = [word for word in words if word["text"] == marker]
        require(len(matches) == 1, f"graphics-state: {marker} has no unique visible word box")
        return matches[0]

    control = unique("REFERENCECONTROL")
    normal_height = control["yMax"] - control["yMin"]
    for marker in ("SCALEDFOLLOW", "ROTATEDFOLLOW", "COLORFOLLOW", "LINKFOLLOW"):
        word = unique(marker)
        require(.95 * normal_height <= word["yMax"] - word["yMin"] <= 1.05 * normal_height,
                f"graphics-state: {marker} inherited a scale or rotation")
    references = []
    for number in range(1, len(reader.pages) + 1):
        page_words = [word for word in words if word["page"] == number]
        headers = [word for word in page_words if word["text"] == "Verweis"]
        if not headers:
            continue
        header = headers[0]
        references.extend(word for word in page_words
                          if re.fullmatch(r"91\.10\.[1-8]", word["text"])
                          and word["yMin"] > header["yMax"] - .5
                          and word["xMin"] >= header["xMin"] - .5)
    require({word["text"] for word in references} == {f"91.10.{i}" for i in range(1, 9)},
            "graphics-state: a right-column reference disappeared or moved out of its column")
    require(all(.95 * normal_height <= word["yMax"] - word["yMin"] <= 1.05 * normal_height
                for word in references), "graphics-state: a right-column reference inherited a transform")
    require(max(word["xMin"] for word in references) - min(word["xMin"] for word in references) < 1,
            "graphics-state: right-column reference positions changed after a transformed formula")
    for marker, number in (("SCALEDFOLLOW", 2), ("ROTATEDFOLLOW", 4),
                           ("COLORFOLLOW", 6), ("LINKFOLLOW", 8)):
        following = unique(marker)
        matches = [word for word in references if word["text"] == f"91.10.{number}"]
        require(len(matches) == 1 and matches[0]["page"] == following["page"]
                and abs(matches[0]["yMin"] - following["yMin"]) < 1,
                f"graphics-state: the reference beside {marker} moved to another baseline")
    links = [unique(f"LINKROW{number:02}") for number in range(1, 73)]
    require(len({word["page"] for word in links}) >= 2,
            "graphics-state: a local hyperlink made the whole tall context indivisible")
    require(all(word["yMax"] - word["yMin"] >= .95 * normal_height for word in links),
            "graphics-state: linked context rows were shrunk instead of continuing")
    require(all((a["page"], a["yMin"]) < (b["page"], b["yMin"]) for a, b in zip(links, links[1:])),
            "graphics-state: linked context rows were reordered or overprinted")
    if LAYOUT_AUDITOR is None:
        LAYOUT_AUDITOR = runpy.run_path(str(ROOT / "scripts/check-proof-reference-layout.py"))["audit_pdf"]
    audit = LAYOUT_AUDITOR((str(output / f"{name}.pdf"), .5, False, True))
    (output / f"{name}.layout.json").write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    require(audit["certified"] and not audit["issues"],
            "graphics-state: transformed formula/header objects exceed their marked cells or page text area:\n"
            + json.dumps(audit["issues"][:8], ensure_ascii=True, indent=2))


def check_pdf(name: str, output: Path) -> None:
    result = subprocess.run(["pdftotext", "-layout", str(output / f"{name}.pdf"), "-"],
                            capture_output=True, check=True, timeout=30)
    text = unicodedata.normalize("NFKC", result.stdout.decode("utf-8", errors="replace"))
    (output / f"{name}.pdf.txt").write_text(text, encoding="utf-8")
    heading = "Verwendete Sätze und Definitionen"
    flattened = " ".join(text.split())
    expected_count = (25 if name == "table-tail" else
                      sum(bool(labels) for labels in EXPECTED[name].values()))
    continued = flattened.count(heading + " (Fortsetzung)")
    actual_count = flattened.count(heading) - continued
    if name in {"pagination", "tall-context"}:
        require(continued >= 1 and actual_count == 1,
                f"{name}: long reference table did not continue with repeated headers")
        markers = ([f"PAGEPREMISE{number:02}" for number in range(1, 21)]
                   if name == "pagination" else
                   [f"TALLROW{number:02}" for number in range(1, 45)] +
                   ["TALLCONCLUSIONMARKER", "DECLNOTEMARKER", "PREMNOTEMARKER",
                    "BLOCKTWOMARKER", "BLOCKTHREEMARKER", "BLOCKFOURMARKER", "RAWHEADINGMARKER"])
        for marker in markers:
            require(flattened.count(marker) == 2,
                    f"{name}: {marker} was lost or duplicated across page breaks")
    else:
        require(actual_count == expected_count,
                f"{name}: expected {expected_count} rendered reference tables, "
                f"found {actual_count}")
    for marker in ("Theorem nicht gefunden", "Mehrdeutige Theorem", "??"):
        require(marker not in text, f"{name}: unresolved reference in final PDF: {marker}")
    if name == "core":
        # Check actual placement, independently of the instrumented renderer:
        # both nested tables must have only one overview before the next proof.
        cases = list(EXPECTED[name])
        for index, case in enumerate(cases):
            start = flattened.index(f"CASE {case}")
            end = (flattened.index(f"CASE {cases[index + 1]}", start)
                   if index + 1 < len(cases) else len(flattened))
            chunk = flattened[start:end]
            count = chunk.count(heading) - chunk.count(heading + " (Fortsetzung)")
            require(count == bool(EXPECTED[name][case]),
                    f"core/{case}: reference table is missing, duplicated, or outside its proof")
        require(flattened.count("PREMISEMARKER") == 3,
                "core: premise must appear at declaration and in both referencing proofs")
        require(flattened.count("CLASSICPREMISE") == 2
                and flattened.count("CLASSICCONCLUSION") == 2,
                "core: classical definition's premise/conclusion did not render in its overview")
        for marker in ("CLASSICTHEOREMPREMISE", "CLASSICTHEOREMCONCLUSION",
                       "CLASSICAXIOMPREMISE", "CLASSICAXIOMCONCLUSION"):
            require(flattened.count(marker) == 2,
                    f"core: {marker} did not render in both its declaration and overview")
    elif name == "consumer":
        require("IMPORTEDPREMISE" in text and "IMPORTEDDEFINITION" in text,
                "consumer: original imported assumptions are absent from the PDF")
    elif name == "overflow":
        normalized = compact(text)
        for marker in OVERFLOW_MARKERS:
            require(normalized.count(marker) == 1,
                    f"overflow: {marker} was lost or duplicated in the rendered overview")
        for letter in ("P", "Q"):
            terms = re.findall(rf"{letter}(\d{{2}})(?!\d)", normalized)
            require(sorted(terms) == [f"{number:02}" for number in range(1, 61)],
                    f"overflow: the wide {letter} formula lost or duplicated indexed terms")
        require(continued >= 2,
                "overflow: tall statements must retain continuation headers across pages")
    elif name == "table-tail":
        require(continued >= 1,
                "table-tail: boundary cases no longer exercise a table continuation page")
    final_log = (output / f"{name}.log").read_text(encoding="utf-8", errors="replace")
    require("Overfull \\hbox" not in final_log,
            f"{name}: reference fixture has an overfull line; inspect its PDF and log")
    require("Overfull \\vbox" not in final_log,
            f"{name}: a reference context exceeds the page height")
    require("Missing character:" not in final_log,
            f"{name}: a reference fixture lost glyphs")
    if name == "tall-context":
        check_context_layout(name, output)
    elif name == "overflow":
        check_overflow_layout(name, output)
    elif name == "graphics-state":
        check_graphics_layout(name, output)
    table_pages = check_table_page_headers(name, output)
    require(bool(table_pages) == bool(expected_count),
            f"{name}: PDF reference-table tags do not match its expected proof overviews")
    if name == "table-tail":
        check_table_tail(text, table_pages)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT,
                        help="Directory for isolated PDF, registry and audit output")
    args = parser.parse_args()
    for executable in ("lualatex", "pdftotext"):
        require(shutil.which(executable) is not None, f"Required program unavailable: {executable}")
    require(find_spec("pdfplumber") is not None, "Required Python package unavailable: pdfplumber")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for name in ("core", "producer", "consumer", "pagination", "tall-context", "overflow", "table-tail", "graphics-state"):
        build(name, output)
        check_events(name, output)
        check_pdf(name, output)
        print(f"PASS {name}: two builds, reference contents, order and rendered PDF")
    print(f"Proof-reference integration checks passed. Output: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
