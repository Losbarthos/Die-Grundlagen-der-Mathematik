"""Generate B28's coordinate-map companion from its unchanged canonical section."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/e-coordinates"
SOURCE = ROOT / "Bd. 28 - Halbgruppen.tex"
JOB = "_B28-e-coordinates"
START = r"\section{Koordinatenisomorphismen von Halbgruppen}"
END = r"\section{Morphismen von Potenzhalbgruppen}"
HELPERS = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def source_section():
    text = SOURCE.read_text(encoding="utf-8-sig")
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError("The coordinate section boundaries must be unique")
    start, end = text.index(START), text.index(END)
    if end <= start:
        raise ValueError("The coordinate section boundaries are reversed")
    return text[start:end]


def records():
    section = source_section()
    masked = HELPERS["mask_comments"](section)
    ids = []
    for match in re.finditer(r"\\Formula(?:Thm|Def|Axiom)DeltaK\b", masked):
        declaration = HELPERS["call"](masked, match.start(), 3)
        ids.append(masked[slice(*declaration.args[1])].strip())
    if len(ids) != len(set(ids)) or not ids:
        raise ValueError("The coordinate section needs unique statement IDs")
    rows = registry(ROOT / "registry/_B28.registry.tsv")
    canonical_ids = {row[1]: row[3] for row in rows if row[0] == "ID"}
    if missing := set(ids) - canonical_ids.keys():
        raise ValueError(f"Rebuild B28 first; missing coordinate statements: {sorted(missing)}")
    labels = {canonical_ids[key] for key in ids}
    local = [row for row in rows if row_label(row) in labels]
    external = [row for row in rows if row_label(row) not in labels]
    prefixes = {tuple(row[4].split(".")[:-1]) for row in local if row[0] == "ID"}
    if len(prefixes) != 1:
        raise ValueError("The companion must contain exactly one canonical numbered section")
    band, chapter, number = next(iter(prefixes))
    if band != "28":
        raise ValueError("The coordinate statements must remain in B28")
    counters = (f"\\setcounter{{chapter}}{{{int(chapter)}}}\n"
                f"\\setcounter{{section}}{{{int(number) - 1}}}\n")
    return section, counters, ids, labels, local, external


def aux_lines(path):
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match:
            if match[1] in result:
                raise ValueError(f"Duplicate AUX label: {match[1]}")
            result[match[1]] = line
    return result


def aux_number(line):
    first = re.match(r"\\newlabel\{[^}]+\}", line)
    outer, _ = HELPERS["group"](line, first.end())
    number, _ = HELPERS["group"](line, outer[0])
    return line[slice(*number)]


def expected_files():
    section, counters, ids, labels, local, external = records()
    canonical_aux = aux_lines(ROOT / "registry/_B28.aux")
    imported_labels = {row_label(row) for row in external}
    if missing := imported_labels - canonical_aux.keys():
        raise ValueError(f"Incomplete B28 AUX: {sorted(missing)}")
    return {
        "section.tex": "% Generated from the canonical B28 section; edit B28, not this file.\n" + counters + section,
        "b28-external.registry.tsv": "".join("\t".join(row) + "\n" for row in external),
        "b28-external.aux": "\\relax\n" + "\n".join(line for label, line in canonical_aux.items()
                                                       if label in imported_labels) + "\n",
    }


def prepare():
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    for name, content in expected_files().items():
        target = DIRECTORY / name
        if not target.exists() or target.read_text(encoding="utf-8") != content:
            target.write_text(content, encoding="utf-8")
    print(f"Coordinate companion prepared from B28: {len(records()[2])} unchanged statements.")


def audit():
    from pypdf import PdfReader
    for name, expected in expected_files().items():
        if (DIRECTORY / name).read_text(encoding="utf-8") != expected:
            raise ValueError(f"Stale generated coordinate input: {name}")
    _, _, ids, labels, local, _ = records()
    base = DIRECTORY / JOB
    current = registry(base.with_suffix(".registry.tsv"))
    if Counter(map(tuple, current)) != Counter(map(tuple, local)):
        raise ValueError("Coordinate statement identities, formulas, premises or numbering differ from B28")
    actual_aux = aux_lines(base.with_suffix(".aux"))
    canonical_aux = aux_lines(ROOT / "registry/_B28.aux")
    for label in labels:
        if label not in actual_aux or aux_number(actual_aux[label]) != aux_number(canonical_aux[label]):
            raise ValueError(f"Coordinate companion numbering differs from B28: {label}")
    pdf = base.with_suffix(".pdf")
    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    reader = PdfReader(pdf)
    publisher["assert_build_ready"](pdf, reader)
    publisher["audit"]([pdf], root=ROOT)
    report = {"statements": len(ids), "pages": len(reader.pages), "source": SOURCE.name,
              "canonical_registry_matches": True, "numbering_matches": True,
              "generated_section_unchanged": True, "links_passed": True}
    (DIRECTORY / "audit.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Coordinate companion passed: {len(ids)} unchanged statements, {len(reader.pages)} pages.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "audit"))
    args = parser.parse_args()
    {"prepare": prepare, "audit": audit}[args.command]()
