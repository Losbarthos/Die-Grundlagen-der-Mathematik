"""Prepare isolated CSB editions and audit them against the canonical volumes.

Run from the repository root through build-csb-pilot.ps1. This checks document
identity and links, not the mathematical validity of inference rules.
"""
from __future__ import annotations

import argparse
import re
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/csb"
MAIN_IDS = (
    "CantorBernsteinPartDef", "CantorBernsteinPartSubset",
    "CantorBernsteinPartContainsSeed", "CantorBernsteinPartMinimal",
    "CantorBernsteinPartClosed", "CantorBernsteinPartFixedPoint",
    "CantorBernsteinComplementIdentity", "CantorBernsteinSecondBranchImage",
    "CantorBernsteinFixedInjections",
)
HELPER_IDS = (
    "CantorBernsteinPartClosedUniversal", "CantorBernsteinComplementForward",
    "CantorBernsteinComplementBackward",
)
APPLICATION_IDS = (
    "CardLeqDef", "Gleichmächtigkeit", "CantorSchroederBernstein",
    "EqCardMutualCardLeqEquiv",
)


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def id_map(rows):
    return {row[1]: row[3] for row in rows if row[0] == "ID"}


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def aux_labels(path):
    # Titles may contain nested TeX groups, so a flat regex is insufficient.
    group = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))["group"]
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match:
            outer, _ = group(line, match.end())
            if not outer:
                continue
            position, fields = outer[0], []
            while position < outer[1]:
                value, position = group(line, position)
                if not value:
                    break
                fields.append(line[value[0]:value[1]])
            if len(fields) >= 4:
                result[match[1]] = (fields[0].strip(), fields[3])
    return result


def write_import(band, name, labels, rows):
    selected = [row for row in rows if row_label(row) in labels]
    (DIRECTORY / (name + ".registry.tsv")).write_text(
        "".join("\t".join(row) + "\n" for row in selected), encoding="utf-8"
    )
    lines = []
    for line in (ROOT / f"registry/_{band}.aux").read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            lines.append(line)
    (DIRECTORY / (name + ".aux")).write_text("\\relax\n" + "\n".join(lines) + "\n", encoding="utf-8")
    missing = labels - set(aux_labels(DIRECTORY / (name + ".aux")))
    if missing:
        raise ValueError(f"{band}: missing imported AUX labels: {sorted(missing)}")


def prepare():
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows = registry(ROOT / "registry/_B08.registry.tsv")
    identifiers = id_map(rows)
    local_labels = {identifiers[key] for key in MAIN_IDS + HELPER_IDS}
    all_labels = {row_label(row) for row in rows}
    external_labels = all_labels - local_labels
    write_import("B08", "b08-external", external_labels, rows)
    # The prose edition declares no results itself; every B08 reference is external.
    write_import("B08", "b08-reading", all_labels, rows)
    application = registry(ROOT / "registry/_B11.registry.tsv")
    application_map = id_map(application)
    write_import("B11", "b11-application", {application_map[key] for key in APPLICATION_IDS}, application)
    label = identifiers[MAIN_IDS[-1]]
    printed = aux_labels(ROOT / "registry/_B08.aux")[label][0]
    band, chapter, section, _ = map(int, printed.split("."))
    (DIRECTORY / "position.tex").write_text(
        "% Generated from the canonical B08 AUX; do not edit.\n"
        f"\\renewcommand{{\\FormulaBandID}}{{{band}}}\n"
        f"\\setcounter{{file}}{{{band}}}\n"
        f"\\setcounter{{chapter}}{{{chapter}}}\n"
        f"\\setcounter{{section}}{{{section - 1}}}\n", encoding="utf-8"
    )
    print("CSB imports prepared; canonical main theorem: " + printed)


def audit():
    from pypdf import PdfReader

    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    canonical = registry(ROOT / "registry/_B08.registry.tsv")
    canonical_ids = id_map(canonical)
    canonical_aux = aux_labels(ROOT / "registry/_B08.aux")
    helper_targets = {f"csb.helper.{key}" for key in HELPER_IDS}
    for edition in ("reading", "proofs"):
        base = DIRECTORY / f"_B08-csb-{edition}"
        rows = registry(base.with_suffix(".registry.tsv"))
        identifiers = id_map(rows)
        expected_ids = MAIN_IDS + HELPER_IDS if edition == "proofs" else ()
        expected_labels = {canonical_ids[key] for key in expected_ids}
        if set(identifiers) != set(expected_ids):
            raise ValueError(f"{edition}: unexpected/missing result identities: {set(identifiers) ^ set(expected_ids)}")
        expected_rows = {tuple(row) for row in canonical if row_label(row) in expected_labels}
        if {tuple(row) for row in rows} != expected_rows:
            raise ValueError(f"{edition}: statements, contexts or registry records differ from B08")
        labels = aux_labels(base.with_suffix(".aux"))
        for key in expected_ids:
            label = canonical_ids[key]
            if identifiers[key] != label or labels.get(label, (None,))[0] != canonical_aux[label][0]:
                raise ValueError(f"{edition}: inconsistent label/number for {key}")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        destinations = set(reader.named_destinations)
        if f"csb.{edition}" not in destinations:
            raise ValueError(f"{edition}: edition entry target missing from PDF")
        if edition == "reading":
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            forbidden_text = (
                ("Zur Benutzung", r"\bZur\s+Benutzung\b"),
                ("Aussagen zum Lesebeweis", r"\bAussagen\s+zum\s+Lesebeweis\b"),
                ("Aussagen und tabellarische Ableitungen", r"\bAussagen\s+und\s+tabellarische\s+Ableitungen\b"),
                ("Ableitungsnachweise", r"\bAbleitungsnachweise\b"),
                ("Lesebeweis", r"\bLesebeweis\b"),
            )
            for heading, pattern in forbidden_text:
                if re.search(pattern, text, re.IGNORECASE):
                    raise ValueError(f"reading: removed section or label {heading!r} is still present")
        elif missing := helper_targets - destinations:
            raise ValueError(f"proofs: semantic helper targets missing from PDF: {sorted(missing)}")
        for key in expected_ids:
            if labels[canonical_ids[key]][1] not in destinations:
                raise ValueError(f"{edition}: result target missing from PDF: {key}")
        cache = {}
        companion = "proofs" if edition == "reading" else "reading"
        companion_target = DIRECTORY / f"_B08-csb-{companion}.pdf"
        companion_links = 0
        for action in publisher["remote_actions"](reader):
            target = (pdf.parent / publisher["file_name"](action)).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():
                raise ValueError(f"{edition}: missing/outside build target: {target}")
            if target not in cache:
                cache[target] = set(PdfReader(target).named_destinations)
            if str(action.get("/D")) not in cache[target]:
                raise ValueError(f"{edition}: remote destination missing: {target}, {action.get('/D')}")
            if target == companion_target and str(action.get("/D")) == f"csb.{companion}":
                companion_links += 1
        if not companion_links:
            raise ValueError(f"{edition}: missing navigation to companion edition")
        if edition == "reading":
            print(f"CSB reading: no local declarations or removed formal sections, entry target and PDF links passed ({len(reader.pages)} pages).")
        else:
            print(f"CSB {edition}: {len(expected_ids)} identities, exact declarations, numbers and PDF links passed ({len(reader.pages)} pages).")

    main_pdf = ROOT / "registry/_B08.pdf"
    main_reader = PdfReader(main_pdf)
    proof_pdf = (DIRECTORY / "_B08-csb-proofs.pdf").resolve()
    linked_helpers = set()
    for action in publisher["remote_actions"](main_reader):
        target = (main_pdf.parent / publisher["file_name"](action)).resolve()
        destination = str(action.get("/D"))
        if target == proof_pdf and destination in helper_targets:
            linked_helpers.add(destination)
    if missing := helper_targets - linked_helpers:
        raise ValueError(f"B08: direct remote links to proof helper targets missing: {sorted(missing)}")

    theorem_anchor = canonical_aux[canonical_ids[MAIN_IDS[-1]]][1]
    theorem_destination = main_reader.named_destinations.get(theorem_anchor)
    if theorem_destination is None:
        raise ValueError(f"B08: main theorem PDF target missing: {theorem_anchor}")
    theorem_page = main_reader.get_destination_page_number(theorem_destination)
    if theorem_page is None or not 0 <= theorem_page < len(main_reader.pages):
        raise ValueError(f"B08: main theorem target has no valid page: {theorem_anchor}")
    edition_targets = {
        edition: ((DIRECTORY / f"_B08-csb-{edition}.pdf").resolve(), f"csb.{edition}")
        for edition in ("reading", "proofs")
    }
    linked_editions = set()
    for annotation in main_reader.pages[theorem_page].get("/Annots", []):
        action = annotation.get_object().get("/A")
        if action is None:
            continue
        action = action.get_object()
        if action.get("/S") != "/GoToR":
            continue
        target = (main_pdf.parent / publisher["file_name"](action)).resolve()
        destination = str(action.get("/D"))
        for edition, expected in edition_targets.items():
            if (target, destination) == expected:
                linked_editions.add(edition)
    if missing := set(edition_targets) - linked_editions:
        raise ValueError(f"B08: main theorem page {theorem_page + 1} lacks proof links: {sorted(missing)}")
    print(f"CSB main theorem: both companion links present on B08 page {theorem_page + 1}.")
    print("CSB separation: 3 semantic helper targets and direct B08 links passed; reading contains no local formal declarations or removed sections.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "audit"))
    args = parser.parse_args()
    {"prepare": prepare, "audit": audit}[args.mode]()
