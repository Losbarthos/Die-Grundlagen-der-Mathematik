"""Prepare and audit the Dedekind recursion companions and their public B10 result.

These checks establish document integrity and reference ownership, not a
machine verification of the mathematical inference rules.
"""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/dedekind"
MAIN_ID = "DedekindRecursionTheorem"
PRIVATE_IDS = {"RecCoreLeastAdmissible", "RecCoreStageBarrier", "RecCoreStageUnique"}
# The original active construction has 26 declarations and 18 registered
# subsidiary results. The five theorems inside an existing \iffalse block
# are inactive and deliberately do not appear in the registry.
EXPECTED_LABELS = {
    *(f"ax:auto:10E.1.1.{i}" for i in range(1, 4)),
    *(f"def:auto:10E.1.1.{i}" for i in range(1, 5)),
    *(f"thm:auto:10E.1.1.{i}" for i in range(1, 20)),
    *(f"thm:pp:10E.1.1.{parent}:{i}"
      for parent, count in ((1, 3), (2, 3), (3, 2), (11, 6), (14, 2), (18, 2))
      for i in range(1, count + 1)),
}


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def id_map(rows):
    return {row[1]: row[3] for row in rows if row[0] == "ID"}


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def aux_labels(path):
    group = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))["group"]
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if not match:
            continue
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


def write_import(name, rows, aux_text):
    labels = {row_label(row) for row in rows}
    (DIRECTORY / (name + ".registry.tsv")).write_text(
        "".join("\t".join(row) + "\n" for row in rows), encoding="utf-8"
    )
    lines = []
    for line in aux_text.splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            lines.append(line)
    target = DIRECTORY / (name + ".aux")
    target.write_text("\\relax\n" + "\n".join(lines) + "\n", encoding="utf-8")
    if missing := labels - set(aux_labels(target)):
        raise ValueError(f"{name}: missing imported AUX labels: {sorted(missing)}")


def main_records():
    rows = registry(ROOT / "registry/_B10.registry.tsv")
    identifiers = id_map(rows)
    if MAIN_ID not in identifiers:
        raise ValueError("B10: missing public Dedekind recursion theorem")
    if misplaced := PRIVATE_IDS & set(identifiers):
        raise ValueError(f"B10: private construction results remain in the main volume: {sorted(misplaced)}")
    return rows, identifiers


def proof_records():
    base = DIRECTORY / "_B10-dedekind-proofs"
    rows = registry(base.with_suffix(".registry.tsv"))
    identifiers = id_map(rows)
    labels = {row_label(row) for row in rows}
    if labels != EXPECTED_LABELS:
        raise ValueError(f"proofs: unexpected or missing construction labels: {sorted(labels ^ EXPECTED_LABELS)}")
    if len(rows) != 50 or len(identifiers) != 6 or not PRIVATE_IDS <= set(identifiers):
        raise ValueError("proofs: expected 44 structural records and six ID records, including the three private theorem IDs")
    if Counter(row[2] for row in rows if row[0] == "ID") != Counter(definition=3, theorem=3):
        raise ValueError("proofs: unexpected identity kinds")
    if MAIN_ID in identifiers:
        raise ValueError("proofs: public theorem must remain owned by B10")
    aux = aux_labels(base.with_suffix(".aux"))
    for row in rows:
        label = row_label(row)
        if label not in aux or not aux[label][0].startswith("10E."):
            raise ValueError(f"proofs: missing or non-companion number for {label}")
        if row[0] != "ID" and row[3] != aux[label][0]:
            raise ValueError(f"proofs: registry and AUX numbers disagree for {label}")
    return rows, identifiers, aux


def prepare():
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows, identifiers = main_records()
    aux_path = ROOT / "registry/_B10.aux"
    aux_text = aux_path.read_text(encoding="utf-8-sig")
    for name in ("b10-external", "b10-reading"):
        write_import(name, rows, aux_text)
    (DIRECTORY / "position.tex").write_text(
        "% Generated independent companion numbering; do not edit.\n"
        "\\renewcommand{\\FormulaBandID}{10E}\n"
        "\\setcounter{file}{10}\n"
        "\\setcounter{chapter}{0}\n"
        "\\setcounter{section}{0}\n"
        "\\setcounter{subsection}{0}\n"
        "\\setcounter{formulaDef}{0}\n"
        "\\setcounter{formulaThm}{0}\n", encoding="utf-8"
    )
    print("Dedekind imports prepared; canonical main theorem: "
          + aux_labels(aux_path)[identifiers[MAIN_ID]][0])


def assert_disjoint(main, main_ids, proof, proof_ids):
    if set(proof_ids) & set(main_ids) or {row_label(row) for row in proof} & {row_label(row) for row in main}:
        raise ValueError("proofs: local identities or labels overlap B10")


def prepare_reading():
    rows, identifiers, _ = proof_records()
    main, main_ids = main_records()
    assert_disjoint(main, main_ids, rows, identifiers)
    write_import("proofs-reading", rows,
                 (DIRECTORY / "_B10-dedekind-proofs.aux").read_text(encoding="utf-8-sig"))
    print("Dedekind reading imports prepared from 44 canonical companion statements.")


def audit():
    from pypdf import PdfReader

    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    canonical, canonical_ids = main_records()
    canonical_aux = aux_labels(ROOT / "registry/_B10.aux")
    proof_rows, proof_ids, proof_aux = proof_records()
    assert_disjoint(canonical, canonical_ids, proof_rows, proof_ids)
    for name, expected in (("b10-external", canonical), ("b10-reading", canonical),
                           ("proofs-reading", proof_rows)):
        if Counter(map(tuple, registry(DIRECTORY / (name + ".registry.tsv")))) != Counter(map(tuple, expected)):
            raise ValueError(f"{name}: stale or incomplete canonical registry import")
        expected_aux = proof_aux if name == "proofs-reading" else canonical_aux
        imported_aux = aux_labels(DIRECTORY / (name + ".aux"))
        for label in {row_label(row) for row in expected}:
            if imported_aux.get(label) != expected_aux.get(label):
                raise ValueError(f"{name}: stale or incomplete AUX import for {label}")
    cache = {}
    main_pdf = ROOT / "registry/_B10.pdf"
    theorem_anchor = canonical_aux[canonical_ids[MAIN_ID]][1]
    for edition in ("reading", "proofs"):
        base = DIRECTORY / f"_B10-dedekind-{edition}"
        rows = registry(base.with_suffix(".registry.tsv"))
        expected_rows = Counter(map(tuple, proof_rows)) if edition == "proofs" else Counter()
        if Counter(map(tuple, rows)) != expected_rows:
            raise ValueError(f"{edition}: unexpected local registry records")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        destinations = set(reader.named_destinations)
        expected_targets = {f"dedekind.{edition}"}
        if edition == "proofs":
            expected_targets.add("dedekind.proof")
            expected_targets.update(proof_aux[label][1] for label in EXPECTED_LABELS)
        if missing := expected_targets - destinations:
            raise ValueError(f"{edition}: PDF targets missing: {sorted(missing)}")
        companion = "proofs" if edition == "reading" else "reading"
        companion_target = (DIRECTORY / f"_B10-dedekind-{companion}.pdf").resolve()
        companion_link = main_link = False
        for action in publisher["remote_actions"](reader):
            target = (pdf.parent / publisher["file_name"](action)).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():
                raise ValueError(f"{edition}: missing/outside build target: {target}")
            if target not in cache:
                cache[target] = set(PdfReader(target).named_destinations)
            destination = str(action.get("/D"))
            if destination not in cache[target]:
                raise ValueError(f"{edition}: remote destination missing: {target}, {destination}")
            companion_link |= target == companion_target and destination == f"dedekind.{companion}"
            main_link |= target == main_pdf.resolve() and destination == theorem_anchor
        if not companion_link or not main_link:
            raise ValueError(f"{edition}: missing navigation to companion edition or canonical B10 theorem")
        print(f"Dedekind {edition}: {len({row_label(row) for row in rows})} local statements; "
              f"ownership, numbering, PDF targets and links passed ({len(reader.pages)} pages).")

    main_reader = PdfReader(main_pdf)
    if theorem_anchor not in main_reader.named_destinations:
        raise ValueError("B10: public Dedekind theorem target missing")
    proof_target = (DIRECTORY / "_B10-dedekind-proofs.pdf").resolve()
    actual_proof_links = {
        str(action.get("/D")) for action in publisher["remote_actions"](main_reader)
        if (main_pdf.parent / publisher["file_name"](action)).resolve() == proof_target
    }
    if "dedekind.proof" not in actual_proof_links:
        raise ValueError("B10: direct statement-to-proof link missing")
    theorem_page = main_reader.get_destination_page_number(main_reader.named_destinations[theorem_anchor])
    if theorem_page is None or not 0 <= theorem_page < len(main_reader.pages):
        raise ValueError("B10: main theorem target has no valid page")
    linked_editions = set()
    edition_targets = {
        ((DIRECTORY / f"_B10-dedekind-{edition}.pdf").resolve(), f"dedekind.{edition}"): edition
        for edition in ("reading", "proofs")
    }
    for annotation in main_reader.pages[theorem_page].get("/Annots", []):
        action = annotation.get_object().get("/A")
        if action is None:
            continue
        action = action.get_object()
        if action.get("/S") == "/GoToR":
            key = ((main_pdf.parent / publisher["file_name"](action)).resolve(), str(action.get("/D")))
            if key in edition_targets:
                linked_editions.add(edition_targets[key])
    if missing := {"reading", "proofs"} - linked_editions:
        raise ValueError(f"B10: theorem page {theorem_page + 1} lacks companion links: {sorted(missing)}")
    print(f"Dedekind main volume: public theorem retained, construction externalized; "
          f"both companion links on theorem page {theorem_page + 1}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "prepare-reading", "audit"))
    args = parser.parse_args()
    {"prepare": prepare, "prepare-reading": prepare_reading, "audit": audit}[args.mode]()
