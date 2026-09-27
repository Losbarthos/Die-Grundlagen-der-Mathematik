"""Prepare and audit the bracketing companions and their canonical B28 theorem.

The checks establish declaration identities, original numbering, isolated
registries and working PDF navigation; they do not verify inference rules.
"""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/bracketing"
NUMBERS = {
    "SemigroupWordBlockBase": "28.2.2.1",
    "SemigroupWordBlockStep": "28.2.2.2",
    "SemigroupWordBlockLaw": "28.2.2.3",
    "SemigroupTreeNormalFormLeaf": "28.2.3.1",
    "SemigroupTreeNormalFormNode": "28.2.3.2",
    "SemigroupTreeNormalForm": "28.2.3.3",
    "SemigroupBracketingIndependence": "28.2.3.4",
}
SECTIONS = {
    "SemigroupWordBlockLaw": "block",
    "SemigroupTreeNormalForm": "normal",
    "SemigroupBracketingIndependence": "independence",
}
EXPECTED_LABELS = {"thm:auto:" + number for number in NUMBERS.values()}
MAIN_ID = "SemigroupBracketingIndependence"
MAIN_LABEL = "thm:auto:" + NUMBERS[MAIN_ID]
MAIN_RESULT_TARGET = "section*.13"
PROOF_IDS = set(NUMBERS) - {MAIN_ID}
PROOF_LABELS = EXPECTED_LABELS - {MAIN_LABEL}
MAIN_TARGET = "bracketing.notation"
FINAL_PROOF_TARGET = "bracketing.proof.independence"


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def id_map(rows):
    identifiers = [row[1] for row in rows if row[0] == "ID"]
    if duplicates := [key for key, count in Counter(identifiers).items() if count != 1]:
        raise ValueError(f"duplicate local result identities: {duplicates}")
    return {row[1]: row[3] for row in rows if row[0] == "ID"}


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def aux_labels(path):
    # AUX titles contain nested groups; use the shared balanced TeX reader.
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


def check_numbers(rows, identifiers, aux, expected_ids, owner):
    for key in expected_ids:
        label = "thm:auto:" + NUMBERS[key]
        if identifiers.get(key) != label or aux.get(label, (None,))[0] != NUMBERS[key]:
            raise ValueError(f"{owner}: original label/number changed for {key}")
    for row in rows:
        if row_label(row) not in EXPECTED_LABELS:
            continue
        if row[2] != "theorem":
            raise ValueError(f"{owner}: unexpected declaration kind: {row}")
        if row[0] != "ID" and row[3] != aux[row_label(row)][0]:
            raise ValueError(f"{owner}: registry/AUX number disagreement: {row_label(row)}")


def main_records():
    rows = registry(ROOT / "registry/_B28.registry.tsv")
    identifiers = id_map(rows)
    if set(identifiers) & set(NUMBERS) != {MAIN_ID}:
        raise ValueError("B28 must own exactly the bracketing-independence theorem")
    labels = {row_label(row) for row in rows}
    if labels & EXPECTED_LABELS != {MAIN_LABEL}:
        raise ValueError("B28 must contain exactly the canonical main theorem label")
    aux = aux_labels(ROOT / "registry/_B28.aux")
    if set(aux) & EXPECTED_LABELS != {MAIN_LABEL}:
        raise ValueError("B28 AUX must contain only the canonical main theorem label")
    check_numbers(rows, identifiers, aux, {MAIN_ID}, "B28")
    if aux[MAIN_LABEL][1] != MAIN_RESULT_TARGET:
        raise ValueError("B28: published main theorem destination changed")
    return rows, identifiers, aux


def proof_records():
    base = DIRECTORY / "_B28-bracketing-proofs"
    rows = registry(base.with_suffix(".registry.tsv"))
    identifiers = id_map(rows)
    if set(identifiers) != PROOF_IDS:
        raise ValueError(f"proofs: unexpected/missing identities: {set(identifiers) ^ PROOF_IDS}")
    if {row_label(row) for row in rows} != PROOF_LABELS:
        raise ValueError("proofs: unexpected or missing local result labels")
    aux = aux_labels(base.with_suffix(".aux"))
    if MAIN_LABEL in aux:
        raise ValueError("proofs: the main theorem must be referenced, not declared again")
    check_numbers(rows, identifiers, aux, PROOF_IDS, "proofs")
    main, main_ids, _ = main_records()
    if set(identifiers) & set(main_ids) or {row_label(row) for row in main} & PROOF_LABELS:
        raise ValueError("proofs: result identities and labels must be disjoint from B28")
    proof_formulas = {row[5] for row in rows if row[0] != "ID"}
    if any(row[0] != "ID" and row[2] == "theorem" and row[5] in proof_formulas for row in main):
        raise ValueError("B28: a proof theorem is duplicated under another result identity")
    return rows, identifiers, aux


def prepare():
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows, _, _ = main_records()
    aux_text = (ROOT / "registry/_B28.aux").read_text(encoding="utf-8-sig")
    write_import("b28-external", rows, aux_text)
    write_import("b28-reading", rows, aux_text)
    (DIRECTORY / "position.tex").write_text(
        "% Generated original theorem positions; do not edit.\n"
        "\\renewcommand{\\FormulaBandID}{28}\n"
        "\\setcounter{file}{28}\n"
        "\\setcounter{chapter}{2}\n"
        "\\setcounter{section}{1}\n"
        "\\setcounter{subsection}{0}\n"
        "\\setcounter{formulaDef}{0}\n"
        "\\setcounter{formulaThm}{0}\n", encoding="utf-8"
    )
    print("Bracketing imports prepared; both companions import the canonical B28 main theorem.")


def prepare_reading():
    rows, _, _ = proof_records()
    write_import("proofs-reading", rows,
                 (DIRECTORY / "_B28-bracketing-proofs.aux").read_text(encoding="utf-8-sig"))
    print("Bracketing reading imports prepared: main theorem from B28, six subsidiary results from proofs.")


def audit():
    from pypdf import PdfReader

    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    canonical, _, canonical_aux = main_records()
    proof_rows, _, proof_aux = proof_records()
    for name, expected, expected_aux in (
        ("b28-external", canonical, canonical_aux),
        ("b28-reading", canonical, canonical_aux),
        ("proofs-reading", proof_rows, proof_aux),
    ):
        if Counter(map(tuple, registry(DIRECTORY / (name + ".registry.tsv")))) != Counter(map(tuple, expected)):
            raise ValueError(f"{name}: stale or incomplete registry import")
        imported_aux = aux_labels(DIRECTORY / (name + ".aux"))
        if set(imported_aux) != {row_label(row) for row in expected}:
            raise ValueError(f"{name}: unexpected or missing AUX imports")
        for label in imported_aux:
            if imported_aux[label] != expected_aux[label]:
                raise ValueError(f"{name}: stale AUX target/number: {label}")

    cache = {}

    def remote_links(pdf, reader):
        links = set()
        for action in publisher["remote_actions"](reader):
            target = (pdf.parent / publisher["file_name"](action)).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():
                raise ValueError(f"{pdf.name}: missing/outside build target: {target}")
            if target not in cache:
                cache[target] = set(PdfReader(target).named_destinations)
            destination = str(action.get("/D"))
            if destination not in cache[target]:
                raise ValueError(f"{pdf.name}: remote destination missing: {target}, {destination}")
            links.add((target, destination))
        return links

    main_pdf = ROOT / "registry/_B28.pdf"
    for edition in ("reading", "proofs"):
        base = DIRECTORY / f"_B28-bracketing-{edition}"
        rows = registry(base.with_suffix(".registry.tsv"))
        expected_rows = Counter(map(tuple, proof_rows)) if edition == "proofs" else Counter()
        if Counter(map(tuple, rows)) != expected_rows:
            raise ValueError(f"{edition}: unexpected local registry records")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        expected_targets = {f"bracketing.{edition}"}
        if edition == "proofs":
            expected_targets.update(proof_aux[label][1] for label in PROOF_LABELS)
            expected_targets.update(f"bracketing.statement.{key}" for key in PROOF_IDS)
            expected_targets.add(FINAL_PROOF_TARGET)
        else:
            expected_targets.update(f"bracketing.reading.{section}" for section in SECTIONS.values())
        if missing := expected_targets - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF targets: {sorted(missing)}")
        links = remote_links(pdf, reader)
        companion = "proofs" if edition == "reading" else "reading"
        expected_link = ((DIRECTORY / f"_B28-bracketing-{companion}.pdf").resolve(), f"bracketing.{companion}")
        if expected_link not in links:
            raise ValueError(f"{edition}: missing companion entry link")
        if (main_pdf.resolve(), MAIN_TARGET) not in links:
            raise ValueError(f"{edition}: missing link to the B28 notation reference")
        if (main_pdf.resolve(), MAIN_RESULT_TARGET) not in links:
            raise ValueError(f"{edition}: missing link to the canonical B28 main theorem")
        print(f"Bracketing {edition}: identities, original numbers, imports and all PDF links passed ({len(reader.pages)} pages).")

    reader = PdfReader(main_pdf)
    publisher["assert_build_ready"](main_pdf, reader)
    publisher["audit_local_targets"](reader, main_pdf)
    links = remote_links(main_pdf, reader)
    proof_target = (DIRECTORY / "_B28-bracketing-proofs.pdf").resolve()
    reading_target = (DIRECTORY / "_B28-bracketing-reading.pdf").resolve()
    if MAIN_TARGET not in reader.named_destinations:
        raise ValueError("B28: notation reference PDF target missing")
    if MAIN_RESULT_TARGET not in reader.named_destinations:
        raise ValueError("B28: canonical main theorem PDF target missing")
    expected_links = {
        (reading_target, "bracketing.reading"),
        *((proof_target, f"bracketing.statement.{key}") for key in SECTIONS if key != MAIN_ID),
        (proof_target, FINAL_PROOF_TARGET),
    }
    if missing := expected_links - links:
        raise ValueError(f"B28: notation reference lacks reading/proof links: {sorted(missing)}")
    print("Bracketing ownership verified: main theorem only in B28, six subsidiary results only in proofs; reading, result and final-proof links verified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "prepare-reading", "audit"))
    args = parser.parse_args()
    {"prepare": prepare, "prepare-reading": prepare_reading, "audit": audit}[args.mode]()
