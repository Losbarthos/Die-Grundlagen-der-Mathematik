"""Prepare and audit the formal-difference companions to B41.

The checked migration manifest records the original statement identities and
formulas. These are document-integrity checks, not a proof-assistant check.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/differences"
MANIFEST = json.loads((ROOT / "scripts/differences-manifest.json").read_text(encoding="utf-8"))
MAIN_ID = MANIFEST["main_id"]
MAIN_LABEL = "thm:auto:" + MANIFEST["main_number"]


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def id_map(rows):
    keys = [row[1] for row in rows if row[0] == "ID"]
    if duplicates := [key for key, count in Counter(keys).items() if count != 1]:
        raise ValueError(f"Duplicate local IDs: {duplicates}")
    return {row[1]: row[3] for row in rows if row[0] == "ID"}


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


def moved_record(row):
    # Preserve formulas, hashes, titles and identities; change only labels and numbers.
    row = list(row)
    if row[0] == "ID":
        row[3] = row[3].replace(":41.4.", ":41E.1.")
    else:
        row[1] = row[1].replace(":41.4.", ":41E.1.")
        row[3] = row[3].replace("41.4.", "41E.1.")
    return row


EXPECTED_PROOF = [moved_record(row) for row in MANIFEST["private_records"]]
PRIVATE_IDS = set(id_map(EXPECTED_PROOF))
SUPPLEMENTS = runpy.run_path(str(ROOT / "scripts/differences-supplements.py"))


def records_equal(actual, expected, owner):
    # The first structural field is an insertion index, not an identity.
    a, b = Counter(tuple(row[1:]) for row in actual), Counter(tuple(row[1:]) for row in expected)
    if a != b:
        raise ValueError(f"{owner}: statement migration differs from manifest; "
                         f"missing={list((b-a).elements())}, extra={list((a-b).elements())}")


def main_records():
    base = ROOT / "registry/_B41"
    rows = registry(base.with_suffix(".registry.tsv"))
    ids = id_map(rows)
    records_equal(rows, MANIFEST["public_records"], "B41")
    if PRIVATE_IDS & set(ids) or ids.get(MAIN_ID) != MAIN_LABEL:
        raise ValueError("B41 must own the canonical main theorem and no private construction IDs")
    aux = aux_labels(base.with_suffix(".aux"))
    for label, expected in MANIFEST["public_aux"].items():
        if aux.get(label) != tuple(expected):
            raise ValueError(f"B41: original public number/anchor changed: {label}, {aux.get(label)}")
    old_private = {row_label(row) for row in MANIFEST["private_records"]}
    if old_private & set(aux):
        raise ValueError("B41 AUX still owns extracted construction labels")
    return rows, ids, aux


def proof_records():
    base = DIRECTORY / "_B41-differences-proofs"
    rows = registry(base.with_suffix(".registry.tsv"))
    ids = id_map(rows)
    original_labels = {row_label(row) for row in EXPECTED_PROOF}
    original = [row for row in rows if row_label(row) in original_labels]
    records_equal(original, EXPECTED_PROOF, "original construction proofs")
    additions = SUPPLEMENTS["declarations"]()
    if set(ids) != PRIVATE_IDS | set(additions) or MAIN_ID in ids:
        raise ValueError("proofs: missing private IDs or duplicate public theorem")
    added_labels = {ids[key] for key in additions}
    if {row_label(row) for row in rows} != original_labels | added_labels:
        raise ValueError("proofs: orphan or unrecognized structural registry record")
    aux = aux_labels(base.with_suffix(".aux"))
    for row in rows:
        label = row_label(row)
        if label not in aux or not aux[label][0].startswith("41E."):
            raise ValueError(f"proofs: missing/non-companion label {label}")
        if row[0] != "ID" and row[3] != aux[label][0]:
            raise ValueError(f"proofs: registry/AUX numbering differs for {label}")
    for key, declaration in additions.items():
        label = ids[key]
        if not aux[label][0].startswith(f"41E.{declaration['chapter']}."):
            raise ValueError(f"{key}: wrong supplement chapter number")
        if next(row[2] for row in rows if row[0] == "ID" and row[1] == key) != declaration["kind"]:
            raise ValueError(f"{key}: source and registry disagree on declaration kind")
    if MAIN_LABEL in aux:
        raise ValueError("proofs: public theorem must be imported, not declared locally")
    return rows, ids, aux


def write_import(name, rows, aux_path):
    labels = {row_label(row) for row in rows}
    (DIRECTORY / (name + ".registry.tsv")).write_text(
        "".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")
    lines = []
    for line in aux_path.read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            lines.append(line)
    target = DIRECTORY / (name + ".aux")
    target.write_text("\\relax\n" + "\n".join(lines) + "\n", encoding="utf-8")
    if set(aux_labels(target)) != labels:
        raise ValueError(f"{name}: incomplete filtered AUX import")


def prepare():
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows, _, _ = main_records()
    for name in ("b41-external", "b41-reading"):
        write_import(name, rows, ROOT / "registry/_B41.aux")
    (DIRECTORY / "position.tex").write_text(
        "% Generated companion numbering; do not edit.\n"
        "\\renewcommand{\\FormulaBandID}{41E}\n"
        "\\setcounter{file}{41}\n"
        "\\setcounter{chapter}{0}\n"
        "\\setcounter{section}{0}\n"
        "\\setcounter{subsection}{0}\n"
        "\\setcounter{formulaDef}{0}\n"
        "\\setcounter{formulaThm}{0}\n", encoding="utf-8")
    print("Differences: canonical B41 imports and independent 41E numbering prepared.")


def prepare_reading():
    rows, _, _ = proof_records()
    main_records()
    write_import("proofs-reading", rows, DIRECTORY / "_B41-differences-proofs.aux")
    print(f"Differences: reading imports prepared from {len(id_map(rows))} result IDs.")


def audit():
    from pypdf import PdfReader

    additions, _ = SUPPLEMENTS["audit_sources"]()
    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    public, _, public_aux = main_records()
    proofs, _, proof_aux = proof_records()
    for name, rows, aux in (("b41-external", public, public_aux),
                            ("b41-reading", public, public_aux),
                            ("proofs-reading", proofs, proof_aux)):
        records_equal(registry(DIRECTORY / (name + ".registry.tsv")), rows, name)
        expected = {row_label(row): aux[row_label(row)] for row in rows}
        if aux_labels(DIRECTORY / (name + ".aux")) != expected:
            raise ValueError(f"{name}: stale or incomplete AUX import")

    cache = {}

    def checked_links(pdf, reader):
        links = set()
        for action in publisher["remote_actions"](reader):
            target = (pdf.parent / publisher["file_name"](action)).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():
                raise ValueError(f"{pdf.name}: missing/outside PDF target: {target}")
            if target not in cache:
                cache[target] = set(PdfReader(target).named_destinations)
            destination = str(action.get("/D"))
            if destination not in cache[target]:
                raise ValueError(f"{pdf.name}: missing destination {destination} in {target}")
            links.add((target, destination))
        return links

    main_pdf = ROOT / "registry/_B41.pdf"
    for edition in ("proofs", "reading"):
        base = DIRECTORY / f"_B41-differences-{edition}"
        rows = registry(base.with_suffix(".registry.tsv"))
        records_equal(rows, proofs if edition == "proofs" else [], edition)
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        expected_targets = {f"differences.{edition}"}
        if edition == "proofs":
            expected_targets.add("differences.proof")
            expected_targets.update("differences.statement." + key for key in PRIVATE_IDS | set(additions))
            expected_targets.update(proof_aux[row_label(row)][1] for row in proofs)
        if missing := expected_targets - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF targets: {sorted(missing)}")
        links = checked_links(pdf, reader)
        companion = "reading" if edition == "proofs" else "proofs"
        expected_links = {
            ((DIRECTORY / f"_B41-differences-{companion}.pdf").resolve(), f"differences.{companion}"),
            (main_pdf.resolve(), "differences.main"),
            (main_pdf.resolve(), public_aux[MAIN_LABEL][1]),
        }
        if missing := expected_links - links:
            raise ValueError(f"{edition}: missing navigation: {missing}")
        print(f"Differences {edition}: {len(reader.pages)} pages; identities, formulas, numbering and links passed.")

    reader = PdfReader(main_pdf)
    publisher["assert_build_ready"](main_pdf, reader)
    publisher["audit_local_targets"](reader, main_pdf)
    links = checked_links(main_pdf, reader)
    expected_links = {
        ((DIRECTORY / "_B41-differences-reading.pdf").resolve(), "differences.reading"),
        ((DIRECTORY / "_B41-differences-proofs.pdf").resolve(), "differences.proofs"),
        ((DIRECTORY / "_B41-differences-proofs.pdf").resolve(), "differences.proof"),
    }
    if missing := expected_links - links:
        raise ValueError(f"B41: missing companion links: {missing}")
    for label in MANIFEST["public_aux"]:
        if public_aux[label][1] not in reader.named_destinations:
            raise ValueError(f"B41: public PDF destination missing: {label}")
    print("B41: canonical theorem, all remaining result numbers/anchors and companion navigation preserved.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "prepare-reading", "audit"))
    args = parser.parse_args()
    {"prepare": prepare, "prepare-reading": prepare_reading, "audit": audit}[args.mode]()
