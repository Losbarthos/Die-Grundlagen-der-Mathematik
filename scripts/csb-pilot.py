"""Prepare and audit the CSB companions and their canonical B08 theorem.

These checks establish statement ownership, unchanged mathematical source,
isolated numbering and PDF navigation, not the validity of inference rules.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/csb"
MAIN_ID = "CantorBernsteinFixedInjections"
PRIVATE_LABELS = {
    "CantorBernsteinPartDef": "def:auto:8E.1.1.1",
    "CantorBernsteinPartSubset": "thm:auto:8E.1.1.1",
    "CantorBernsteinPartContainsSeed": "thm:auto:8E.1.1.2",
    "CantorBernsteinPartMinimal": "thm:auto:8E.1.1.3",
    "CantorBernsteinPartClosed": "thm:auto:8E.1.1.4",
    "CantorBernsteinPartClosedUniversal": "thm:pp:8E.1.1.4:1",
    "CantorBernsteinPartFixedPoint": "thm:auto:8E.1.1.5",
    "CantorBernsteinComplementIdentity": "thm:auto:8E.1.1.6",
    "CantorBernsteinComplementForward": "thm:pp:8E.1.1.6:1",
    "CantorBernsteinComplementBackward": "thm:pp:8E.1.1.6:2",
    "CantorBernsteinSecondBranchImage": "thm:auto:8E.1.1.7",
}
PRIVATE_IDS = set(PRIVATE_LABELS)
HELPER_IDS = {
    "CantorBernsteinPartClosedUniversal", "CantorBernsteinComplementForward",
    "CantorBernsteinComplementBackward",
}
APPLICATION_IDS = {
    "CardLeqDef", "Gleichmächtigkeit", "CantorSchroederBernstein",
    "EqCardMutualCardLeqEquiv",
}
FINAL_PROOF_TARGET = "csb.proof"
LEGACY_CSB_LABELS = {
    label.replace("8E.1.1", "8.3.7") for label in PRIVATE_LABELS.values()
} | {"thm:auto:8.3.7.8"}

# Migration baseline, 2026-09-21: SHA-256 of kind + newline + the normalized
# formula from the original CSB registry. Labels, numbers and titles are omitted.
# The definition also has an ID alias record. H statements have ID records only.
FORMULA_FINGERPRINTS = {
    "CantorBernsteinPartDef": (
        "7916ab81129e80c287dbc7ae756dbfc7d8ada13a6d0171fcd9cf3e30f96e6000",
        "a0f018371f90779d54a26bd9ac757ef60cc0ff8ea43bffbe46a51fe312b1f723",
    ),
    "CantorBernsteinPartSubset": ("438a939ee2fbc29ffb7a8ebdac81a198291cc27e4094d577b835007ad6aeb34b",),
    "CantorBernsteinPartContainsSeed": ("a065e7ed0eb336914131f80d5cbd366d6189932e8d0a77ddc6cd3b466e2f2a0d",),
    "CantorBernsteinPartMinimal": ("d4131ca33a60c74baa321a3c5c4efda98b9c10b876a310f9131368f9abff7f9b",),
    "CantorBernsteinPartClosed": ("b343f296204427883e9fb4364352bca4915f60cd86603704951e9fc5575e596b",),
    "CantorBernsteinPartFixedPoint": ("4ebcfab8b922381c4d84b4bfb47a3407e6653d3660a7b81243066edaeef17d79",),
    "CantorBernsteinComplementIdentity": ("3a1a64d639b21916f95ddf7ae9532de5f2d98afab026333cef4913b37977719f",),
    "CantorBernsteinSecondBranchImage": ("a83b5934eebe717744afb5f3aeccbb9f0500f2ff063f1c03339ef3dd6250effb",),
    MAIN_ID: ("1f6a4bfe2b8e4a958b0ea4e48789a20945d8ee2991f1c6a2fd5bcfd31b7c0d39",),
}
# Preserve both displayed and lookup formulas of the three H statements and
# all 145 proof rows (including hypotheses and inference references).
HELPER_SOURCE_FINGERPRINTS = {
    "CantorBernsteinPartClosedUniversal": "ca52c2c118a7d94900752392fdad2babe69b76b0ac7006604b13f42d91f7e34f",
    "CantorBernsteinComplementForward": "cf30878d9964bd2adc431fc6aa1e3248ffbb15c1af6987745cd4d871a0f9a227",
    "CantorBernsteinComplementBackward": "8076f38d99aa0dd3cae480135d2255e41aa3359faeaab807eadbb31b9c7f587c",
}
PROOF_ROWS_FINGERPRINT = "5f0aff8530f32758791372edc8171c1b6ef5e34e82bfe8f344569e33ebf7b136"


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
    # Titles may contain nested TeX groups, so a flat regex is insufficient.
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
            if match[1] in result:
                raise ValueError(f"{path.name}: duplicate local AUX label: {match[1]}")
            result[match[1]] = (fields[0].strip(), fields[3])
    return result


def write_if_changed(path, text):
    # Unchanged generated imports keep their timestamps for incremental builds.
    if not path.exists() or path.read_text(encoding="utf-8-sig") != text:
        path.write_text(text, encoding="utf-8")


def write_import(name, rows, aux_text):
    labels = {row_label(row) for row in rows}
    write_if_changed(DIRECTORY / (name + ".registry.tsv"),
                     "".join("\t".join(row) + "\n" for row in rows))
    lines = []
    for line in aux_text.splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            lines.append(line)
    target = DIRECTORY / (name + ".aux")
    write_if_changed(target, "\\relax\n" + "\n".join(lines) + "\n")
    if set(aux_labels(target)) != labels:
        raise ValueError(f"{name}: unexpected or missing imported AUX labels")


def formula_fingerprint(row):
    return sha256((row[2] + "\n" + row[5]).encode("utf-8")).hexdigest()


def assert_formulas(rows, identifiers, expected_ids, owner):
    for key in expected_ids:
        label = identifiers[key]
        actual = Counter(formula_fingerprint(row) for row in rows
                         if row[0] != "ID" and row_label(row) == label)
        if actual != Counter(FORMULA_FINGERPRINTS.get(key, ())):
            raise ValueError(f"{owner}: mathematical registry formula changed for {key}")
        kind = "definition" if key == "CantorBernsteinPartDef" else "theorem"
        if any(row[2] != kind for row in rows if row_label(row) == label):
            raise ValueError(f"{owner}: incorrect declaration kind for {key}")


def assert_proof_source():
    scanner = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))
    source = ROOT / "tex/b08/cantor-bernstein/beweistabellen.tex"
    text = scanner["mask_comments"](source.read_text(encoding="utf-8-sig"))

    def tokens(value):
        return re.findall(r"\\[A-Za-z@]+|\\.|[^\s]", value)

    def fingerprint(value):
        return sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()

    steps = [tokens(text[row.start:row.end]) for row in scanner["rows"](text)]
    if len(steps) != 145 or fingerprint(steps) != PROOF_ROWS_FINGERPRINT:
        raise ValueError("proofs: original mathematical proof rows or inference references changed")
    helpers = {}
    for match in re.finditer(r"\\proofpartwideindR\b", text):
        call = scanner["call"](text, match.start(), 2, optional_after=1)
        key = text[slice(*call.opts[-1])].strip() if len(call.opts) == 2 else ""
        if key in helpers:
            raise ValueError(f"proofs: duplicated subsidiary source declaration: {key}")
        helpers[key] = fingerprint([tokens(text[slice(*arg)]) for arg in call.args])
    if helpers != HELPER_SOURCE_FINGERPRINTS:
        raise ValueError("proofs: original H statements or their lookup formulas changed")


def main_records():
    rows = registry(ROOT / "registry/_B08.registry.tsv")
    identifiers = id_map(rows)
    if set(identifiers) & (PRIVATE_IDS | {MAIN_ID}) != {MAIN_ID}:
        raise ValueError("B08 must own exactly the public CSB theorem and none of its private results")
    aux = aux_labels(ROOT / "registry/_B08.aux")
    label = identifiers[MAIN_ID]
    records = [row for row in rows if row[0] != "ID" and row_label(row) == label]
    assert_formulas(rows, identifiers, {MAIN_ID}, "B08")
    number = records[0][3]
    if not re.fullmatch(r"8\.\d+\.\d+\.\d+", number) or label != "thm:auto:" + number:
        raise ValueError("B08: invalid canonical CSB theorem number or label")
    if aux.get(label, (None,))[0] != number:
        raise ValueError("B08: main theorem registry and AUX numbers disagree")
    if stale := (set(aux) & LEGACY_CSB_LABELS) - {label}:
        raise ValueError(f"B08: obsolete CSB declarations remain in AUX: {sorted(stale)}")
    private_formulas = {value for key, values in FORMULA_FINGERPRINTS.items()
                        if key != MAIN_ID for value in values}
    if any(row[0] != "ID" and formula_fingerprint(row) in private_formulas for row in rows):
        raise ValueError("B08: a private CSB formula remains under a local result label")
    main_formulas = set(FORMULA_FINGERPRINTS[MAIN_ID])
    if any(row[0] != "ID" and row_label(row) != label
           and formula_fingerprint(row) in main_formulas for row in rows):
        raise ValueError("B08: the public CSB statement is declared more than once")
    return rows, identifiers, aux


def proof_records():
    base = DIRECTORY / "_B08-csb-proofs"
    rows = registry(base.with_suffix(".registry.tsv"))
    identifiers = id_map(rows)
    if identifiers != PRIVATE_LABELS:
        raise ValueError("proofs: expected exactly the 11 private identities with their independent 8E labels")
    if len(rows) != 20 or {row_label(row) for row in rows} != set(PRIVATE_LABELS.values()):
        raise ValueError("proofs: expected nine formula/alias records and 11 ID records only")
    assert_formulas(rows, identifiers, PRIVATE_IDS, "proofs")
    aux = aux_labels(base.with_suffix(".aux"))
    for key, label in identifiers.items():
        expected = label.removeprefix("def:auto:").removeprefix("thm:auto:")
        if key in HELPER_IDS:
            parent, part = label.removeprefix("thm:pp:").rsplit(":", 1)
            expected = f"{parent}(H{part})"
        if aux.get(label, (None,))[0] != expected:
            raise ValueError(f"proofs: missing or inconsistent companion number for {key}")
    for row in rows:
        if row[0] != "ID" and row[3] != aux[row_label(row)][0]:
            raise ValueError(f"proofs: registry/AUX number disagreement for {row_label(row)}")
    main, main_ids, main_aux = main_records()
    if set(identifiers) & set(main_ids) or set(PRIVATE_LABELS.values()) & {row_label(row) for row in main}:
        raise ValueError("proofs: local identities and labels overlap B08")
    if set(aux) & (LEGACY_CSB_LABELS | {main_ids[MAIN_ID]}):
        raise ValueError("proofs: main-volume CSB labels must only be imported, never declared locally")
    if set(PRIVATE_LABELS.values()) & set(main_aux):
        raise ValueError("B08: private companion labels must not be declared locally")
    assert_proof_source()
    return rows, identifiers, aux


def application_records():
    rows = registry(ROOT / "registry/_B11.registry.tsv")
    identifiers = id_map(rows)
    if missing := APPLICATION_IDS - set(identifiers):
        raise ValueError(f"B11: missing application identities: {sorted(missing)}")
    labels = {identifiers[key] for key in APPLICATION_IDS}
    return [row for row in rows if row_label(row) in labels], aux_labels(ROOT / "registry/_B11.aux")


def prepare():
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows, identifiers, aux = main_records()
    aux_text = (ROOT / "registry/_B08.aux").read_text(encoding="utf-8-sig")
    for name in ("b08-external", "b08-reading"):
        write_import(name, rows, aux_text)
    application, _ = application_records()
    write_import("b11-application", application,
                 (ROOT / "registry/_B11.aux").read_text(encoding="utf-8-sig"))
    number = aux[identifiers[MAIN_ID]][0]
    write_if_changed(DIRECTORY / "position.tex",
                     "% Generated independent companion numbering; do not edit.\n"
                     "\\renewcommand{\\FormulaBandID}{8E}\n"
                     "\\setcounter{file}{8}\n"
                     "\\setcounter{chapter}{1}\n"
                     "\\setcounter{section}{0}\n"
                     "\\setcounter{subsection}{0}\n"
                     "\\setcounter{formulaDef}{0}\n"
                     "\\setcounter{formulaThm}{0}\n"
                     f"\\newcommand{{\\CSBMainTheoremNumber}}{{{number}}}\n")
    print("CSB imports prepared; canonical B08 theorem: " + number)


def prepare_reading():
    rows, _, _ = proof_records()
    write_import("proofs-reading", rows,
                 (DIRECTORY / "_B08-csb-proofs.aux").read_text(encoding="utf-8-sig"))
    print("CSB reading imports prepared: public theorem from B08, 11 private identities from proofs.")


def audit():
    from pypdf import PdfReader

    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    canonical, canonical_ids, canonical_aux = main_records()
    proof_rows, _, proof_aux = proof_records()
    application, application_aux = application_records()
    for name, expected, expected_aux in (
        ("b08-external", canonical, canonical_aux),
        ("b08-reading", canonical, canonical_aux),
        ("proofs-reading", proof_rows, proof_aux),
        ("b11-application", application, application_aux),
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

    def action_link(pdf, action):
        target = (pdf.parent / publisher["file_name"](action)).resolve()
        if not target.is_relative_to(ROOT) or not target.is_file():
            raise ValueError(f"{pdf.name}: missing/outside build target: {target}")
        if target not in cache:
            cache[target] = set(PdfReader(target).named_destinations)
        destination = str(action.get("/D"))
        if destination not in cache[target]:
            raise ValueError(f"{pdf.name}: remote destination missing: {target}, {destination}")
        return target, destination

    def remote_links(pdf, reader):
        return {action_link(pdf, action) for action in publisher["remote_actions"](reader)}

    main_pdf = ROOT / "registry/_B08.pdf"
    theorem_anchor = canonical_aux[canonical_ids[MAIN_ID]][1]
    for edition in ("reading", "proofs"):
        base = DIRECTORY / f"_B08-csb-{edition}"
        rows = registry(base.with_suffix(".registry.tsv"))
        expected_rows = Counter(map(tuple, proof_rows)) if edition == "proofs" else Counter()
        if Counter(map(tuple, rows)) != expected_rows:
            raise ValueError(f"{edition}: unexpected local registry records")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        expected_targets = {f"csb.{edition}"}
        if edition == "proofs":
            expected_targets.add(FINAL_PROOF_TARGET)
            expected_targets.update(f"csb.helper.{key}" for key in HELPER_IDS)
            expected_targets.update(proof_aux[label][1] for label in PRIVATE_LABELS.values())
        else:
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            for heading, pattern in (
                ("Zur Benutzung", r"\bZur\s+Benutzung\b"),
                ("Aussagen zum Lesebeweis", r"\bAussagen\s+zum\s+Lesebeweis\b"),
                ("Aussagen und tabellarische Ableitungen", r"\bAussagen\s+und\s+tabellarische\s+Ableitungen\b"),
                ("Ableitungsnachweise", r"\bAbleitungsnachweise\b"),
                ("Lesebeweis", r"\bLesebeweis\b"),
            ):
                if re.search(pattern, text, re.IGNORECASE):
                    raise ValueError(f"reading: removed section or label {heading!r} is still present")
        if missing := expected_targets - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF targets: {sorted(missing)}")
        links = remote_links(pdf, reader)
        companion = "proofs" if edition == "reading" else "reading"
        companion_entry = ((DIRECTORY / f"_B08-csb-{companion}.pdf").resolve(), f"csb.{companion}")
        if companion_entry not in links:
            raise ValueError(f"{edition}: missing companion entry link")
        if (main_pdf.resolve(), theorem_anchor) not in links:
            raise ValueError(f"{edition}: missing reference to the canonical B08 main theorem")
        print(f"CSB {edition}: ownership, unchanged formulas, imports and PDF links passed ({len(reader.pages)} pages).")

    main_reader = PdfReader(main_pdf)
    publisher["assert_build_ready"](main_pdf, main_reader)
    publisher["audit_local_targets"](main_reader, main_pdf)
    remote_links(main_pdf, main_reader)
    destination = main_reader.named_destinations.get(theorem_anchor)
    if destination is None:
        raise ValueError(f"B08: public theorem PDF target missing: {theorem_anchor}")
    theorem_page = main_reader.get_destination_page_number(destination)
    if theorem_page is None or not 0 <= theorem_page < len(main_reader.pages):
        raise ValueError("B08: main theorem target has no valid page")
    expected_links = {
        ((DIRECTORY / "_B08-csb-reading.pdf").resolve(), "csb.reading"),
        ((DIRECTORY / "_B08-csb-proofs.pdf").resolve(), FINAL_PROOF_TARGET),
    }
    page_links = set()
    for annotation in main_reader.pages[theorem_page].get("/Annots", []):
        action = annotation.get_object().get("/A")
        if action is not None:
            action = action.get_object()
            if action.get("/S") == "/GoToR":
                page_links.add(action_link(main_pdf, action))
    if missing := expected_links - page_links:
        raise ValueError(f"B08: theorem page {theorem_page + 1} lacks reading/final-proof links: {sorted(missing)}")
    print(f"CSB separation: main theorem only in B08; definition, seven subsidiary theorems and three H results only in proofs. "
          f"Direct reading/final-proof links verified on B08 page {theorem_page + 1}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "prepare-reading", "audit"))
    args = parser.parse_args()
    {"prepare": prepare, "prepare-reading": prepare_reading, "audit": audit}[args.mode]()
