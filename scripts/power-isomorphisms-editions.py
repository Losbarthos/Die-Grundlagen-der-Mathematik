"""Prepare and audit the power-isomorphisms companions and their canonical B28 theorem.

The checks establish declaration identities, original numbering, isolated
registries and working PDF navigation; they do not verify inference rules.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/power-isomorphisms"
MANIFEST_PATH = ROOT / "scripts/power-isomorphisms-manifest.json"
MANIFEST_SHA256 = "562c05fda37e57b5d1dc3d96254f62817104ae7a8fa11b0030a01534e58c04b6"
if hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest() != MANIFEST_SHA256:
    raise ValueError("The original power-isomorphism identity snapshot must remain unchanged")
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
IDENTITIES = MANIFEST["identities"]
NUMBERS = {key: item["number"] for key, item in IDENTITIES.items()}
SECTIONS = {
    "SemigroupHomPreservesPowerProduct": "product",
    "PowerSemigroupInducedMapOperation": "operation",
    "SemigroupIsoInducesPowerSemigroupIso": "isomorphism",
}
EXPECTED_LABELS = {item["label"] for item in IDENTITIES.values()}
MAIN_ID = MANIFEST["main_id"]
MAIN_LABEL = IDENTITIES[MAIN_ID]["label"]
PROOF_IDS = set(IDENTITIES) - {MAIN_ID}
PROOF_LABELS = EXPECTED_LABELS - {MAIN_LABEL}
MAIN_TARGET = "power-isomorphisms.notation"
FINAL_PROOF_TARGET = "power-isomorphisms.proof.isomorphism"
registry_records = runpy.run_path(str(ROOT / "scripts/registry-editions.py"))["registry_records"]


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


def check_numbers(rows, identifiers, aux, expected_ids, owner, *, canonical_main_target=None):
    expected_labels = {IDENTITIES[key]["label"] for key in expected_ids}
    for key in expected_ids:
        item = IDENTITIES[key]
        label = item["label"]
        destination = (canonical_main_target if key == MAIN_ID and canonical_main_target is not None
                       else item["destination"])
        if identifiers.get(key) != label or aux.get(label) != (item["number"], destination):
            raise ValueError(f"{owner}: original identity/number/destination changed for {key}")
    actual = [row for row in rows if row_label(row) in expected_labels]
    expected = [row for row in MANIFEST["canonical_registry"] if row_label(row) in expected_labels]
    if registry_records(actual) != registry_records(expected):
        raise ValueError(f"{owner}: original theorem formulas or declaration metadata changed")


def prepare_main():
    """Bootstrap B28's imports without requiring a previously built companion."""
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows = [row for row in MANIFEST["canonical_registry"] if row_label(row) in PROOF_LABELS]
    aux_text = "\\relax\n" + "".join(
        r"\newlabel{%s}{{%s}{1}{}{%s}{}}" % (item["label"], item["number"], item["destination"]) + "\n"
        for key, item in IDENTITIES.items() if key in PROOF_IDS)
    # Preserve the original numbers and PDF destinations even on a clean build.
    # Readers use result numbers, not the placeholder page field.
    write_import("proofs-main", rows, aux_text)
    print("Power-isomorphism B28 imports prepared from the protected original identities.")


def main_records():
    rows = registry(ROOT / "registry/_B28.registry.tsv")
    identifiers = id_map(rows)
    if set(identifiers) & set(NUMBERS) != {MAIN_ID}:
        raise ValueError("B28 must own exactly the final power-isomorphism theorem")
    labels = {row_label(row) for row in rows}
    if labels & EXPECTED_LABELS != {MAIN_LABEL}:
        raise ValueError("B28 must contain exactly the canonical main theorem label")
    aux = aux_labels(ROOT / "registry/_B28.aux")
    if set(aux) & EXPECTED_LABELS != {MAIN_LABEL}:
        raise ValueError("B28 AUX must contain only the canonical main theorem label")
    # Anonymous destination counters change when earlier declarations move to
    # another volume. Keep the protected identity, number, kind and formula;
    # resolve this canonical destination from the current authoritative AUX.
    current_target = aux[MAIN_LABEL][1]
    if not re.fullmatch(r"section\*\.\d+", current_target):
        raise ValueError("B28: invalid canonical main theorem destination")
    check_numbers(rows, identifiers, aux, {MAIN_ID}, "B28",
                  canonical_main_target=current_target)
    return rows, identifiers, aux


def proof_records():
    base = DIRECTORY / "_B28-power-isomorphisms-proofs"
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
        "\\setcounter{section}{14}\n"
        "\\setcounter{subsection}{0}\n"
        "\\setcounter{formulaDef}{0}\n"
        "\\setcounter{formulaThm}{1}\n", encoding="utf-8"
    )
    print("Power-isomorphism imports prepared; both companions import the canonical B28 main theorem.")


def prepare_reading():
    rows, _, _ = proof_records()
    write_import("proofs-reading", rows,
                 (DIRECTORY / "_B28-power-isomorphisms-proofs.aux").read_text(encoding="utf-8-sig"))
    print("Power-isomorphism reading imports prepared: main theorem from B28, fourteen subsidiary results from proofs.")


def check_main_pdf_target(reader, target):
    semantic = "power-isomorphisms.main.isomorphism"
    destinations = reader.named_destinations
    if target not in destinations or semantic not in destinations:
        raise ValueError("B28: canonical or semantic main theorem PDF target missing")
    if (reader.get_destination_page_number(destinations[target]) !=
            reader.get_destination_page_number(destinations[semantic])):
        raise ValueError("B28: canonical main theorem destination disagrees with its semantic PDF target")


def audit():
    from pypdf import PdfReader

    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    canonical, _, canonical_aux = main_records()
    main_result_target = canonical_aux[MAIN_LABEL][1]
    proof_rows, _, proof_aux = proof_records()
    for name, expected, expected_aux in (
        ("b28-external", canonical, canonical_aux),
        ("b28-reading", canonical, canonical_aux),
        ("proofs-reading", proof_rows, proof_aux),
        ("proofs-main", proof_rows, proof_aux),
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

    def remote_links(pdf, reader, *, own_companions_only=False):
        links = set()
        for action in publisher["remote_actions"](reader):
            target = (pdf.parent / publisher["file_name"](action)).resolve()
            if own_companions_only and target.parent != DIRECTORY.resolve():
                continue
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
        base = DIRECTORY / f"_B28-power-isomorphisms-{edition}"
        rows = registry(base.with_suffix(".registry.tsv"))
        expected_rows = Counter(map(tuple, proof_rows)) if edition == "proofs" else Counter()
        if Counter(map(tuple, rows)) != expected_rows:
            raise ValueError(f"{edition}: unexpected local registry records")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        expected_targets = {f"power-isomorphisms.{edition}"}
        if edition == "proofs":
            expected_targets.update(proof_aux[label][1] for label in PROOF_LABELS)
            expected_targets.update(f"power-isomorphisms.statement.{key}" for key in SECTIONS if key != MAIN_ID)
            expected_targets.add(FINAL_PROOF_TARGET)
        else:
            expected_targets.update(f"power-isomorphisms.reading.{section}" for section in SECTIONS.values())
        if missing := expected_targets - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF targets: {sorted(missing)}")
        links = remote_links(pdf, reader)
        companion = "proofs" if edition == "reading" else "reading"
        expected_link = ((DIRECTORY / f"_B28-power-isomorphisms-{companion}.pdf").resolve(), f"power-isomorphisms.{companion}")
        if expected_link not in links:
            raise ValueError(f"{edition}: missing companion entry link")
        if (main_pdf.resolve(), MAIN_TARGET) not in links:
            raise ValueError(f"{edition}: missing link to the B28 notation reference")
        if (main_pdf.resolve(), main_result_target) not in links:
            raise ValueError(f"{edition}: missing link to the canonical B28 main theorem")
        print(f"Power-isomorphism {edition}: identities, original numbers, imports and all PDF links passed ({len(reader.pages)} pages).")

    reader = PdfReader(main_pdf)
    publisher["assert_build_ready"](main_pdf, reader)
    publisher["audit_local_targets"](reader, main_pdf)
    links = remote_links(main_pdf, reader, own_companions_only=True)
    proof_target = (DIRECTORY / "_B28-power-isomorphisms-proofs.pdf").resolve()
    reading_target = (DIRECTORY / "_B28-power-isomorphisms-reading.pdf").resolve()
    if MAIN_TARGET not in reader.named_destinations:
        raise ValueError("B28: notation reference PDF target missing")
    check_main_pdf_target(reader, main_result_target)
    expected_links = {
        (reading_target, "power-isomorphisms.reading"),
        *((proof_target, f"power-isomorphisms.statement.{key}") for key in SECTIONS if key != MAIN_ID),
        (proof_target, FINAL_PROOF_TARGET),
    }
    if missing := expected_links - links:
        raise ValueError(f"B28: notation reference lacks reading/proof links: {sorted(missing)}")
    print("Power-isomorphism ownership verified: main theorem only in B28, fourteen subsidiary results only in proofs; reading, result and final-proof links verified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare-main", "prepare", "prepare-reading", "audit"))
    args = parser.parse_args()
    {"prepare-main": prepare_main, "prepare": prepare, "prepare-reading": prepare_reading, "audit": audit}[args.mode]()
