"""Prepare and audit B37's null-product companion editions.

These are source, identity and navigation checks, not a formal proof checker.
The pre-existing B37 registry baseline is immutable; additions have separate IDs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/nullproducts"
SOURCE = ROOT / "tex/b37/nullproducts"
MAIN_ID = "FiniteTwoProductZeroReconstruction"
MANIFEST = ROOT / "scripts/nullproducts-manifest.json"
HELPERS = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))
group, mask_comments = HELPERS["group"], HELPERS["mask_comments"]


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def id_map(rows):
    names = [row[1] for row in rows if row[0] == "ID"]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate local semantic IDs")
    return {row[1]: row[3] for row in rows if row[0] == "ID"}


def aux_labels(path):
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
            fields.append(line[slice(*value)])
        if len(fields) >= 4:
            if match[1] in result:
                raise ValueError(f"Duplicate label in {path.name}: {match[1]}")
            result[match[1]] = (fields[0].strip(), fields[3])
    return result


def manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8-sig"))


def main_records():
    data = manifest()
    base = ROOT / "registry/_B37"
    rows, labels = registry(base.with_suffix(".registry.tsv")), aux_labels(base.with_suffix(".aux"))
    ids = id_map(rows)
    if MAIN_ID not in ids:
        raise ValueError("B37: canonical reconstruction theorem is missing")
    expected = Counter(tuple(row[1:]) for row in data["canonical_registry"])
    current = Counter(tuple(row[1:]) for row in rows)
    if missing := expected - current:
        raise ValueError(f"B37: previous canonical records changed: {list(missing.elements())}")
    for label, expected_value in data["canonical_aux"].items():
        if labels.get(label) != tuple(expected_value):
            raise ValueError(f"B37: previous number/destination changed: {label}")
    if extra := set(ids) - set(id_map(data["canonical_registry"])) - {MAIN_ID}:
        raise ValueError(f"B37: unexpected new public identities: {sorted(extra)}")
    return rows, ids, labels


def write_import(name, rows, source_aux):
    labels = {row_label(row) for row in rows}
    (DIRECTORY / (name + ".registry.tsv")).write_text(
        "".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")
    selected = []
    for line in source_aux.read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            selected.append(line)
    target = DIRECTORY / (name + ".aux")
    target.write_text("\\relax\n" + "\n".join(selected) + "\n", encoding="utf-8")
    if set(aux_labels(target)) != labels:
        raise ValueError(f"{name}: filtered AUX is incomplete")


def prepare():
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows, _, _ = main_records()
    write_import("b37-external", rows, ROOT / "registry/_B37.aux")
    print("Null products: B37 canonical statements imported; private numbering is 37E.")


def proof_records():
    base = DIRECTORY / "_B37-nullproducts-proofs"
    rows, labels = registry(base.with_suffix(".registry.tsv")), aux_labels(base.with_suffix(".aux"))
    ids = id_map(rows)
    expected_ids = set(manifest()["private_ids"])
    if set(ids) != expected_ids:
        raise ValueError(f"Proof companion identities differ from manifest: {set(ids) ^ expected_ids}")
    if MAIN_ID in ids:
        raise ValueError("The proof companion must not redeclare the B37 theorem")
    for row in rows:
        label = row_label(row)
        if label not in labels or not labels[label][0].startswith("37E."):
            raise ValueError(f"Proof companion: missing or non-37E number: {label}")
        if row[0] != "ID" and row[3] != labels[label][0]:
            raise ValueError(f"Proof companion: registry/AUX number mismatch: {label}")
    return rows, ids, labels


def assert_disjoint(main_rows, proof_rows):
    if set(id_map(main_rows)) & set(id_map(proof_rows)):
        raise ValueError("Canonical and proof companion IDs overlap")
    if {row_label(r) for r in main_rows} & {row_label(r) for r in proof_rows}:
        raise ValueError("Canonical and proof companion labels overlap")


def prepare_reading():
    rows, _, _ = proof_records()
    main, _, _ = main_records()
    assert_disjoint(main, rows)
    write_import("proofs-reading", rows, DIRECTORY / "_B37-nullproducts-proofs.aux")
    print("Null products: reading imports refreshed from the canonical proof companion.")


def source_ids(text):
    result = []
    for match in re.finditer(r"\\Formula(?:Thm|Def|Axiom)DeltaK(R?)\b", text):
        parsed = HELPERS["call"](text, match.start(), 4 if match[1] else 3)
        key = parsed.args[2 if match[1] else 1]
        result.append(text[slice(*key)].strip())
    return result


def audit_sources():
    reading = mask_comments((SOURCE / "reading.tex").read_text(encoding="utf-8-sig"))
    if re.search(r"\\Formula(?:Thm|Def|Axiom)(?:Delta\w*|Auto)\b", reading):
        raise ValueError("The reading edition must not declare local numbered statements")
    main = mask_comments((SOURCE / "main-result.tex").read_text(encoding="utf-8-sig"))
    if source_ids(main) != [MAIN_ID]:
        raise ValueError("Exactly one public theorem declaration must appear in main-result.tex")
    declared = []
    for name in manifest()["proof_sources"]:
        text = mask_comments((SOURCE / name).read_text(encoding="utf-8-sig"))
        local_ids = source_ids(text)
        declared.extend(local_ids)
        if MAIN_ID in local_ids:
            raise ValueError(f"{name}: competing public theorem declaration")
        if HELPERS["inventory"](SOURCE / name)["control_characters"]:
            raise ValueError(f"{name}: invalid source control character")
    if len(declared) != len(set(declared)):
        raise ValueError("Private source statements declared more than once")
    if missing := set(declared) - set(manifest()["private_ids"]):
        raise ValueError(f"Private source IDs absent from manifest: {sorted(missing)}")
    print("Null-product source ownership and control-character audit passed.")


def audit():
    from pypdf import PdfReader

    audit_sources()
    main_rows, _, main_aux = main_records()
    proof_rows, _, proof_aux = proof_records()
    assert_disjoint(main_rows, proof_rows)
    for name, rows, labels in (("b37-external", main_rows, main_aux), ("proofs-reading", proof_rows, proof_aux)):
        if registry(DIRECTORY / (name + ".registry.tsv")) != rows:
            raise ValueError(f"{name}: stale registry import")
        expected_aux = {row_label(row): labels[row_label(row)] for row in rows}
        if aux_labels(DIRECTORY / (name + ".aux")) != expected_aux:
            raise ValueError(f"{name}: stale AUX import")
    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    cache = {}

    def links(pdf, reader):
        result = set()
        for action in publisher["remote_actions"](reader):
            target = (pdf.parent / publisher["file_name"](action)).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():
                raise ValueError(f"{pdf.name}: missing/outside target {target}")
            if target not in cache:
                cache[target] = set(PdfReader(target).named_destinations)
            destination = action.get("/D")
            if not isinstance(destination, str) or str(destination) not in cache[target]:
                raise ValueError(f"{pdf.name}: missing destination {destination} in {target}")
            result.add((target, str(destination)))
        return result

    main_pdf = ROOT / "registry/_B37.pdf"
    proof_pdf = DIRECTORY / "_B37-nullproducts-proofs.pdf"
    reading_pdf = DIRECTORY / "_B37-nullproducts-reading.pdf"
    for edition in ("proofs", "reading"):
        base = DIRECTORY / f"_B37-nullproducts-{edition}"
        if edition == "reading" and registry(base.with_suffix(".registry.tsv")):
            raise ValueError("Reading edition must have an empty local registry")
        if set(aux_labels(base.with_suffix(".aux"))) & set(main_aux):
            raise ValueError(f"{edition}: imported B37 labels registered locally")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        required = {f"nullproducts.{edition}"}
        if edition == "proofs":
            required |= {"nullproducts.proof." + key for key in manifest()["proof_targets"]}
        if missing := required - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing named targets: {sorted(missing)}")
        companion = "reading" if edition == "proofs" else "proofs"
        expected_links = {
            (main_pdf.resolve(), "nullproducts.main"),
            ((DIRECTORY / f"_B37-nullproducts-{companion}.pdf").resolve(), f"nullproducts.{companion}"),
        }
        if missing := expected_links - links(pdf, reader):
            raise ValueError(f"{edition}: missing navigation: {sorted(missing)}")
        print(f"Null products {edition}: {len(reader.pages)} pages; numbering, ownership and links passed.")
    main_reader = PdfReader(main_pdf)
    expected_links = {
        (proof_pdf.resolve(), "nullproducts.proofs"),
        (reading_pdf.resolve(), "nullproducts.reading"),
        (proof_pdf.resolve(), "nullproducts.proof.NPReconstructionConclusion"),
    }
    if missing := expected_links - links(main_pdf, main_reader):
        raise ValueError(f"B37: missing companion navigation: {sorted(missing)}")
    publisher["audit_local_targets"](main_reader, main_pdf)
    print("B37's original numbers and destinations are preserved; companion navigation passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "prepare-reading", "audit", "audit-sources"))
    args = parser.parse_args()
    {"prepare": prepare, "prepare-reading": prepare_reading, "audit": audit, "audit-sources": audit_sources}[args.mode]()
