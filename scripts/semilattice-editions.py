"""Prepare and audit the semilattice/order companions to B45.

All statements remain canonical in B45. The manifest preserves their original
registry, numbers, PDF destinations and the 23 extracted proof-table bodies.
These checks establish document integrity, not formal mathematical validity.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/semilattice"
SOURCE_DIRECTORY = ROOT / "tex/b45/semilattice"
MAIN_SOURCE = ROOT / "Bd. 45 - Halbverbände und Verbände.tex"
MANIFEST_PATH = ROOT / "scripts/semilattice-manifest.json"
SOURCE_HELPERS = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))
group = SOURCE_HELPERS["group"]
mask_comments = SOURCE_HELPERS["mask_comments"]


def manifest():
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8-sig"))
    ids = [item["id"] for item in data["statements"]]
    if len(ids) != 23 or len(set(ids)) != 23:
        raise ValueError("Semilattice manifest must contain exactly 23 distinct proof identities")
    return data


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def records_equal(actual, expected, owner):
    # The first structural field is an insertion index, not an identity.
    a, b = Counter(tuple(row[1:]) for row in actual), Counter(tuple(row[1:]) for row in expected)
    if a != b:
        raise ValueError(f"{owner}: registry differs from manifest; "
                         f"missing={list((b-a).elements())}, extra={list((a-b).elements())}")


def id_map(rows):
    keys = [row[1] for row in rows if row[0] == "ID"]
    if duplicates := [key for key, count in Counter(keys).items() if count != 1]:
        raise ValueError(f"Duplicate local IDs: {duplicates}")
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
            fields.append(line[value[0]:value[1]])
        if len(fields) >= 4:
            if match[1] in result:
                raise ValueError(f"{path.name}: duplicate local label {match[1]}")
            result[match[1]] = (fields[0].strip(), fields[3])
    return result


def main_records(data):
    base = ROOT / "registry/_B45"
    rows = registry(base.with_suffix(".registry.tsv"))
    records_equal(rows, data["canonical_registry"], "B45")
    ids = id_map(rows)
    aux = aux_labels(base.with_suffix(".aux"))
    for label, expected in data["canonical_aux"].items():
        if aux.get(label) != tuple(expected):
            raise ValueError(f"B45: original number/anchor changed: {label}, {aux.get(label)}")
    for item in data["statements"]:
        if ids.get(item["id"]) != item["label"]:
            raise ValueError(f"B45: canonical statement ownership changed: {item['id']}")
        if aux.get(item["label"]) != (item["number"], item["destination"]):
            raise ValueError(f"B45: migrated statement number/anchor changed: {item['id']}")
    return rows, aux


def write_import(rows):
    labels = {row_label(row) for row in rows}
    (DIRECTORY / "b45-external.registry.tsv").write_text(
        "".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")
    lines = []
    for line in (ROOT / "registry/_B45.aux").read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            lines.append(line)
    target = DIRECTORY / "b45-external.aux"
    target.write_text("\\relax\n" + "\n".join(lines) + "\n", encoding="utf-8")
    if set(aux_labels(target)) != labels:
        raise ValueError("b45-external: incomplete filtered AUX import")


def prepare():
    data = manifest()
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows, _ = main_records(data)
    write_import(rows)
    print("Semilattice: canonical B45 statements imported; both companion registries remain empty.")


def normalized(text):
    return re.sub(r"\s+", "", mask_comments(text))


def audit_sources():
    data = manifest()
    expected = {item["id"]: item for item in data["statements"]}
    main = mask_comments(MAIN_SOURCE.read_text(encoding="utf-8-sig"))
    shared = mask_comments((SOURCE_DIRECTORY / "statements.tex").read_text(encoding="utf-8-sig"))
    proofs = mask_comments((SOURCE_DIRECTORY / "proofs.tex").read_text(encoding="utf-8-sig"))
    declarations = {}
    pattern = r"\\expandafter\s*\\newcommand\s*\\csname\s*SemilatticeStatement@([^\s\\]+)\s*\\endcsname"
    for match in re.finditer(pattern, shared):
        body, _ = group(shared, match.end())
        if body is None or match[1] in declarations:
            raise ValueError(f"Missing/duplicate shared declaration: {match[1]}")
        declarations[match[1]] = shared[slice(*body)]
    if set(declarations) != set(expected):
        raise ValueError(f"Shared statement identities differ: {set(declarations) ^ set(expected)}")
    invocations = re.findall(r"\\SemilatticeStatement\s*\{([^}]+)\}", main)
    if Counter(invocations) != Counter(expected.keys()):
        raise ValueError("B45 must invoke each of the 23 shared statements exactly once")
    proof_statements = re.findall(r"\\SemilatticeProofStatement\s*\{([^}]+)\}", proofs)
    if Counter(proof_statements) != Counter(expected.keys()):
        raise ValueError("The proof companion must reproduce each shared statement exactly once")
    actual_proofs = {}
    for table in re.finditer(r"\\begin\{(tabproof\w*)\}.*?\\end\{\1\}", proofs, re.S):
        preceding = re.findall(r"\\SemilatticeProofStatement\s*\{([^}]+)\}", proofs[:table.start()])
        if not preceding or preceding[-1] in actual_proofs:
            raise ValueError("Missing/duplicate extracted table identity")
        actual_proofs[preceding[-1]] = table[0]
    if set(actual_proofs) != set(expected):
        raise ValueError(f"Extracted proof table identities differ: {set(actual_proofs) ^ set(expected)}")
    compact_main = normalized(main)
    for key, item in expected.items():
        if normalized(declarations[key]) != normalized(item["statement"]):
            raise ValueError(f"Shared statement differs from the original: {key}")
        if normalized(actual_proofs[key]) != normalized(item["proof"]):
            raise ValueError(f"Extracted proof table differs from the original: {key}")
        if normalized(item["proof"]) in compact_main:
            raise ValueError(f"Extracted proof table still appears in B45: {key}")
    print("Semilattice sources: 23 unchanged shared statements and 23 unchanged extracted proof tables.")


def audit():
    from pypdf import PdfReader

    audit_sources()
    data = manifest()
    canonical, canonical_aux = main_records(data)
    records_equal(registry(DIRECTORY / "b45-external.registry.tsv"), canonical, "b45-external")
    expected_aux = {row_label(row): canonical_aux[row_label(row)] for row in canonical}
    if aux_labels(DIRECTORY / "b45-external.aux") != expected_aux:
        raise ValueError("b45-external: stale AUX imports")
    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    cache = {}

    def links(pdf, reader):
        result = set()
        for action in publisher["remote_actions"](reader):
            target = (pdf.parent / publisher["file_name"](action)).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():
                raise ValueError(f"{pdf.name}: missing/outside PDF target: {target}")
            if target not in cache:
                cache[target] = set(PdfReader(target).named_destinations)
            destination = action.get("/D")
            if not isinstance(destination, str) or str(destination) not in cache[target]:
                raise ValueError(f"{pdf.name}: missing/unsupported destination {destination} in {target}")
            result.add((target, str(destination)))
        return result

    main_pdf = ROOT / "registry/_B45.pdf"
    proof_targets = {"semilattice.proof." + item["id"] for item in data["statements"]}
    for edition in ("proofs", "reading"):
        base = DIRECTORY / f"_B45-semilattice-{edition}"
        if registry(base.with_suffix(".registry.tsv")):
            raise ValueError(f"{edition}: companion must not register local statements")
        if set(aux_labels(base.with_suffix(".aux"))) & set(canonical_aux):
            raise ValueError(f"{edition}: canonical B45 labels must only be imported")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        expected_targets = {f"semilattice.{edition}"}
        if edition == "proofs":
            expected_targets.update(proof_targets)
        if missing := expected_targets - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF targets: {sorted(missing)}")
        actual_links = links(pdf, reader)
        companion = "reading" if edition == "proofs" else "proofs"
        expected_links = {
            ((DIRECTORY / f"_B45-semilattice-{companion}.pdf").resolve(), f"semilattice.{companion}"),
            (main_pdf.resolve(), "semilattice.main"),
        }
        if edition == "proofs":
            expected_links.update((main_pdf.resolve(), item["destination"]) for item in data["statements"])
        if missing := expected_links - actual_links:
            raise ValueError(f"{edition}: missing navigation: {sorted(missing)}")
        print(f"Semilattice {edition}: {len(reader.pages)} pages; empty registry, canonical references and all PDF links passed.")

    reader = PdfReader(main_pdf)
    publisher["assert_build_ready"](main_pdf, reader)
    publisher["audit_local_targets"](reader, main_pdf)
    expected_targets = {"semilattice.main"} | {target for _, target in data["canonical_aux"].values()}
    if missing := expected_targets - set(reader.named_destinations):
        raise ValueError(f"B45: original PDF targets missing: {sorted(missing)}")
    proof_pdf = (DIRECTORY / "_B45-semilattice-proofs.pdf").resolve()
    expected_links = {
        ((DIRECTORY / "_B45-semilattice-reading.pdf").resolve(), "semilattice.reading"),
        (proof_pdf, "semilattice.proofs"),
        *((proof_pdf, target) for target in proof_targets),
    }
    if missing := expected_links - links(main_pdf, reader):
        raise ValueError(f"B45: missing companion/proof navigation: {sorted(missing)}")
    print("B45: all canonical identities, formulas, numbers and destinations preserved; 23 direct proof links verified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "audit", "audit-sources"))
    args = parser.parse_args()
    {"prepare": prepare, "audit": audit, "audit-sources": audit_sources}[args.mode]()
