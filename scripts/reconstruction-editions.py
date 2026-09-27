"""Prepare and audit the group-reconstruction companions to B40.

All statements remain canonical in B40. The manifest preserves their original
registry, numbers, PDF destinations and the 12 extracted proof-table bodies.
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
DIRECTORY = ROOT / "registry/reconstruction"
SOURCE_DIRECTORY = ROOT / "tex/b40/reconstruction"
MAIN_SOURCE = ROOT / "Bd. 40 - Gruppen.tex"
MANIFEST_PATH = ROOT / "scripts/reconstruction-manifest.json"
SOURCE_HELPERS = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))
group = SOURCE_HELPERS["group"]
mask_comments = SOURCE_HELPERS["mask_comments"]


def manifest():
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8-sig"))
    ids = [item["id"] for item in data["statements"]]
    if len(ids) != 12 or len(set(ids)) != 12:
        raise ValueError("Reconstruction manifest must contain exactly 12 distinct proof identities")
    # Later foundation results are appended to B40. Keep the original snapshot
    # intact and record only these explicitly reviewed additions separately.
    if data.get("additional_registry"):
        additional_ids = [row[1] for row in data["additional_registry"] if row[0] == "ID"]
        if sorted(additional_ids) != ["GroupIsoInverse", "SemigroupIsoGroupTransport"]:
            raise ValueError("Unexpected additional B40 foundation identities")
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
    base = ROOT / "registry/_B40"
    rows = registry(base.with_suffix(".registry.tsv"))
    records_equal(rows, data["canonical_registry"] + data.get("additional_registry", []), "B40")
    ids = id_map(rows)
    aux = aux_labels(base.with_suffix(".aux"))
    for label, expected in (data["canonical_aux"] | data.get("additional_aux", {})).items():
        if aux.get(label) != tuple(expected):
            raise ValueError(f"B40: original number/anchor changed: {label}, {aux.get(label)}")
    for item in data["statements"]:
        if ids.get(item["id"]) != item["label"]:
            raise ValueError(f"B40: canonical statement ownership changed: {item['id']}")
        if aux.get(item["label"]) != (item["number"], item["destination"]):
            raise ValueError(f"B40: migrated statement number/anchor changed: {item['id']}")
    for item in data["inner_statements"]:
        if ids.get(item["id"]) != item["label"]:
            raise ValueError(f"B40: canonical inner statement ownership changed: {item['id']}")
        if aux.get(item["label"]) != (item["number"], item["destination"]):
            raise ValueError(f"B40: original inner statement number/anchor changed: {item['id']}")
    return rows, aux


def write_import(rows):
    labels = {row_label(row) for row in rows}
    (DIRECTORY / "b40-external.registry.tsv").write_text(
        "".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")
    lines = []
    for line in (ROOT / "registry/_B40.aux").read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            lines.append(line)
    target = DIRECTORY / "b40-external.aux"
    target.write_text("\\relax\n" + "\n".join(lines) + "\n", encoding="utf-8")
    if set(aux_labels(target)) != labels:
        raise ValueError("b40-external: incomplete filtered AUX import")


def prepare():
    data = manifest()
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows, _ = main_records(data)
    write_import(rows)
    print("Reconstruction: canonical B40 statements imported; both companion registries remain empty.")


def normalized(text):
    return re.sub(r"\s+", "", mask_comments(text))


def audit_sources():
    data = manifest()
    expected = {item["id"]: item for item in data["statements"]}
    main = mask_comments(MAIN_SOURCE.read_text(encoding="utf-8-sig"))
    shared = mask_comments((SOURCE_DIRECTORY / "statements.tex").read_text(encoding="utf-8-sig"))
    proofs = mask_comments((SOURCE_DIRECTORY / "proofs.tex").read_text(encoding="utf-8-sig"))
    declarations = {}
    pattern = r"\\expandafter\s*\\newcommand\s*\\csname\s*ReconstructionStatement@([^\s\\]+)\s*\\endcsname"
    for match in re.finditer(pattern, shared):
        body, _ = group(shared, match.end())
        if body is None or match[1] in declarations:
            raise ValueError(f"Missing/duplicate shared declaration: {match[1]}")
        declarations[match[1]] = shared[slice(*body)]
    if set(declarations) != set(expected):
        raise ValueError(f"Shared statement identities differ: {set(declarations) ^ set(expected)}")
    invocations = re.findall(r"\\ReconstructionStatement\s*\{([^}]+)\}", main)
    if Counter(invocations) != Counter(expected.keys()):
        raise ValueError("B40 must invoke each of the 12 shared statements exactly once")
    proof_statements = re.findall(r"\\ReconstructionProofStatement\s*\{([^}]+)\}", proofs)
    if Counter(proof_statements) != Counter(expected.keys()):
        raise ValueError("The proof companion must reproduce each shared statement exactly once")
    actual_proofs = {}
    for table in re.finditer(r"\\begin\{(tabproof\w*)\}.*?\\end\{\1\}", proofs, re.S):
        preceding = re.findall(r"\\ReconstructionProofStatement\s*\{([^}]+)\}", proofs[:table.start()])
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
            raise ValueError(f"Extracted proof table still appears in B40: {key}")
    for item in data["retained_statements"]:
        if normalized(item["statement"]) not in compact_main or normalized(item["proof"]) not in compact_main:
            raise ValueError(f"B40: retained general foundation changed or missing: {item['id']}")
    inner = data["inner_statements"][0]
    match = re.search(r"\\newcommand\{\\ReconstructionProductMemberFormula\}", shared)
    body, _ = group(shared, match.end()) if match else (None, None)
    if not body or normalized(shared[slice(*body)]) != normalized(inner["formula"]):
        raise ValueError("The preserved inner product-member statement differs from the original")
    if main.count(r"\ReconstructionProductMemberStatement") != 1:
        raise ValueError("B40 must retain exactly one canonical inner product-member statement")
    print("Reconstruction sources: 12 unchanged shared statements and extracted tables; "
          "one preserved inner statement and seven unchanged foundation tables.")


def audit():
    from pypdf import PdfReader

    audit_sources()
    data = manifest()
    canonical, canonical_aux = main_records(data)
    records_equal(registry(DIRECTORY / "b40-external.registry.tsv"), canonical, "b40-external")
    expected_aux = {row_label(row): canonical_aux[row_label(row)] for row in canonical}
    if aux_labels(DIRECTORY / "b40-external.aux") != expected_aux:
        raise ValueError("b40-external: stale AUX imports")
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

    main_pdf = ROOT / "registry/_B40.pdf"
    proof_targets = {"reconstruction.proof." + item["id"] for item in data["statements"]}
    for edition in ("proofs", "reading"):
        base = DIRECTORY / f"_B40-reconstruction-{edition}"
        if registry(base.with_suffix(".registry.tsv")):
            raise ValueError(f"{edition}: companion must not register local statements")
        if set(aux_labels(base.with_suffix(".aux"))) & set(canonical_aux):
            raise ValueError(f"{edition}: canonical B40 labels must only be imported")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        expected_targets = {f"reconstruction.{edition}"}
        if edition == "proofs":
            expected_targets.update(proof_targets)
        if missing := expected_targets - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF targets: {sorted(missing)}")
        actual_links = links(pdf, reader)
        companion = "reading" if edition == "proofs" else "proofs"
        expected_links = {
            ((DIRECTORY / f"_B40-reconstruction-{companion}.pdf").resolve(), f"reconstruction.{companion}"),
            (main_pdf.resolve(), "reconstruction.main"),
        }
        if edition == "proofs":
            expected_links.update((main_pdf.resolve(), item["destination"]) for item in data["statements"])
            expected_links.update((main_pdf.resolve(), item["destination"]) for item in data["inner_statements"])
        if missing := expected_links - actual_links:
            raise ValueError(f"{edition}: missing navigation: {sorted(missing)}")
        print(f"Reconstruction {edition}: {len(reader.pages)} pages; empty registry, canonical references and all PDF links passed.")

    reader = PdfReader(main_pdf)
    publisher["assert_build_ready"](main_pdf, reader)
    publisher["audit_local_targets"](reader, main_pdf)
    expected_targets = {"reconstruction.main"} | {
        target for _, target in (data["canonical_aux"] | data.get("additional_aux", {})).values()
    }
    if missing := expected_targets - set(reader.named_destinations):
        raise ValueError(f"B40: original PDF targets missing: {sorted(missing)}")
    proof_pdf = (DIRECTORY / "_B40-reconstruction-proofs.pdf").resolve()
    expected_links = {
        ((DIRECTORY / "_B40-reconstruction-reading.pdf").resolve(), "reconstruction.reading"),
        (proof_pdf, "reconstruction.proofs"),
        *((proof_pdf, target) for target in proof_targets),
    }
    if missing := expected_links - links(main_pdf, reader):
        raise ValueError(f"B40: missing companion/proof navigation: {sorted(missing)}")
    print("B40: all canonical identities, formulas, numbers and destinations preserved; 12 direct proof links verified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "audit", "audit-sources"))
    args = parser.parse_args()
    {"prepare": prepare, "audit": audit, "audit-sources": audit_sources}[args.mode]()
