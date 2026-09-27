"""Prepare and audit the Frankl special-case companions to B46.

All statements remain canonical in B46. The manifest preserves their original
registry, numbers, PDF destinations and the 17 extracted proof-table bodies.
The later rare-triple example adds one canonical existence theorem and keeps
its auxiliary statements and proofs in the independent 46E companion space.
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
DIRECTORY = ROOT / "registry/frankl"
SOURCE_DIRECTORY = ROOT / "tex/b46/frankl"
MAIN_SOURCE = ROOT / "Bd. 46 - Frankls Vermutung.tex"
MANIFEST_PATH = ROOT / "scripts/frankl-manifest.json"
TRIPLE_ID = "FranklRareTripleExists"
SOURCE_HELPERS = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))
group = SOURCE_HELPERS["group"]
mask_comments = SOURCE_HELPERS["mask_comments"]


def manifest():
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8-sig"))
    ids = [item["id"] for item in data["statements"]]
    if len(ids) != 17 or len(set(ids)) != 17:
        raise ValueError("Frankl manifest must contain exactly 17 distinct proof identities")
    if Counter(item["kind"] for item in data["statements"]) != {"theorem": 16, "definition": 1}:
        raise ValueError("Frankl manifest must include the 16 theorem tables and one definition proof")
    if sum(item["canonical_id"] is None for item in data["statements"]) != 3:
        raise ValueError("Frankl manifest must preserve the three formula-keyed statements")
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
    base = ROOT / "registry/_B46"
    rows = registry(base.with_suffix(".registry.tsv"))
    ids = id_map(rows)
    if TRIPLE_ID not in ids:
        raise ValueError("B46: missing new rare-triple existence theorem")
    triple_label = ids[TRIPLE_ID]
    original_rows = [row for row in rows if row_label(row) != triple_label]
    records_equal(original_rows, data["canonical_registry"], "B46 original results")
    additions = [row for row in rows if row_label(row) == triple_label]
    if len(additions) != 2 or sum(row[0] == "ID" for row in additions) != 1:
        raise ValueError("B46: exactly one new canonical theorem and its ID are permitted")
    if any(row[2] != "theorem" for row in additions):
        raise ValueError("B46: the rare-triple addition must be a theorem")
    aux = aux_labels(base.with_suffix(".aux"))
    for label, expected in data["canonical_aux"].items():
        if aux.get(label) != tuple(expected):
            raise ValueError(f"B46: original number/anchor changed: {label}, {aux.get(label)}")
    for item in data["statements"]:
        canonical_id = item["canonical_id"]
        if canonical_id is not None and ids.get(canonical_id) != item["label"]:
            raise ValueError(f"B46: canonical statement ownership changed: {item['id']}")
        if canonical_id is None and item["id"] in ids:
            raise ValueError(f"B46: local companion identity became a canonical ID: {item['id']}")
        if aux.get(item["label"]) != (item["number"], item["destination"]):
            raise ValueError(f"B46: migrated statement number/anchor changed: {item['id']}")
    return rows, aux


def write_import(rows):
    labels = {row_label(row) for row in rows}
    (DIRECTORY / "b46-external.registry.tsv").write_text(
        "".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")
    lines = []
    for line in (ROOT / "registry/_B46.aux").read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            lines.append(line)
    target = DIRECTORY / "b46-external.aux"
    target.write_text("\\relax\n" + "\n".join(lines) + "\n", encoding="utf-8")
    if set(aux_labels(target)) != labels:
        raise ValueError("b46-external: incomplete filtered AUX import")


def prepare():
    data = manifest()
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows, _ = main_records(data)
    write_import(rows)
    print("Frankl: canonical B46 statements imported; new proof auxiliaries use 46E.")


def normalized(text):
    return re.sub(r"\s+", "", mask_comments(text))


def audit_sources():
    data = manifest()
    expected = {item["id"]: item for item in data["statements"]}
    main = mask_comments(MAIN_SOURCE.read_text(encoding="utf-8-sig"))
    shared = mask_comments((SOURCE_DIRECTORY / "statements.tex").read_text(encoding="utf-8-sig"))
    proofs = mask_comments((SOURCE_DIRECTORY / "proofs.tex").read_text(encoding="utf-8-sig"))
    declarations = {}
    pattern = r"\\expandafter\s*\\newcommand\s*\\csname\s*FranklStatement@([^\s\\]+)\s*\\endcsname"
    for match in re.finditer(pattern, shared):
        body, _ = group(shared, match.end())
        if body is None or match[1] in declarations:
            raise ValueError(f"Missing/duplicate shared declaration: {match[1]}")
        declarations[match[1]] = shared[slice(*body)]
    if set(declarations) != set(expected):
        raise ValueError(f"Shared statement identities differ: {set(declarations) ^ set(expected)}")
    invocations = re.findall(r"\\FranklStatement\s*\{([^}]+)\}", main)
    if Counter(invocations) != Counter(expected.keys()):
        raise ValueError("B46 must invoke each of the 17 shared statements exactly once")
    proof_statements = re.findall(r"\\FranklProofStatement\s*\{([^}]+)\}", proofs)
    if Counter(proof_statements) != Counter(expected.keys()):
        raise ValueError("The proof companion must reproduce each shared statement exactly once")
    if invocations != list(expected) or proof_statements != list(expected):
        raise ValueError("The canonical volume and proof companion must retain the original statement order")
    actual_proofs = {}
    actual_contexts = {}
    for table in re.finditer(r"\\begin\{(tabproof\w*)\}.*?\\end\{\1\}", proofs, re.S):
        preceding = list(re.finditer(r"\\FranklProofStatement\s*\{([^}]+)\}", proofs[:table.start()]))
        if not preceding or preceding[-1][1] in actual_proofs:
            raise ValueError("Missing/duplicate extracted table identity")
        identity = preceding[-1][1]
        actual_proofs[identity] = table[0]
        actual_contexts[identity] = proofs[preceding[-1].end():table.start()]
    if set(actual_proofs) != set(expected):
        raise ValueError(f"Extracted proof table identities differ: {set(actual_proofs) ^ set(expected)}")
    compact_main = normalized(main)
    for key, item in expected.items():
        if normalized(declarations[key]) != normalized(item["statement"]):
            raise ValueError(f"Shared statement differs from the original: {key}")
        if normalized(actual_proofs[key]) != normalized(item["proof"]):
            raise ValueError(f"Extracted proof table differs from the original: {key}")
        if item["proof_context"] and normalized(item["proof_context"]) not in normalized(actual_contexts[key]):
            raise ValueError(f"Extracted proof lost its original local notation: {key}")
        if normalized(item["proof"]) in compact_main:
            raise ValueError(f"Extracted proof table still appears in B46: {key}")
    print("Frankl sources: 17 unchanged shared statements and 17 unchanged extracted proof tables.")
    triple = mask_comments((SOURCE_DIRECTORY / "triple-statement.tex").read_text(encoding="utf-8-sig"))
    if len(re.findall(r"\\FormulaThmDeltaK\b", triple)) != 1 or "{" + TRIPLE_ID + "}" not in triple:
        raise ValueError("Rare-triple source must define exactly one canonical theorem")
    if r"\FranklRareTripleStatement" not in main or "triple-proofs.tex" in main or "triple-notation.tex" in main:
        raise ValueError("B46 must contain only the new main theorem, not the auxiliary construction or proof")


def audit():
    from pypdf import PdfReader

    audit_sources()
    supplements = runpy.run_path(str(ROOT / "scripts/frankl-triple-audit.py"))
    declared = supplements["audit_sources"]()
    data = manifest()
    canonical, canonical_aux = main_records(data)
    records_equal(registry(DIRECTORY / "b46-external.registry.tsv"), canonical, "b46-external")
    expected_aux = {row_label(row): canonical_aux[row_label(row)] for row in canonical}
    if aux_labels(DIRECTORY / "b46-external.aux") != expected_aux:
        raise ValueError("b46-external: stale AUX imports")
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

    main_pdf = ROOT / "registry/_B46.pdf"
    proof_targets = {"frankl.proof." + item["id"] for item in data["statements"]} | {"frankl.proof." + TRIPLE_ID}
    for edition in ("proofs", "reading"):
        base = DIRECTORY / f"_B46-frankl-{edition}"
        local_rows = registry(base.with_suffix(".registry.tsv"))
        if edition == "reading" and local_rows:
            raise ValueError("The reading edition must not register local statements")
        if edition == "proofs":
            local_ids = id_map(local_rows)
            if not local_ids or any(not key.startswith("FranklTriple") for key in local_ids):
                raise ValueError("The proof edition may register only the rare-triple auxiliaries")
            if set(local_ids) & set(id_map(canonical)):
                raise ValueError("Companion auxiliaries duplicate canonical B46 IDs")
            if set(declared) != set(local_ids):
                raise ValueError("The proof registry must contain exactly the declared rare-triple auxiliaries")
            local_aux = aux_labels(base.with_suffix(".aux"))
            for row in local_rows:
                if row_label(row) not in local_aux or not local_aux[row_label(row)][0].startswith("46E."):
                    raise ValueError("Every proof auxiliary must use the independent 46E number space")
        if set(aux_labels(base.with_suffix(".aux"))) & set(canonical_aux):
            raise ValueError(f"{edition}: canonical B46 labels must only be imported")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        expected_targets = {f"frankl.{edition}"}
        if edition == "proofs":
            expected_targets.update(proof_targets)
        if missing := expected_targets - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF targets: {sorted(missing)}")
        actual_links = links(pdf, reader)
        companion = "reading" if edition == "proofs" else "proofs"
        expected_links = {
            ((DIRECTORY / f"_B46-frankl-{companion}.pdf").resolve(), f"frankl.{companion}"),
            (main_pdf.resolve(), "frankl.main"),
        }
        if edition == "proofs":
            expected_links.update((main_pdf.resolve(), item["destination"]) for item in data["statements"])
            expected_links.add((main_pdf.resolve(), canonical_aux[id_map(canonical)[TRIPLE_ID]][1]))
        if missing := expected_links - actual_links:
            raise ValueError(f"{edition}: missing navigation: {sorted(missing)}")
        print(f"Frankl {edition}: {len(reader.pages)} pages; statement ownership, canonical references and all PDF links passed.")

    reader = PdfReader(main_pdf)
    publisher["assert_build_ready"](main_pdf, reader)
    publisher["audit_local_targets"](reader, main_pdf)
    expected_targets = {"frankl.main"} | {target for _, target in data["canonical_aux"].values()}
    if missing := expected_targets - set(reader.named_destinations):
        raise ValueError(f"B46: original PDF targets missing: {sorted(missing)}")
    proof_pdf = (DIRECTORY / "_B46-frankl-proofs.pdf").resolve()
    expected_links = {
        ((DIRECTORY / "_B46-frankl-reading.pdf").resolve(), "frankl.reading"),
        (proof_pdf, "frankl.proofs"),
        *((proof_pdf, target) for target in proof_targets),
    }
    if missing := expected_links - links(main_pdf, reader):
        raise ValueError(f"B46: missing companion/proof navigation: {sorted(missing)}")
    print("B46: all original identities, formulas, numbers and destinations preserved; one new existence theorem and 18 direct proof links verified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "audit", "audit-sources"))
    args = parser.parse_args()
    {"prepare": prepare, "audit": audit, "audit-sources": audit_sources}[args.mode]()
