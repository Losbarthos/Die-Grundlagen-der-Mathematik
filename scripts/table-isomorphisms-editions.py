"""Preserve B37 identities while extracting multiplication-table proof tables.

The checks cover declaration ownership, numbering, formulas and PDF links.
They are not a formal proof checker.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/table-isomorphisms"
MANIFEST_PATH = ROOT / "scripts/table-isomorphisms-manifest.json"
MANIFEST_SHA256 = "0584f9f3fb5375f7876f6d2f250f789eacd4bbdb600133614aaf102cd0183bb3"
if hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest() != MANIFEST_SHA256:
    raise ValueError("The original B37 table-isomorphism snapshot must remain unchanged")
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
IDENTITIES = MANIFEST["identities"]
PROOF_IDS = set(MANIFEST["proof_ids"])
PROOF_LABELS = {IDENTITIES[key]["label"] for key in PROOF_IDS}
PRIVATE_IDS = {
    "B37TAutomorphismIdentity", "B37TAutomorphismComposition", "B37TAutomorphismInverse",
    "B37TIsoBridge", "B37TArbitraryCarrierCriterion", "B37TDoubleInverse",
    "B37TNumberingFactorization", "B37TRenumbering", "B37TOrbitTupleCandidatesDef",
    "B37TCodeOrbitCandidates", "B37TFiniteProduct", "B37TNumberingsDef",
    "B37TFiniteNumberings", "B37TCodeCandidatesDef", "B37TTableTupleMapDef",
    "B37TCodeCandidateImage", "B37TFiniteCodeCandidates",
    "B37TLexBaseOrderDef", "B37TLexBaseIrreflexive", "B37TLexBaseTransitive",
    "B37TLexBaseTrichotomy", "B37TLexNaturalBase", "B37TLexIterationBase",
    "B37TLexBoundedPair", "B37TLexBoundedTriple",
    "B37TLexTupleDef", "B37TLexOrderDef", "B37TLexCoordinate",
    "B37TLexFirstDifference", "B37TLexIrreflexive", "B37TLexTrichotomy",
    "B37TLexEarlyWitness", "B37TLexEqualWitness", "B37TLexLateWitness",
    "B37TLexTransitive", "B37TLexAsymmetric", "B37TLexWeakReflexive",
    "B37TLexWeakAntisymmetric", "B37TLexWeakTransitive", "B37TLexTotalOrder",
    "B37TLexFiniteMinimum", "B37TLexEmptyLength", "B37TLexCodeCandidatesTyped",
    "B37TLexCodeMinimum", "B37TMinimalCodeDef", "B37TLexMinimumMembership",
    "B37TMinimalCodeForward", "B37TMinimalCodeBackward", "B37TMinimalCodeCriterion",
}
PUBLIC_IDS = set(IDENTITIES) - PROOF_IDS
PUBLIC_LABELS = {IDENTITIES[key]["label"] for key in PUBLIC_IDS}
PROOF_TARGETS = set(MANIFEST["proof_targets"]) | {
    "FiniteSemigroupMultiplicationTableDef", "FiniteSemigroupRelabelledOperationDef",
    "automorphisms", "arbitrary-carriers", "renumbering", "finite-candidates", "minimal-code",
}
registry_records = runpy.run_path(str(ROOT / "scripts/registry-editions.py"))["registry_records"]
validate_private_registry = runpy.run_path(str(ROOT / "scripts/registry-editions.py"))["validate_private_registry"]
group = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))["group"]


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def id_map(rows):
    keys = [row[1] for row in rows if row[0] == "ID"]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate local result identities")
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
                raise ValueError(f"Duplicate AUX label: {match[1]}")
            result[match[1]] = (fields[0].strip(), fields[3])
    return result


def write_import(name, rows, aux_text):
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    labels = {row_label(row) for row in rows}
    (DIRECTORY / (name + ".registry.tsv")).write_text(
        "".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")
    lines = []
    for line in aux_text.splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            lines.append(line)
    target = DIRECTORY / (name + ".aux")
    target.write_text("\\relax\n" + "\n".join(lines) + "\n", encoding="utf-8")
    if set(aux_labels(target)) != labels:
        raise ValueError(f"{name}: incomplete AUX import")


def baseline_rows(*, proofs):
    return [row for row in MANIFEST["canonical_registry"]
            if (row_label(row) in PROOF_LABELS) == proofs]


def check_owner(rows, aux, *, proofs):
    owner = "proofs" if proofs else "B37"
    expected = baseline_rows(proofs=proofs)
    # Keep current display metadata as well as formulas, IDs and numbering.
    protected = [row for row in rows if row_label(row) in PROOF_LABELS] if proofs else rows
    if registry_records(protected) != registry_records(expected):
        raise ValueError(f"{owner}: original declaration identities, formulas or metadata changed")
    identifiers = id_map(rows)
    expected_labels = {row_label(row) for row in expected}
    forbidden = PUBLIC_LABELS if proofs else PROOF_LABELS
    if set(aux) & forbidden:
        raise ValueError(f"{owner}: declarations from the other owner occur in its AUX")
    for label in expected_labels:
        if aux.get(label) != tuple(MANIFEST["canonical_aux"][label]):
            raise ValueError(f"{owner}: original number or destination changed: {label}")
    if proofs:
        if set(identifiers) != PROOF_IDS | PRIVATE_IDS:
            raise ValueError(f"proofs: missing or unexpected local IDs: {set(identifiers) ^ (PROOF_IDS | PRIVATE_IDS)}")
        private_labels = {identifiers[key] for key in PRIVATE_IDS}
        if set(map(row_label, rows)) != PROOF_LABELS | private_labels:
            raise ValueError("proofs: a local statement has no permitted semantic ID")
        validate_private_registry(
            [row for row in rows if row_label(row) in private_labels], aux, PRIVATE_IDS, "37T")
    return rows, identifiers, aux


def main_records():
    base = ROOT / "registry/_B37"
    return check_owner(registry(base.with_suffix(".registry.tsv")),
                       aux_labels(base.with_suffix(".aux")), proofs=False)


def proof_records():
    base = DIRECTORY / "_B37-table-isomorphisms-proofs"
    return check_owner(registry(base.with_suffix(".registry.tsv")),
                       aux_labels(base.with_suffix(".aux")), proofs=True)


def prepare_main():
    """Bootstrap B37 without needing a previously built proof companion."""
    rows = baseline_rows(proofs=True)
    aux_text = "".join(
        r"\newlabel{%s}{{%s}{1}{}{%s}{}}" %
        (label, *MANIFEST["canonical_aux"][label]) + "\n"
        for label in sorted(PROOF_LABELS))
    write_import("proofs-main", rows, aux_text)
    print("Table-isomorphism B37 imports prepared with the seven original H identities.")


def prepare():
    rows, _, _ = main_records()
    write_import("b37-external", rows, (ROOT / "registry/_B37.aux").read_text(encoding="utf-8-sig"))
    print("Public B37 statements imported; no duplicate declarations in the companions.")


def prepare_reading():
    rows, _, _ = proof_records()
    aux_text = (DIRECTORY / "_B37-table-isomorphisms-proofs.aux").read_text(encoding="utf-8-sig")
    write_import("proofs-reading", rows, aux_text)
    write_import("proofs-main", rows, aux_text)
    print("Reading and B37 imports refreshed from the actual H proof destinations.")


def check_import(name, expected, expected_aux):
    if registry_records(registry(DIRECTORY / (name + ".registry.tsv"))) != registry_records(expected):
        raise ValueError(f"{name}: stale registry import")
    imported = aux_labels(DIRECTORY / (name + ".aux"))
    if set(imported) != {row_label(row) for row in expected}:
        raise ValueError(f"{name}: unexpected or missing AUX imports")
    if any(value != expected_aux[label] for label, value in imported.items()):
        raise ValueError(f"{name}: stale original number or destination")


def require_links(actual, expected, owner):
    if missing := expected - actual:
        raise ValueError(f"{owner}: missing PDF navigation: {sorted(missing)}")


def audit():
    from pypdf import PdfReader

    public_rows, _, public_aux = main_records()
    proof_rows, _, proof_aux = proof_records()
    check_import("b37-external", public_rows, public_aux)
    check_import("proofs-reading", proof_rows, proof_aux)
    check_import("proofs-main", proof_rows, proof_aux)
    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    main_pdf = ROOT / "registry/_B37.pdf"
    proof_pdf = DIRECTORY / "_B37-table-isomorphisms-proofs.pdf"
    reading_pdf = DIRECTORY / "_B37-table-isomorphisms-reading.pdf"
    cache = {}

    def links(pdf, reader, *, own_pair_only=False):
        result = set()
        for action in publisher["remote_actions"](reader):
            target = (pdf.parent / publisher["file_name"](action)).resolve()
            if own_pair_only and target.parent != DIRECTORY.resolve():
                continue
            if not target.is_relative_to(ROOT) or not target.is_file():
                raise ValueError(f"{pdf.name}: missing or outside PDF target: {target}")
            if target not in cache:
                cache[target] = set(PdfReader(target).named_destinations)
            destination = str(action.get("/D"))
            if destination not in cache[target]:
                raise ValueError(f"{pdf.name}: missing destination {destination} in {target.name}")
            result.add((target, destination))
        return result

    for edition, pdf in (("proofs", proof_pdf), ("reading", reading_pdf)):
        local = registry(pdf.with_suffix(".registry.tsv"))
        if registry_records(local) != registry_records(proof_rows if edition == "proofs" else []):
            raise ValueError(f"{edition}: imported declarations were registered locally")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        required = {f"table-isomorphisms.{edition}"}
        if edition == "proofs":
            required |= {"table-isomorphisms.proof." + key for key in PROOF_TARGETS}
            required |= {proof_aux[label][1] for label in PROOF_LABELS}
        if missing := required - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF destinations: {sorted(missing)}")
        companion = reading_pdf if edition == "proofs" else proof_pdf
        companion_name = "reading" if edition == "proofs" else "proofs"
        require_links(links(pdf, reader), {
            (main_pdf.resolve(), "table-isomorphisms.main"),
            (companion.resolve(), f"table-isomorphisms.{companion_name}"),
        }, edition)
        print(f"Table-isomorphism {edition}: original identities and PDF links passed ({len(reader.pages)} pages).")

    reader = PdfReader(main_pdf)
    if "table-isomorphisms.main" not in reader.named_destinations:
        raise ValueError("B37: missing table-isomorphism entry")
    require_links(links(main_pdf, reader, own_pair_only=True), {
        (reading_pdf.resolve(), "table-isomorphisms.reading"),
        (proof_pdf.resolve(), "table-isomorphisms.proofs"),
        *((proof_pdf.resolve(), "table-isomorphisms.proof." + key) for key in PROOF_TARGETS),
    }, "B37")
    print(f"B37 owns every original public declaration; proofs owns seven unchanged H-results and {len(PRIVATE_IDS)} private 37T results.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare-main", "prepare", "prepare-reading", "audit"))
    args = parser.parse_args()
    {"prepare-main": prepare_main, "prepare": prepare, "prepare-reading": prepare_reading, "audit": audit}[args.mode]()
