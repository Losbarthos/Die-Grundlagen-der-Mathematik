"""Audit the B37 index/period split, original identities and companion PDF links."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/index-period"
MANIFEST_PATH = ROOT / "scripts/index-period-manifest.json"
MANIFEST_SHA256 = "91d348f2ae53f0245defe9b31fb37405b998520f9a9920de3d041aa508baa680"
if hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest() != MANIFEST_SHA256:
    raise ValueError("The original B37 index/period snapshot must remain unchanged")
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
IDENTITIES = MANIFEST["identities"]
PRIVATE_IDS = {"B37IPPositivePowersTyped", "B37IPRepetitionSetWellDefined"}
PROOF_TARGETS = set(MANIFEST["proof_targets"]) | {"FiniteSemigroupPowerRepetitionSetDef"}
PUBLIC_LABELS = {row[3] if row[0] == "ID" else row[1] for row in MANIFEST["canonical_registry"]}
registry_helpers = runpy.run_path(str(ROOT / "scripts/registry-editions.py"))
registry_records = registry_helpers["registry_records"]
validate_private_registry = registry_helpers["validate_private_registry"]
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


def check_owner(rows, aux, *, proofs):
    identifiers = id_map(rows)
    if proofs:
        if set(aux) & PUBLIC_LABELS:
            raise ValueError("proofs: public B37 declarations were registered locally")
        validate_private_registry(rows, aux, PRIVATE_IDS, "37I")
    else:
        if registry_records(rows) != registry_records(MANIFEST["canonical_registry"]):
            raise ValueError("B37: original declaration identities, formulas or metadata changed")
        for label in PUBLIC_LABELS:
            if aux.get(label) != tuple(MANIFEST["canonical_aux"][label]):
                raise ValueError(f"B37: original number or destination changed: {label}")
    return rows, identifiers, aux


def main_records():
    base = ROOT / "registry/_B37"
    return check_owner(registry(base.with_suffix(".registry.tsv")),
                       aux_labels(base.with_suffix(".aux")), proofs=False)


def proof_records():
    base = DIRECTORY / "_B37-index-period-proofs"
    return check_owner(registry(base.with_suffix(".registry.tsv")),
                       aux_labels(base.with_suffix(".aux")), proofs=True)


def prepare():
    rows, _, _ = main_records()
    write_import("b37-external", rows, (ROOT / "registry/_B37.aux").read_text(encoding="utf-8-sig"))
    print("Index/period: complete original B37 statements imported without redeclaration.")


def prepare_reading():
    rows, _, _ = proof_records()
    write_import("proofs-reading", rows,
                 (DIRECTORY / "_B37-index-period-proofs.aux").read_text(encoding="utf-8-sig"))
    print("Index/period: private proof statements imported into the reading edition.")


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
    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    main_pdf = ROOT / "registry/_B37.pdf"
    proof_pdf = DIRECTORY / "_B37-index-period-proofs.pdf"
    reading_pdf = DIRECTORY / "_B37-index-period-reading.pdf"
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
        required = {f"index-period.{edition}"}
        if edition == "proofs":
            required |= {"index-period.proof." + key for key in PROOF_TARGETS}
        if missing := required - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF destinations: {sorted(missing)}")
        companion = reading_pdf if edition == "proofs" else proof_pdf
        companion_name = "reading" if edition == "proofs" else "proofs"
        require_links(links(pdf, reader), {
            (main_pdf.resolve(), "index-period.main"),
            (companion.resolve(), f"index-period.{companion_name}"),
        }, edition)
        print(f"Index/period {edition}: original identities and PDF links passed ({len(reader.pages)} pages).")

    reader = PdfReader(main_pdf)
    if "index-period.main" not in reader.named_destinations:
        raise ValueError("B37: missing index/period entry")
    require_links(links(main_pdf, reader, own_pair_only=True), {
        (reading_pdf.resolve(), "index-period.reading"),
        (proof_pdf.resolve(), "index-period.proofs"),
        *((proof_pdf.resolve(), "index-period.proof." + key) for key in PROOF_TARGETS),
    }, "B37")
    print(f"B37 keeps all original statements; proofs owns only {len(PRIVATE_IDS)} new private 37I results.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "prepare-reading", "audit"))
    args = parser.parse_args()
    {"prepare": prepare, "prepare-reading": prepare_reading, "audit": audit}[args.mode]()
