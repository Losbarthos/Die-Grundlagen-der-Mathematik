"""Prepare and audit the Mogiljanskaja companions and their public B28 result.

The checks cover statement identities, numbering and PDF navigation. They do
not constitute a machine verification of the mathematical inference rules.
"""
from __future__ import annotations

import argparse
from collections import Counter
import re
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/mogiljanskaja"
MAIN_ID = "MogiljanskajaPairCounterexample"
FOUNDATION_IDS = (
    "MogiljanskajaLayerLDef", "MogiljanskajaLayerDDef",
    "MogiljanskajaAElementsDef", "MogiljanskajaBElementsDef",
    "MogiljanskajaAIndexUnique", "MogiljanskajaBIndexUnique",
    "MogiljanskajaLayerLMembership", "MogiljanskajaLayerDMembership",
    "MogiljanskajaLayerLImage", "MogiljanskajaLayerDImage",
    "MogiljanskajaLayersDisjoint", "MogiljanskajaDPrimeDef",
    "MogiljanskajaReserveMembership", "MogiljanskajaReserveMarkerFacts",
    "B21ReserveAvoidsFirstTwoRows", "B21ReserveMarkerDistinct",
    "MogiljanskajaReserveCoreFacts", "MogiljanskajaRowParametrizationsDef",
    "MogiljanskajaRowParametrizationsBijective", "B21DeltaBijective",
    "B21UpsilonBijective", "MogiljanskajaThetaDef",
    "MogiljanskajaThetaBijective", "MogiljanskajaShiftValueInV",
    "MogiljanskajaShiftSequenceDef", "MogiljanskajaShiftSequenceFacts",
    "B21ShiftSequenceInjective", "B21ShiftImageTermSetDef",
    "MogiljanskajaShiftSequenceImage", "MogiljanskajaSigmaDef",
    "MogiljanskajaSigmaBijective", "MogiljanskajaVParametrizationDef",
    "MogiljanskajaVParametrizationBijective", "MogiljanskajaDPrimeIndexSetDef",
    "MogiljanskajaDPrimeParametrizationDef", "B21TaggedTwoLayerEquality",
    "MogiljanskajaDPrimeParametrizationBijective", "B21DPrimeFamilyBijective",
    "MogiljanskajaFamilyImages",
)
FOUNDATION_ALIASES = (
    "B21ReserveAvoidsFirstTwoRows", "B21ReserveMarkerDistinct",
    "B21DeltaBijective", "B21UpsilonBijective",
    "B21ShiftSequenceInjective", "B21DPrimeFamilyBijective",
)
CORE_IDS = (
    "MogiljanskajaPairDef", "MogiljanskajaBasePairProperties",
    "MogiljanskajaProductPartsDef", "MogiljanskajaPowerProductFormula",
    "MogiljanskajaReserveMapsDef", "MogiljanskajaReserveMapProperties",
    "MogiljanskajaPhiDef", "MogiljanskajaPowerSemigroupIsomorphism",
    "MogiljanskajaConstructedPairCounterexample",
)
DETAIL_IDS = (
    "MogiljanskajaRuleDef", "MogiljanskajaArgumentM1WellDefined",
    "MogiljanskajaArgumentM2Semigroups", "MogiljanskajaArgumentM3Infinite",
    "MogiljanskajaArgumentM4ProductStatus", "MogiljanskajaArgumentM5NotIsomorphic",
    "MogiljanskajaArgumentM6ProductClassification",
    "MogiljanskajaArgumentM7AbsorptionHypotheses",
    "MogiljanskajaArgumentM8PsiBijective", "MogiljanskajaArgumentM9EtaBijective",
    "MogiljanskajaArgumentM10EtaFixedPart", "MogiljanskajaArgumentM11RectangleProtected",
    "MogiljanskajaArgumentM12PhiBijective", "MogiljanskajaArgumentM13PhiInvariants",
    "MogiljanskajaArgumentM14ProductPartsInvariant", "MogiljanskajaArgumentM15ProductFixed",
    "MogiljanskajaArgumentM16PowerIsomorphism",
    "MogiljanskajaArgumentM17CounterexampleWitness",
)
ALL_IDS = FOUNDATION_IDS + CORE_IDS + DETAIL_IDS


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def id_map(rows):
    return {row[1]: row[3] for row in rows if row[0] == "ID"}


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def aux_labels(path):
    # AUX titles contain nested TeX groups; balance them instead of flattening.
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


def write_import(name, labels, rows, aux_text):
    selected = [row for row in rows if row_label(row) in labels]
    (DIRECTORY / (name + ".registry.tsv")).write_text(
        "".join("\t".join(row) + "\n" for row in selected), encoding="utf-8"
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


def main_records():
    rows = registry(ROOT / "registry/_B28.registry.tsv")
    identifiers = id_map(rows)
    if MAIN_ID not in identifiers:
        raise ValueError("B28: missing public counterexample theorem")
    if misplaced := set(ALL_IDS) & set(identifiers):
        raise ValueError(f"B28: companion declarations still in main volume: {sorted(misplaced)}")
    return rows, identifiers


def b21_records():
    rows = registry(ROOT / "registry/_B21.registry.tsv")
    identifiers = id_map(rows)
    if misplaced := set(ALL_IDS) & set(identifiers):
        raise ValueError(f"B21: companion declarations still in main volume: {sorted(misplaced)}")
    return rows, identifiers


def assert_disjoint(rows, identifiers, proof_rows, proof_ids, volume):
    if set(identifiers) & set(proof_ids) or {row_label(row) for row in rows} & {row_label(row) for row in proof_rows}:
        raise ValueError(f"proofs: local identities or labels overlap {volume}")


def proof_records():
    base = DIRECTORY / "_B28-mog-proofs"
    rows = registry(base.with_suffix(".registry.tsv"))
    identifiers = id_map(rows)
    if set(identifiers) != set(ALL_IDS):
        raise ValueError(f"proofs: unexpected/missing result identities: {set(identifiers) ^ set(ALL_IDS)}")
    if Counter(row[2] for row in rows if row[0] == "ID") != Counter(definition=18, theorem=48):
        raise ValueError("proofs: expected 18 definitions, 42 theorems and six theorem-part aliases")
    aliases = {key for key, label in identifiers.items() if label.startswith("thm:pp:")}
    if aliases != set(FOUNDATION_ALIASES):
        raise ValueError(f"proofs: unexpected/missing theorem-part aliases: {aliases ^ set(FOUNDATION_ALIASES)}")
    labels = aux_labels(base.with_suffix(".aux"))
    for row in rows:
        label = row_label(row)
        if label not in labels or not labels[label][0].startswith("28E."):
            raise ValueError(f"proofs: missing or non-companion number for {label}")
        if row[0] != "ID" and row[3] != labels[label][0]:
            raise ValueError(f"proofs: registry and AUX numbers disagree for {label}")
    for chapter, expected_ids in ((1, FOUNDATION_IDS), (2, CORE_IDS), (3, DETAIL_IDS)):
        for key in expected_ids:
            if not labels[identifiers[key]][0].startswith(f"28E.{chapter}."):
                raise ValueError(f"proofs: {key} does not belong to companion chapter {chapter}")
    return rows, identifiers, labels


def prepare():
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    foundational_rows, _ = b21_records()
    write_import("b21-external", {row_label(row) for row in foundational_rows}, foundational_rows,
                 (ROOT / "registry/_B21.aux").read_text(encoding="utf-8-sig"))
    rows, identifiers = main_records()
    all_labels = {row_label(row) for row in rows}
    aux_path = ROOT / "registry/_B28.aux"
    aux_text = aux_path.read_text(encoding="utf-8-sig")
    # Both editions import the complete remaining B21 and B28 registries.
    # The example-specific foundations and construction are owned by the
    # proof companion under its separate 28E number prefix.
    write_import("b28-external", all_labels, rows, aux_text)
    write_import("b28-reading", all_labels, rows, aux_text)
    labels = aux_labels(aux_path)
    (DIRECTORY / "position.tex").write_text(
        "% Generated independent companion numbering; do not edit.\n"
        "\\renewcommand{\\FormulaBandID}{28E}\n"
        "\\setcounter{file}{28}\n"
        "\\setcounter{chapter}{0}\n"
        "\\setcounter{section}{0}\n"
        "\\setcounter{subsection}{0}\n"
        "\\setcounter{formulaDef}{0}\n"
        "\\setcounter{formulaThm}{0}\n", encoding="utf-8"
    )
    print("Mogiljanskaja imports prepared; canonical main theorem: "
          + labels[identifiers[MAIN_ID]][0])


def prepare_reading():
    rows, identifiers, _ = proof_records()
    main, main_ids = main_records()
    assert_disjoint(main, main_ids, rows, identifiers, "B28")
    foundational, foundational_ids = b21_records()
    assert_disjoint(foundational, foundational_ids, rows, identifiers, "B21")
    labels = {row_label(row) for row in rows}
    write_import("proofs-reading", labels, rows,
                 (DIRECTORY / "_B28-mog-proofs.aux").read_text(encoding="utf-8-sig"))
    print("Mogiljanskaja reading imports prepared from 60 canonical companion declarations and six aliases.")


def audit():
    from pypdf import PdfReader

    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    canonical, canonical_ids = main_records()
    canonical_aux = aux_labels(ROOT / "registry/_B28.aux")
    foundational, foundational_ids = b21_records()
    foundational_aux = aux_labels(ROOT / "registry/_B21.aux")
    proof_rows, proof_ids, proof_aux = proof_records()
    assert_disjoint(canonical, canonical_ids, proof_rows, proof_ids, "B28")
    assert_disjoint(foundational, foundational_ids, proof_rows, proof_ids, "B21")
    for name, expected, expected_aux in (
        ("b21-external", foundational, foundational_aux),
        ("b28-external", canonical, canonical_aux),
        ("b28-reading", canonical, canonical_aux),
        ("proofs-reading", proof_rows, proof_aux),
    ):
        if Counter(map(tuple, registry(DIRECTORY / (name + ".registry.tsv")))) != Counter(map(tuple, expected)):
            raise ValueError(f"{name}: stale or incomplete canonical registry import")
        imported_aux = aux_labels(DIRECTORY / (name + ".aux"))
        for label in {row_label(row) for row in expected}:
            if imported_aux.get(label) != expected_aux.get(label):
                raise ValueError(f"{name}: stale or incomplete AUX import for {label}")
    cache = {}
    for edition in ("reading", "proofs"):
        base = DIRECTORY / f"_B28-mog-{edition}"
        rows = registry(base.with_suffix(".registry.tsv"))
        identifiers = id_map(rows)
        expected_ids = ALL_IDS if edition == "proofs" else ()
        if set(identifiers) != set(expected_ids):
            raise ValueError(f"{edition}: unexpected/missing result identities: {set(identifiers) ^ set(expected_ids)}")
        expected_rows = Counter(map(tuple, proof_rows)) if edition == "proofs" else Counter()
        if Counter(tuple(row) for row in rows) != expected_rows:
            raise ValueError(f"{edition}: unexpected local registry records")
        labels = aux_labels(base.with_suffix(".aux"))
        for key in expected_ids:
            label = proof_ids[key]
            if identifiers[key] != label or labels.get(label) != proof_aux[label]:
                raise ValueError(f"{edition}: inconsistent label/number for {key}")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        destinations = set(reader.named_destinations)
        if f"mog.{edition}" not in destinations:
            raise ValueError(f"{edition}: edition entry target missing from PDF")
        for key in expected_ids:
            if labels[proof_ids[key]][1] not in destinations:
                raise ValueError(f"{edition}: result target missing from PDF: {key}")
            if f"mog.statement.{key}" not in destinations:
                raise ValueError(f"{edition}: semantic statement target missing from PDF: {key}")
        companion = "proofs" if edition == "reading" else "reading"
        companion_target = (DIRECTORY / f"_B28-mog-{companion}.pdf").resolve()
        companion_links = 0
        for action in publisher["remote_actions"](reader):
            target = (pdf.parent / publisher["file_name"](action)).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():
                raise ValueError(f"{edition}: missing/outside build target: {target}")
            if target not in cache:
                cache[target] = set(PdfReader(target).named_destinations)
            if str(action.get("/D")) not in cache[target]:
                raise ValueError(f"{edition}: remote destination missing: {target}, {action.get('/D')}")
            if target == companion_target and str(action.get("/D")) == f"mog.{companion}":
                companion_links += 1
        if not companion_links:
            raise ValueError(f"{edition}: missing navigation to companion edition")
        print(f"Mogiljanskaja {edition}: {len(expected_ids)} local identities, independent "
              f"canonical ownership, PDF destinations and links passed ({len(reader.pages)} pages).")

    main_pdf = ROOT / "registry/_B28.pdf"
    main_reader = PdfReader(main_pdf)
    if canonical_aux[canonical_ids[MAIN_ID]][1] not in main_reader.named_destinations:
        raise ValueError("B28: public counterexample target missing")
    proof_target = (DIRECTORY / "_B28-mog-proofs.pdf").resolve()
    expected_proof_links = {f"mog.statement.{CORE_IDS[-1]}"}
    actual_proof_links = {
        str(action.get("/D")) for action in publisher["remote_actions"](main_reader)
        if (main_pdf.parent / publisher["file_name"](action)).resolve() == proof_target
    }
    if missing := expected_proof_links - actual_proof_links:
        raise ValueError(f"B28: direct statement-to-proof links missing: {sorted(missing)}")
    theorem_anchor = canonical_aux[canonical_ids[MAIN_ID]][1]
    theorem_page = main_reader.get_destination_page_number(main_reader.named_destinations[theorem_anchor])
    if theorem_page is None or not 0 <= theorem_page < len(main_reader.pages):
        raise ValueError("B28: main theorem target has no valid page")
    linked_editions = set()
    edition_targets = {
        ((DIRECTORY / f"_B28-mog-{edition}.pdf").resolve(), f"mog.{edition}"): edition
        for edition in ("reading", "proofs")
    }
    for annotation in main_reader.pages[theorem_page].get("/Annots", []):
        action = annotation.get_object().get("/A")
        if action is None:
            continue
        action = action.get_object()
        if action.get("/S") != "/GoToR":
            continue
        target = (main_pdf.parent / publisher["file_name"](action)).resolve()
        key = (target, str(action.get("/D")))
        if key in edition_targets:
            linked_editions.add(edition_targets[key])
    if missing := {"reading", "proofs"} - linked_editions:
        raise ValueError(f"B28: main theorem page {theorem_page + 1} lacks companion links: {sorted(missing)}")
    print(f"Mogiljanskaja main volume: only the public counterexample theorem retained; "
          f"both companion links present on theorem page {theorem_page + 1}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "prepare-reading", "audit"))
    args = parser.parse_args()
    {"prepare": prepare, "prepare-reading": prepare_reading, "audit": audit}[args.mode]()
