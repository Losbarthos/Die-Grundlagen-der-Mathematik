"""Prepare and audit the power-semigroup companions to B28.

All active statements remain canonical in B28. The manifest preserves the
original registry and extracted proof bodies as history. An explicit numbering
revision displays active helpers consecutively while preserving their semantic
IDs, labels and PDF destinations.
The original retirement removes ten redundant associativity helpers. A separate
user-authorized revision retires three unused helpers while preserving exactly
their six old PDF targets as unregistered compatibility anchors. Seven active
helpers have independent proof tables before use; all historical snapshots and
retained canonical identities, labels and destinations remain protected.
Explicit proof revisions retain their history and pin the approved new tables
with normalized SHA256 digests and their required references.
The explicitly recorded product-definition revision changes only its structural
registry formula; its ID, number, title and PDF destination remain unchanged.
The complete outer-product theorem extension remains a protected historical
snapshot. An explicit classification revision moves those same two identities
into the H1-H7 helper list, preserving their old native PDF targets as unregistered
compatibility anchors. Both original official theorems remain unchanged.
A separate premise-bundling revision preserves the complete preceding active
proof records and pins all nine approved table lengths without changing statements.
These checks establish document integrity, not formal mathematical validity.
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
registry_records = runpy.run_path(str(ROOT / "scripts/registry-editions.py"))["registry_records"]
DIRECTORY = ROOT / "registry/power"
SOURCE_DIRECTORY = ROOT / "tex/b28/power"
MAIN_SOURCE = ROOT / "Bd. 28 - Halbgruppen.tex"
MANIFEST_PATH = ROOT / "scripts/power-manifest.json"
SOURCE_HELPERS = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))
group, mask_comments = SOURCE_HELPERS["group"], SOURCE_HELPERS["mask_comments"]
PROOF_IDS = {"PowerSemigroupProductMembership", "NonemptyPowerSemigroup"}
DERIVED_STATEMENT_ORDER = (
    "PowerSemigroupLeftOuterProductRepresentation",
    "PowerSemigroupRightOuterProductRepresentation",
)
DERIVED_STATEMENT_IDENTITIES = {
    key: {"label": f"thm:auto:28.2.4.{index}", "number": f"28.2.4.{index}",
          "destination": f"formulaThm.2.4.{index}"}
    for index, key in enumerate(DERIVED_STATEMENT_ORDER, 3)
}
DERIVED_STATEMENT_SNAPSHOT_SHA256 = "9a243463ac175d8ed2212220bbe192306b8cac86e3ce1ca0452f9e6c6cef0115"
PROOF_NORMALIZATION = "tex-comments-and-whitespace-v1"
BUNDLING_PREVIOUS_PROOF_REVISIONS_SHA256 = "8c45b8c6c3b3deba080695d528483ad26074e1c7f76536195f44ee03ad6a7bf8"
BUNDLING_PREVIOUS_SEPARATE_PROOFS_SHA256 = "a6f2d155ea843f8efef187dce08cf48b4fa3b59326dbf84ff9108d7ac1fe5fba"
BUNDLED_PROOF_ROWS = {
    "PowerSemigroupProductClosure": 4,
    "PowerSemigroupCarrierElement": 3,
    "PowerSemigroupProductContains": 5,
    "PowerSemigroupProductSubset": 3,
    "PowerSemigroupLeftOuterProductRepresentation": 5,
    "PowerSemigroupRightOuterProductRepresentation": 5,
    "PowerSemigroupAssociativity": 10,
    "NonemptyPowerSemigroup": 6,
    "PowerSemigroupProductMembership": 6,
}
ORIGINAL_REGISTRY_SHA256 = "507de11991fe6970e0bbb62f9450efbf163fd42f26b1e78d4080cad99db92bb0"
ORIGINAL_DEFINITION_SHA256 = "2a2a4547b7a87f05e0a749be9ab68b80a579c097be4a358671479619f89eb487"
PRODUCT_DEFINITION_ID = "PowerSemigroupProductDef"
PRODUCT_DEFINITION_LABEL = "def:auto:28.2.4.1"
PRODUCT_DEFINITION_NUMBER = "28.2.4.1"
PRODUCT_DEFINITION_DESTINATION = "section*.14"
ORIGINAL_PRODUCT_FORMULA = r"""
  \begin{aligned}[t]
    &\SemigroupAlg{A}{\star}\dsep X,Y\in\PowNE{A}\vdash{}\\[-2pt]
    &X\star_{\mathcal P}Y\coloneqq
      \bigl\{z\in A\bigm|
        \exists x\in X\,\exists y\in Y\,(z=x\star y)\bigr\}
  \end{aligned}
"""
REVISED_PRODUCT_FORMULA = r"""
  \begin{aligned}[t]
    &\SemigroupAlg{A}{\star}\dsep X,Y\in\PowNE{A}\vdash{}\\[-2pt]
    &X\star_{\mathcal P}Y\coloneqq
      \{x\star y\mid x\in X,\ y\in Y\}
  \end{aligned}
"""
RETIRED_INNER_IDS = {
    "PowerSemigroupElementAssociativity",
    "PowerSemigroupLeftTripleMembershipForward",
    "PowerSemigroupLeftTripleMembershipBackward",
    "PowerSemigroupRightTripleMembershipForward",
    "PowerSemigroupRightTripleMembershipBackward",
    "PowerSemigroupTripleWitnessAssociativityForward",
    "PowerSemigroupTripleWitnessAssociativityBackward",
    "PowerSemigroupLeftTripleMembershipEquivalence",
    "PowerSemigroupTripleWitnessAssociativityEquivalence",
    "PowerSemigroupRightTripleMembershipEquivalence",
}


ADDITIONALLY_RETIRED_INNER_ORDER = (
    "PowerSemigroupProductNonempty",
    "PowerSemigroupProductWitnesses",
    "PowerSemigroupProductTermImage",
)
ADDITIONALLY_RETIRED_INNER_IDS = set(ADDITIONALLY_RETIRED_INNER_ORDER)
FIVE_HELPER_ORDER = (
    "PowerSemigroupProductClosure",
    "PowerSemigroupCarrierElement",
    "PowerSemigroupProductContains",
    "PowerSemigroupProductSubset",
    "PowerSemigroupAssociativity",
)
ACTIVE_INNER_ORDER = (*FIVE_HELPER_ORDER[:4], *DERIVED_STATEMENT_ORDER, FIVE_HELPER_ORDER[4])
RECLASSIFIED_INNER_IDENTITIES = {
    key: {"label": f"thm:pp:28.2.4.2:{slot}", "destination": f"proofpartnr.28.2.4.2.{slot}",
          "number": f"28.2.4.2(H{index})"}
    for index, (key, slot) in enumerate(zip(DERIVED_STATEMENT_ORDER, (19, 20)), 5)
}
RECLASSIFIED_INNER_TITLES = {
    "PowerSemigroupLeftOuterProductRepresentation": "Äußere Darstellung bei linker Klammerung",
    "PowerSemigroupRightOuterProductRepresentation": "Äußere Darstellung bei rechter Klammerung",
}
HISTORICAL_NUMBERING_ORDER = (
    *ACTIVE_INNER_ORDER[:4],
    "PowerSemigroupProductNonempty",
    "PowerSemigroupProductWitnesses",
    "PowerSemigroupAssociativity",
    "PowerSemigroupProductTermImage",
)


def all_retired_inner_ids():
    return RETIRED_INNER_IDS | ADDITIONALLY_RETIRED_INNER_IDS


def historical_inner_statements(data):
    return data["inner_statements"] + data.get("added_inner_statements", {}).get("statements", [])


def active_inner_statements(data):
    items = {item["id"]: item for item in historical_inner_statements(data)
             + data.get("helper_classification_revision", {}).get("statements", [])
             if item["id"] not in all_retired_inner_ids()}
    changes = data.get("helper_numbering_revision", {}).get("statements", {})
    return [dict(items[key], number=changes[key]["number"]) if key in changes else items[key]
            for key in ACTIVE_INNER_ORDER]


def active_main_statements(data):
    return data["statements"]


def validate_derived_statements(data):
    extension = data.get("derived_statements", {})
    snapshot = json.dumps(extension, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if hashlib.sha256(snapshot.encode("utf-8")).hexdigest() != DERIVED_STATEMENT_SNAPSHOT_SHA256:
        raise ValueError("The complete historical outer-product theorem extension must remain unchanged")
    validate_revision_provenance(extension, "The historical outer-product representation theorems")
    items = extension.get("statements", [])
    if [item.get("id") for item in items] != list(DERIVED_STATEMENT_ORDER):
        raise ValueError("The explicit extension must record exactly the left and right outer-product theorems")
    for item in items:
        key = item["id"]
        if any(item.get(field) != value for field, value in DERIVED_STATEMENT_IDENTITIES[key].items()):
            raise ValueError(f"The new theorem must retain its approved canonical identity: {key}")
        if not item.get("title", "").strip() or not item.get("statement", "").strip() or not item.get("proof", "").strip():
            raise ValueError(f"The representation theorem needs its complete statement and proof snapshot: {key}")
        if item.get("normalization") != PROOF_NORMALIZATION:
            raise ValueError(f"Unsupported representation proof normalization: {key}")
        if item.get("statement_normalized_sha256") != proof_digest(item["statement"]):
            raise ValueError(f"The representation statement snapshot changed without its explicit record: {key}")
        if item.get("revised_normalized_sha256") != proof_digest(item["proof"]):
            raise ValueError(f"The representation proof snapshot differs from its recorded digest: {key}")
        masked = mask_comments(item["statement"])
        calls = list(re.finditer(r"\\FormulaThmDeltaK\b", masked))
        if len(calls) != 1:
            raise ValueError(f"Each representation snapshot must be one complete theorem declaration: {key}")
        invocation = SOURCE_HELPERS["call"](masked, calls[0].start(), 3)
        if (normalized(masked[slice(*invocation.args[1])]) != key
                or normalized(masked[invocation.start:invocation.end]) != normalized(masked)):
            raise ValueError(f"Representation declaration identity/body mismatch: {key}")
        if len(re.findall(r"\\proofstep(?:widestar|wide)\b", mask_comments(item["proof"]))) != 6:
            raise ValueError(f"Each representation theorem requires its approved six-row proof: {key}")
        if not item.get("required_references") or not all(
            isinstance(ref, str) and ref.strip() for ref in item["required_references"]
        ):
            raise ValueError(f"The representation proof needs explicit required references: {key}")
    rows = extension.get("canonical_registry_rows", [])
    labels = {item["label"] for item in items}
    if len(rows) != 4 or any(row_label(row) not in labels for row in rows):
        raise ValueError("The extension must record exactly the four actual canonical registry rows")
    for item in items:
        expected_id = ["ID", item["id"], "theorem", item["label"]]
        if rows.count(expected_id) != 1:
            raise ValueError(f"The extension must retain exactly its actual theorem-ID registry row: {item['id']}")
        structural = [row for row in rows if row[0] != "ID" and row_label(row) == item["label"]]
        if (len(structural) != 1 or len(structural[0]) != 7
                or structural[0][2:4] != ["theorem", item["number"]]
                or not re.fullmatch(r"am[0-9a-f]{32}", structural[0][4])
                or not structural[0][5].strip()):
            raise ValueError(f"The extension must retain its actual structural theorem registry row: {item['id']}")
    expected_aux = {item["label"]: [item["number"], item["destination"]] for item in items}
    if extension.get("canonical_aux") != expected_aux:
        raise ValueError("The extension must record exactly its two actual canonical AUX identities")
    if extension.get("proof_targets") != list(DERIVED_STATEMENT_ORDER):
        raise ValueError("The extension must record precisely its two new direct proof-target identities")


def validate_helper_classification(data):
    revision = data.get("helper_classification_revision", {})
    validate_revision_provenance(revision, "The explicit outer-product helper classification")
    items = revision.get("statements", [])
    if [item.get("id") for item in items] != list(DERIVED_STATEMENT_ORDER):
        raise ValueError("Exactly the two historical outer-product identities must be reclassified as helpers")
    previous = {item["id"]: item for item in data["derived_statements"]["statements"]}
    expected_mapping = {}
    expected_compatibility = []
    for item in items:
        key = item["id"]
        old = previous[key]
        identity = RECLASSIFIED_INNER_IDENTITIES[key]
        if any(item.get(field) != value for field, value in identity.items()):
            raise ValueError(f"Reclassified helper must use precisely its approved slot 19/20 identity: {key}")
        declaration = mask_comments(old["statement"])
        invocation = SOURCE_HELPERS["call"](declaration, re.search(r"\\FormulaThmDeltaK\b", declaration).start(), 3)
        formula = declaration[slice(*invocation.args[0])]
        if (item.get("title") != RECLASSIFIED_INNER_TITLES[key]
                or normalized(item.get("formula", "")) != normalized(formula)
                or normalized(item.get("key", "")) != normalized(formula)):
            raise ValueError(f"Reclassification must preserve the historical formula and the approved shorter helper title: {key}")
        if (item.get("normalization") != PROOF_NORMALIZATION
                or normalized(item.get("proof", "")) != normalized(old["proof"])
                or item.get("revised_normalized_sha256") != old["revised_normalized_sha256"]
                or item.get("required_references") != old["required_references"]):
            raise ValueError(f"The six-row outer-product proof must remain unchanged during classification: {key}")
        expected_mapping[key] = {"old_number": old["number"], "old_label": old["label"],
                                 "old_destination": old["destination"], **identity}
        expected_compatibility.append({"id": key, "destination": old["destination"],
                                       "replacement_destination": identity["destination"]})
    if revision.get("mapping") != expected_mapping:
        raise ValueError("The classification must explicitly record both old-to-new canonical identity mappings")
    expected_rows = [["ID", item["id"], "theorem", item["label"]] for item in items]
    if revision.get("canonical_registry_rows") != expected_rows:
        raise ValueError("The two reclassified helpers must register only their actual ID rows")
    if revision.get("canonical_aux") != {item["label"]: [item["number"], item["destination"]] for item in items}:
        raise ValueError("The classification must record exactly its two new helper AUX entries")
    if revision.get("compatibility_targets") != expected_compatibility:
        raise ValueError("The two former native theorem targets must remain explicit unregistered compatibility anchors")
    if revision.get("proof_targets") != list(DERIVED_STATEMENT_ORDER):
        raise ValueError("The reclassification must preserve both semantic direct-proof target IDs")


def active_canonical_registry(data):
    retired_labels = {item["label"] for item in historical_inner_statements(data)
                      if item["id"] in all_retired_inner_ids()}
    revision = data["definition_revision"]
    historical = (data["canonical_registry"]
                  + data.get("added_inner_statements", {}).get("canonical_registry_rows", [])
                  + data.get("helper_classification_revision", {}).get("canonical_registry_rows", []))
    return [revision["revised_registry_row"] if row == revision["original_registry_row"] else row
            for row in historical if row_label(row) not in retired_labels]


def active_canonical_aux(data):
    retired_labels = {item["label"] for item in historical_inner_statements(data)
                      if item["id"] in all_retired_inner_ids()}
    historical = (data["canonical_aux"]
                  | data.get("added_inner_statements", {}).get("canonical_aux", {})
                  | data.get("helper_classification_revision", {}).get("canonical_aux", {}))
    result = {label: value for label, value in historical.items() if label not in retired_labels}
    for item in data.get("helper_numbering_revision", {}).get("statements", {}).values():
        result[item["label"]] = [item["number"], item["destination"]]
    return result


def validate_revision_provenance(record, owner):
    if not record.get("reason", "").strip() or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", record.get("date", "")):
        raise ValueError(f"{owner} needs its explicit reason and date")


def validate_helper_numbering(record, order, original, owner):
    validate_revision_provenance(record, owner)
    if record.get("order") != list(order) or set(record.get("statements", {})) != set(order):
        raise ValueError(f"{owner} must record exactly its approved helper order")
    for index, key in enumerate(order, 1):
        expected = {"label": original[key]["label"], "destination": original[key]["destination"],
                    "old_number": original[key]["number"], "number": f"28.2.4.2(H{index})"}
        if record["statements"][key] != expected:
            raise ValueError(f"{owner} must preserve the semantic identity and destination: {key}")


def validate_helper_retirement(data):
    original = {item["id"]: item for item in historical_inner_statements(data)}
    retirement = data.get("helper_retirement_revision", {})
    validate_revision_provenance(retirement, "The three-helper retirement revision")
    removed = [original[key] for key in ADDITIONALLY_RETIRED_INNER_ORDER]
    if retirement.get("statements") != removed or retirement.get("proof_targets") != list(ADDITIONALLY_RETIRED_INNER_ORDER):
        raise ValueError("The new retirement must record exactly the unused nonempty, witnesses and term-image helpers")
    labels = {item["label"] for item in removed}
    historical_rows = data["canonical_registry"] + data["added_inner_statements"]["canonical_registry_rows"]
    historical_aux = data["canonical_aux"] | data["added_inner_statements"]["canonical_aux"]
    if retirement.get("canonical_registry_rows") != [row for row in historical_rows if row_label(row) in labels]:
        raise ValueError("The new retirement must record precisely its three historical registry rows")
    if retirement.get("canonical_aux") != {label: value for label, value in historical_aux.items() if label in labels}:
        raise ValueError("The new retirement must record precisely its three historical AUX identities")
    history = data.get("helper_numbering_revision_history", [])
    if not history:
        raise ValueError("The original eight-helper numbering revision must remain in history")
    for required_order in (HISTORICAL_NUMBERING_ORDER, FIVE_HELPER_ORDER):
        if not any(record.get("record", {}).get("order") == list(required_order) for record in history):
            raise ValueError("Both the original eight-helper and preceding five-helper numbering revisions must remain in history")
    for record in history:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", record.get("recorded_date", "")):
            raise ValueError("Historical helper numbering needs its recording date")
        historical = record.get("record", {})
        order = historical.get("order")
        if order == list(HISTORICAL_NUMBERING_ORDER):
            approved_order = HISTORICAL_NUMBERING_ORDER
        elif order == list(FIVE_HELPER_ORDER):
            approved_order = FIVE_HELPER_ORDER
        else:
            raise ValueError("Historical numbering must preserve an explicitly approved H1-H8 or H1-H5 revision")
        validate_helper_numbering(historical, approved_order, original, "The historical helper numbering revision")
    current_origins = original | {
        key: {**identity, "number": DERIVED_STATEMENT_IDENTITIES[key]["number"]}
        for key, identity in RECLASSIFIED_INNER_IDENTITIES.items()
    }
    validate_helper_numbering(data.get("helper_numbering_revision", {}), ACTIVE_INNER_ORDER, current_origins,
                              "The current H1-H7 numbering revision")
    compatibility = data.get("legacy_pdf_compatibility", {})
    validate_revision_provenance(compatibility, "Legacy PDF compatibility")
    statements = {item["id"]: item for item in data["statements"]}
    canonical_replacements = ("PowerSemigroupProductClosure", "PowerSemigroupProductMembership", PRODUCT_DEFINITION_ID)
    proof_replacements = ("PowerSemigroupProductClosure", "PowerSemigroupProductMembership", "PowerSemigroupProductClosure")
    canonical_owners = original | statements | {PRODUCT_DEFINITION_ID: data["definition_revision"]}
    for field, replacements in (("canonical_targets", canonical_replacements), ("proof_targets", proof_replacements)):
        expected = []
        for key, replacement in zip(ADDITIONALLY_RETIRED_INNER_ORDER, replacements):
            expected.append({
                "id": key,
                "destination": original[key]["destination"] if field == "canonical_targets" else "power.proof." + key,
                "replacement_id": replacement,
                "replacement_destination": canonical_owners[replacement]["destination"] if field == "canonical_targets" else "power.proof." + replacement,
            })
        if compatibility.get(field) != expected:
            raise ValueError(f"Exactly the three approved unregistered compatibility anchors are allowed: {field}")


def product_definition(text):
    """Return the unique complete definition call, its formula and fixed fields."""
    masked = mask_comments(text)
    found = []
    for match in re.finditer(r"\\FormulaDefDeltaK\b", masked):
        invocation = SOURCE_HELPERS["call"](masked, match.start(), 3)
        if normalized(masked[slice(*invocation.args[1])]) == PRODUCT_DEFINITION_ID:
            found.append(invocation)
    if len(found) != 1:
        raise ValueError("Expected exactly one complete product definition")
    invocation = found[0]
    return {
        "source": text[invocation.start:invocation.end],
        "formula": masked[slice(*invocation.args[0])],
        "fixed_arguments": [normalized(masked[slice(*bounds)]) for bounds in invocation.args[1:]],
        "options": [normalized(masked[slice(*bounds)]) for bounds in invocation.opts],
    }


def validate_definition_revision(data):
    snapshot = json.dumps(data["canonical_registry"], ensure_ascii=False, separators=(",", ":"))
    if hashlib.sha256(snapshot.encode("utf-8")).hexdigest() != ORIGINAL_REGISTRY_SHA256:
        raise ValueError("The complete historical canonical registry must remain unchanged")
    revision = data.get("definition_revision", {})
    expected_identity = {
        "id": PRODUCT_DEFINITION_ID,
        "label": PRODUCT_DEFINITION_LABEL,
        "number": PRODUCT_DEFINITION_NUMBER,
        "destination": PRODUCT_DEFINITION_DESTINATION,
    }
    if any(revision.get(key) != value for key, value in expected_identity.items()):
        raise ValueError("The definition revision must preserve the product definition identity")
    if not revision.get("reason", "").strip() or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", revision.get("date", "")):
        raise ValueError("The definition revision needs a reason and date")
    structural = [row for row in data["canonical_registry"]
                  if row[0] != "ID" and row[1] == PRODUCT_DEFINITION_LABEL
                  and row[5] != PRODUCT_DEFINITION_ID]
    if len(structural) != 1 or revision.get("original_registry_row") != structural[0]:
        raise ValueError("The definition revision must record exactly its original structural registry row")
    original, revised = structural[0], revision.get("revised_registry_row")
    if (not isinstance(revised, list) or len(revised) != len(original)
            or any(revised[index] != original[index] for index in (0, 1, 2, 3, 6))
            or revised[4] == original[4] or revised[5] == original[5]
            or not re.fullmatch(r"am[0-9a-f]{32}", revised[4])
            or not revised[5].strip() or revised[5] == PRODUCT_DEFINITION_ID):
        raise ValueError("Only the structural definition hash and formula may change")
    if data["canonical_aux"].get(PRODUCT_DEFINITION_LABEL) != [PRODUCT_DEFINITION_NUMBER, PRODUCT_DEFINITION_DESTINATION]:
        raise ValueError("The original definition number/destination must remain unchanged")
    sources = []
    for key in ("original_definition_source", "revised_definition_source"):
        text = revision.get(key)
        if not isinstance(text, str):
            raise ValueError(f"Missing complete definition source: {key}")
        parsed = product_definition(text)
        if normalized(text) != normalized(parsed["source"]):
            raise ValueError(f"Definition source must contain only the complete definition call: {key}")
        sources.append(parsed)
    old, new = sources
    if proof_digest(old["source"]) != ORIGINAL_DEFINITION_SHA256:
        raise ValueError("The complete historical product definition source must remain unchanged")
    if old["fixed_arguments"] != new["fixed_arguments"] or old["options"] != new["options"]:
        raise ValueError("The definition title, identity and Delta declarations must remain unchanged")
    if normalized(old["formula"]) != normalized(ORIGINAL_PRODUCT_FORMULA):
        raise ValueError("The recorded original definition must retain the bounded set-builder formula")
    if normalized(new["formula"]) != normalized(REVISED_PRODUCT_FORMULA):
        raise ValueError("The revised definition must be exactly the direct term-image formula")


def record_digest(record):
    snapshot = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(snapshot.encode("utf-8")).hexdigest()


def validate_proof_bundling(data):
    revision = data.get("proof_bundling_revision", {})
    validate_revision_provenance(revision, "The conjunctive premise-bundling revision")
    if revision.get("normalization") != PROOF_NORMALIZATION:
        raise ValueError("The premise-bundling revision needs the approved proof normalization")
    if (revision.get("previous_proof_revisions_sha256") != BUNDLING_PREVIOUS_PROOF_REVISIONS_SHA256
            or revision.get("previous_separate_inner_proofs_sha256") != BUNDLING_PREVIOUS_SEPARATE_PROOFS_SHA256):
        raise ValueError("The premise-bundling revision must retain both approved predecessor snapshot identities")
    official_history = [item.get("revisions", {}) for item in data.get("proof_revisions_history", [])
                        if record_digest(item.get("revisions", {})) == BUNDLING_PREVIOUS_PROOF_REVISIONS_SHA256]
    helper_history = [item.get("record", {}) for item in data.get("separate_inner_proofs_history", [])
                      if record_digest(item.get("record", {})) == BUNDLING_PREVIOUS_SEPARATE_PROOFS_SHA256]
    if len(official_history) != 1 or len(helper_history) != 1:
        raise ValueError("The complete preceding official and seven-helper proof revisions must each remain once in history")
    if revision.get("proof_rows") != BUNDLED_PROOF_ROWS:
        raise ValueError("The premise-bundling revision must record exactly the approved nine table lengths")
    if revision.get("unchanged_helper_ids") != ["PowerSemigroupCarrierElement"]:
        raise ValueError("Only the independent carrier-element helper remains unchanged in the bundling revision")
    previous = {item["id"]: item for item in helper_history[0]["tables"]}
    current = {item["id"]: item for item in data["separate_inner_proofs"]["tables"]}
    if current["PowerSemigroupCarrierElement"] != previous["PowerSemigroupCarrierElement"]:
        raise ValueError("The unchanged three-row carrier-element helper must retain its approved record")


def manifest():
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8-sig"))
    validate_definition_revision(data)
    ids = [item["id"] for item in data["statements"]]
    if len(ids) != 2 or set(ids) != PROOF_IDS:
        raise ValueError("Power manifest must contain exactly the two extracted statement identities")
    inner_ids = [item["id"] for item in data["inner_statements"]]
    if len(inner_ids) != 17 or len(set(inner_ids)) != 17:
        raise ValueError("Power manifest must preserve the 17 distinct inner statement identities")
    if Counter(data["proof_targets"]) != Counter(ids + inner_ids):
        raise ValueError("Power manifest must preserve the original 19 proof-target identities")
    retirement = data.get("retired_inner_statements", {})
    retired = [item for item in data["inner_statements"] if item["id"] in RETIRED_INNER_IDS]
    if len(retired) != 10 or retirement.get("statements") != retired:
        raise ValueError("Power retirement must explicitly record exactly the ten original H7-H16 statements")
    retired_labels = {item["label"] for item in retired}
    retired_rows = [row for row in data["canonical_registry"] if row_label(row) in retired_labels]
    retired_aux = {label: value for label, value in data["canonical_aux"].items()
                   if label in retired_labels}
    if retirement.get("canonical_registry_rows") != retired_rows or retirement.get("canonical_aux") != retired_aux:
        raise ValueError("Power retirement must explicitly record precisely the removed registry rows and AUX labels")
    if retirement.get("proof_targets") != [item["id"] for item in retired]:
        raise ValueError("Power retirement must explicitly record the ten removed proof targets")
    if not retirement.get("reason", "").strip() or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", retirement.get("date", "")):
        raise ValueError("Power retirement needs a reason and date")
    addition = data.get("added_inner_statements", {})
    added = addition.get("statements", [])
    if [item["id"] for item in added] != ["PowerSemigroupProductTermImage"]:
        raise ValueError("Power addition must record precisely the product term-image representation")
    label = "thm:pp:28.2.4.2:18"
    number, destination = "28.2.4.2(H18)", "proofpartnr.28.2.4.2.18"
    if (added[0].get("label"), added[0].get("number"), added[0].get("destination")) != (label, number, destination):
        raise ValueError("The added product representation must use the new H18 identity")
    if addition.get("canonical_registry_rows") != [["ID", added[0]["id"], "theorem", label]]:
        raise ValueError("The addition must record exactly the new H18 registry row")
    if addition.get("canonical_aux") != {label: [number, destination]}:
        raise ValueError("The addition must record exactly the new H18 AUX identity")
    if not addition.get("reason", "").strip() or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", addition.get("date", "")):
        raise ValueError("The addition needs a reason and date")
    validate_helper_retirement(data)
    validate_derived_statements(data)
    validate_helper_classification(data)
    active_ids = [item["id"] for item in active_inner_statements(data)]
    statement_ids = [item["id"] for item in active_main_statements(data)]
    if len(active_ids) != 7 or Counter(data.get("active_proof_targets", [])) != Counter(statement_ids + active_ids):
        raise ValueError("Power manifest must provide exactly nine active direct proof targets: two official theorems and seven helpers")
    revisions = data.get("proof_revisions", {})
    if not isinstance(revisions, dict) or set(revisions) - PROOF_IDS:
        raise ValueError("Proof revisions must belong to the two preserved table identities")
    for item in data["statements"]:
        revision = revisions.get(item["id"])
        if revision is None:
            continue
        if revision.get("normalization") != PROOF_NORMALIZATION:
            raise ValueError(f"Unsupported proof normalization: {item['id']}")
        for field in ("original_normalized_sha256", "revised_normalized_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", revision.get(field, "")):
                raise ValueError(f"Missing/invalid {field}: {item['id']}")
        if revision["original_normalized_sha256"] != proof_digest(item["proof"]):
            raise ValueError(f"Historical original proof digest changed: {item['id']}")
        if revision["original_normalized_sha256"] == revision["revised_normalized_sha256"]:
            raise ValueError(f"Proof revision does not change its table: {item['id']}")
        if not revision.get("reason", "").strip() or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", revision.get("date", "")):
            raise ValueError(f"Proof revision needs a reason and date: {item['id']}")
        if not revision.get("required_references") or not all(
            isinstance(reference, str) and reference.strip()
            for reference in revision["required_references"]
        ):
            raise ValueError(f"Proof revision needs explicit required references: {item['id']}")
    history = data.get("proof_revisions_history", [])
    if not history:
        raise ValueError("The stronger shortening must retain the preceding approved proof revision")
    original_proofs = {item["id"]: item["proof"] for item in data["statements"]}
    for record in history:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", record.get("recorded_date", "")):
            raise ValueError("Historical proof revisions need their recording date")
        historic_revisions = record.get("revisions", {})
        if not historic_revisions or set(historic_revisions) - PROOF_IDS:
            raise ValueError("Historical proof revision identities must belong to the original extracted tables")
        for key, revision in historic_revisions.items():
            if revision.get("normalization") != PROOF_NORMALIZATION:
                raise ValueError(f"Unsupported historical proof normalization: {key}")
            if revision.get("original_normalized_sha256") != proof_digest(original_proofs[key]):
                raise ValueError(f"Historical original proof digest changed: {key}")
            if not re.fullmatch(r"[0-9a-f]{64}", revision.get("revised_normalized_sha256", "")):
                raise ValueError(f"Historical revised proof digest missing/invalid: {key}")
            if not revision.get("reason", "").strip() or not revision.get("required_references"):
                raise ValueError(f"Historical proof revision provenance incomplete: {key}")
    separate = data.get("separate_inner_proofs", {})
    if separate:
        tables = separate.get("tables", [])
        if [item.get("id") for item in tables] != list(ACTIVE_INNER_ORDER):
            raise ValueError("Exactly seven helper proof tables must appear in consecutive H1-H7 order")
        if not separate.get("reason", "").strip() or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", separate.get("date", "")):
            raise ValueError("The separate inner proof needs a reason and date")
        for item in tables:
            if item.get("normalization") != PROOF_NORMALIZATION or not re.fullmatch(
                r"[0-9a-f]{64}", item.get("revised_normalized_sha256", "")
            ):
                raise ValueError("The separate inner proof needs a valid normalized digest")
            if not item.get("required_references") or not all(
                isinstance(key, str) and key.strip() for key in item["required_references"]
            ):
                raise ValueError("The separate inner proof needs explicit required references")
    if not separate:
        raise ValueError("Every active helper requires an explicitly recorded independent proof table")
    validate_proof_bundling(data)
    return data


def registry(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8-sig").splitlines() if line]


def row_label(row):
    return row[3] if row[0] == "ID" else row[1]


def records_equal(actual, expected, owner, *, legacy_manifest=False):
    current = registry_records(actual, legacy_manifest=legacy_manifest)
    original = registry_records(expected, legacy_manifest=legacy_manifest)
    if current != original:
        raise ValueError(f"{owner}: registry differs from manifest; "
                         f"missing={list((original-current).elements())}, "
                         f"extra={list((current-original).elements())}")


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
            fields.append(line[slice(*value)])
        if len(fields) >= 4:
            if match[1] in result:
                raise ValueError(f"{path.name}: duplicate local label {match[1]}")
            result[match[1]] = (fields[0].strip(), fields[3])
    return result


def main_records(data):
    base = ROOT / "registry/_B28"
    rows = registry(base.with_suffix(".registry.tsv"))
    records_equal(rows, active_canonical_registry(data), "B28", legacy_manifest=True)
    ids = id_map(rows)
    labels = aux_labels(base.with_suffix(".aux"))
    expected_labels = active_canonical_aux(data)
    if labels != {label: tuple(value) for label, value in expected_labels.items()}:
        missing = set(expected_labels) - set(labels)
        extra = set(labels) - set(expected_labels)
        changed = {label: (expected_labels[label], labels[label])
                   for label in set(labels) & set(expected_labels)
                   if labels[label] != tuple(expected_labels[label])}
        raise ValueError(f"B28: AUX must equal the retained historical labels with the recorded numbering revision; "
                         f"missing={sorted(missing)}, extra={sorted(extra)}, changed={changed}")
    for label, expected in expected_labels.items():
        if labels.get(label) != tuple(expected):
            raise ValueError(f"B28: original number/destination changed: {label}, {labels.get(label)}")
    for item in active_main_statements(data) + active_inner_statements(data):
        if ids.get(item["id"]) != item["label"]:
            raise ValueError(f"B28: canonical statement ownership changed: {item['id']}")
        if labels.get(item["label"]) != (item["number"], item["destination"]):
            raise ValueError(f"B28: migrated statement number/destination changed: {item['id']}")
    return rows, labels


def write_import(rows):
    labels = {row_label(row) for row in rows}
    (DIRECTORY / "b28-external.registry.tsv").write_text(
        "".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")
    lines = []
    for line in (ROOT / "registry/_B28.aux").read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            lines.append(line)
    target = DIRECTORY / "b28-external.aux"
    target.write_text("\\relax\n" + "\n".join(lines) + "\n", encoding="utf-8")
    if set(aux_labels(target)) != labels:
        raise ValueError("b28-external: incomplete filtered AUX import")


def prepare():
    data = manifest()
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows, _ = main_records(data)
    write_import(rows)
    print("Power semigroup: canonical B28 statements imported; both companion registries remain empty.")


def normalized(text):
    return re.sub(r"\s+", "", mask_comments(text))


def proof_digest(text):
    return hashlib.sha256(normalized(text).encode("utf-8")).hexdigest()


def assert_proof_matches(item, actual, revision=None):
    if revision is None:
        if normalized(actual) != normalized(item["proof"]):
            raise ValueError(f"Extracted proof table differs from the original: {item['id']}")
        return
    if proof_digest(actual) != revision["revised_normalized_sha256"]:
        raise ValueError(f"Revised proof table differs from the approved digest: {item['id']}")
    commentless = mask_comments(actual)
    references = {
        normalized(commentless[slice(*reference.args[0])])
        for reference in SOURCE_HELPERS["references"](commentless)
    }
    if missing := {normalized(key) for key in revision["required_references"]} - references:
        raise ValueError(f"Revised proof table lacks required references: {item['id']}, {sorted(missing)}")


def shared_bodies(text, prefix):
    declarations = {}
    pattern = r"\\expandafter\s*\\newcommand\s*\\csname\s*" + prefix + r"@([^\s\\]+)\s*\\endcsname"
    for match in re.finditer(pattern, text):
        body, _ = group(text, match.end())
        if body is None or match[1] in declarations:
            raise ValueError(f"Missing/duplicate shared declaration: {prefix}@{match[1]}")
        declarations[match[1]] = text[slice(*body)]
    return declarations


def audit_sources():
    data = manifest()
    expected = {item["id"]: item for item in active_main_statements(data)}
    main = mask_comments(MAIN_SOURCE.read_text(encoding="utf-8-sig"))
    shared = mask_comments((SOURCE_DIRECTORY / "statements.tex").read_text(encoding="utf-8-sig"))
    proofs = mask_comments((SOURCE_DIRECTORY / "proofs.tex").read_text(encoding="utf-8-sig"))
    reading = mask_comments((SOURCE_DIRECTORY / "reading.tex").read_text(encoding="utf-8-sig"))
    display = mask_comments((SOURCE_DIRECTORY / "proof-display.tex").read_text(encoding="utf-8-sig"))
    definition_macro = re.search(r"\\newcommand\{\\PowerProductDefinitionFormula\}", display)
    if definition_macro is None:
        raise ValueError("The proof companion must display the canonical product definition")
    formula, _ = group(display, definition_macro.end())
    if formula is None or normalized(display[slice(*formula)]) != normalized(REVISED_PRODUCT_FORMULA):
        raise ValueError("The displayed product definition differs from the canonical formula")
    if len(re.findall(r"\\PowerProductDefinitionFormula\b", proofs)) != 1:
        raise ValueError("The proof companion must display the product definition exactly once")
    actual_definition = product_definition(main)["source"]
    if normalized(actual_definition) != normalized(data["definition_revision"]["revised_definition_source"]):
        raise ValueError("The current product definition differs from its recorded revision")
    declarations = shared_bodies(shared, "PowerStatement")
    official_ids = PROOF_IDS
    if set(declarations) != official_ids:
        raise ValueError(f"Shared statement identities differ: {set(declarations) ^ official_ids}")
    invocations = re.findall(r"\\PowerStatement\s*\{([^}]+)\}", main)
    if Counter(invocations) != Counter(official_ids):
        raise ValueError("B28 must invoke exactly the two original canonical shared statements once each")
    proof_statements = re.findall(r"\\PowerProofStatement\s*\{([^}]+)\}", proofs)
    if Counter(proof_statements) != Counter(official_ids):
        raise ValueError("The proof companion must reproduce exactly the two original official statements once each")
    separate = {item["id"]: item for item in data.get("separate_inner_proofs", {}).get("tables", [])}
    inner_proofs = re.findall(r"\\PowerInnerProofStatement\s*\{([^}]+)\}", proofs)
    if inner_proofs != list(ACTIVE_INNER_ORDER) or inner_proofs != list(separate):
        raise ValueError("Seven separate helper tables must appear exactly in H1-H7 order")
    main_heading = re.search(r"\\PowerProofStatement\s*\{NonemptyPowerSemigroup\}", proofs)
    if main_heading is None or proofs.rfind(r"\PowerInnerProofStatement") > main_heading.start():
        raise ValueError("All seven helper proofs must precede the main theorem")
    actual_proofs = {}
    proven_dependencies = set()
    dependency_ids = official_ids | set(ACTIVE_INNER_ORDER)
    for table in re.finditer(r"\\begin\{(tabproof\w*)\}.*?\\end\{\1\}", proofs, re.S):
        preceding = re.findall(r"\\Power(?:Inner)?ProofStatement\s*\{([^}]+)\}", proofs[:table.start()])
        if not preceding or preceding[-1] in actual_proofs:
            raise ValueError("Missing/duplicate extracted table identity")
        key = preceding[-1]
        actual_proofs[key] = table[0]
        used_dependencies = {
            normalized(table[0][slice(*reference.args[0])])
            for reference in SOURCE_HELPERS["references"](table[0])
        } & dependency_ids
        if missing := used_dependencies - proven_dependencies:
            raise ValueError(f"Helper or representation theorem used before its independent proof is complete: {key}, {sorted(missing)}")
        if key in dependency_ids:
            proven_dependencies.add(key)
    required_table_order = [*ACTIVE_INNER_ORDER, "NonemptyPowerSemigroup", "PowerSemigroupProductMembership"]
    if list(actual_proofs) != required_table_order:
        raise ValueError("Both outer-product helper proofs must follow H4 and precede associativity H7, with all nine tables in approved order")
    for key, expected_rows in data["proof_bundling_revision"]["proof_rows"].items():
        row_count = len(re.findall(r"\\proofstep(?:widestar|wide)\b", actual_proofs.get(key, "")))
        if row_count != expected_rows:
            raise ValueError(f"Bundled proof table has an unapproved row count: {key}, {row_count} instead of {expected_rows}")
    expected_proof_ids = official_ids | set(separate)
    if set(actual_proofs) != expected_proof_ids:
        raise ValueError(f"Extracted table identities differ: {set(actual_proofs) ^ expected_proof_ids}")
    for key, record in separate.items():
        assert_proof_matches({"id": key}, actual_proofs[key], record)
    compact_main = normalized(main)
    for key, item in expected.items():
        if normalized(declarations[key]) != normalized(item["statement"]):
            raise ValueError(f"Shared statement differs from its recorded canonical snapshot: {key}")
        revision = data.get("proof_revisions", {}).get(key) if key in PROOF_IDS else item
        assert_proof_matches(item, actual_proofs[key], revision)
        if normalized(item["proof"]) in compact_main:
            raise ValueError(f"Extracted proof table still appears in B28: {key}")
    inner = {item["id"]: item for item in historical_inner_statements(data)
             + data["helper_classification_revision"]["statements"]}
    for prefix, field in (("PowerInnerFormula", "formula"), ("PowerInnerKey", "key"), ("PowerInnerTitle", "title")):
        bodies = shared_bodies(shared, prefix)
        if set(bodies) != set(inner):
            raise ValueError(f"Inner {field} identities differ: {set(bodies) ^ set(inner)}")
        for key, item in inner.items():
            if normalized(bodies[key]) != normalized(item[field]):
                raise ValueError(f"Preserved inner {field} differs from the original: {key}")
    inner_invocations = re.findall(r"\\PowerInnerStatement\s*\{([^}]+)\}", main)
    active_ids = [item["id"] for item in active_inner_statements(data)]
    if inner_invocations != data["helper_numbering_revision"]["order"]:
        raise ValueError("Helper declaration order differs from the consecutive numbering revision")
    if Counter(inner_invocations) != Counter(active_ids):
        raise ValueError("B28 must invoke exactly the seven active H1-H7 helper identities")
    if re.search(r"\\PowerInnerProofResult\b", proofs):
        raise ValueError("Active helper proofs require separate tables, not integrated result markers")
    compatibility = data["legacy_pdf_compatibility"]
    for field, source in (("canonical_targets", main), ("proof_targets", proofs)):
        targets = compatibility[field] + (data["helper_classification_revision"]["compatibility_targets"] if field == "canonical_targets" else [])
        for item in targets:
            marker = r"\hypertarget{" + item["destination"] + "}"
            if source.count(marker) != 1:
                raise ValueError(f"Expected exactly one explicit unregistered compatibility anchor: {item['destination']}")
    active_sources = main + proofs + reading
    for reference in SOURCE_HELPERS["references"](active_sources):
        key = normalized(active_sources[slice(*reference.args[0])])
        if key in all_retired_inner_ids():
            raise ValueError(f"Active power source still cites a retired helper: {key}")
    if re.search(r"\\Formula(?:Thm|Def|Axiom)(?:Delta\w*|Auto)\b", reading):
        raise ValueError("The reading edition must not declare local numbered statements")
    if re.search(r"\\(?:PowerStatement|PowerInnerStatement)\s*\{", proofs + reading):
        raise ValueError("Canonical declarations must only be invoked in B28")
    for path in SOURCE_DIRECTORY.glob("*.tex"):
        if SOURCE_HELPERS["inventory"](path)["control_characters"]:
            raise ValueError(f"{path.name}: invalid source control character")
    display = (SOURCE_DIRECTORY / "proof-display.tex").read_text(encoding="utf-8-sig")
    if not data.get("display_revision", {}).get("inline_result_annotations") is False:
        raise ValueError("The requested removal of result annotations must be explicitly recorded")
    if r"\NewDocumentCommand{\PowerInnerProofResult}{O{} m +m}{#3}" not in display:
        raise ValueError("Result markers must display only their mathematical formula")
    revision_count = len(data.get("proof_revisions", {}))
    print(f"Power sources: two unchanged official statements; two former official outer-product declarations preserved as historical snapshots; "
          f"{2-revision_count} original and {revision_count} explicitly revised historical proof tables verified; "
          "7 active helpers independently proved in H1-H7 order, including both explicitly reclassified outer-product results; "
          "10 original and 3 newly unused helpers explicitly retired without altering historical snapshots; "
          "the 3 newly retired identities retain only their recorded compatibility anchors.")
    if separate:
        print("Power sources: the independently displayed helper proofs match their recorded digests and required references.")
        print("Power sources: conjunctive premise bundles retain both protected predecessor proof snapshots; all nine approved table lengths verified.")


def audit():
    from pypdf import PdfReader

    audit_sources()
    data = manifest()
    canonical, canonical_aux = main_records(data)
    records_equal(registry(DIRECTORY / "b28-external.registry.tsv"), canonical, "b28-external")
    expected_aux = {row_label(row): canonical_aux[row_label(row)] for row in canonical}
    if aux_labels(DIRECTORY / "b28-external.aux") != expected_aux:
        raise ValueError("b28-external: stale AUX imports")
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

    def audit_compatibility_targets(reader, field, owner):
        destinations = reader.named_destinations
        targets = data["legacy_pdf_compatibility"][field] + (
            data["helper_classification_revision"]["compatibility_targets"] if field == "canonical_targets" else [])
        for item in targets:
            target, replacement = item["destination"], item["replacement_destination"]
            if target not in destinations or replacement not in destinations:
                raise ValueError(f"{owner}: missing compatibility/replacement target {target}, {replacement}")
            if reader.get_destination_page_number(destinations[target]) != reader.get_destination_page_number(destinations[replacement]):
                raise ValueError(f"{owner}: compatibility anchor moved away from its replacement proof/statement: {target}")

    main_pdf = ROOT / "registry/_B28.pdf"
    proof_targets = {"power.proof." + key for key in data["active_proof_targets"]}
    for edition in ("proofs", "reading"):
        base = DIRECTORY / f"_B28-power-{edition}"
        if registry(base.with_suffix(".registry.tsv")):
            raise ValueError(f"{edition}: companion must not register local statements")
        if set(aux_labels(base.with_suffix(".aux"))) & set(canonical_aux):
            raise ValueError(f"{edition}: canonical B28 labels must only be imported")
        pdf = base.with_suffix(".pdf")
        reader = PdfReader(pdf)
        publisher["assert_build_ready"](pdf, reader)
        publisher["audit_local_targets"](reader, pdf)
        expected_targets = {f"power.{edition}"}
        if edition == "proofs":
            expected_targets.update(proof_targets)
            expected_targets.add("power.proof.conclusion")
            audit_compatibility_targets(reader, "proof_targets", "Power proofs")
        if missing := expected_targets - set(reader.named_destinations):
            raise ValueError(f"{edition}: missing PDF targets: {sorted(missing)}")
        retired_targets = {"power.proof." + key for key in RETIRED_INNER_IDS}
        if stale := retired_targets & set(reader.named_destinations):
            raise ValueError(f"{edition}: retired direct proof targets still present: {sorted(stale)}")
        companion = "reading" if edition == "proofs" else "proofs"
        expected_links = {
            ((DIRECTORY / f"_B28-power-{companion}.pdf").resolve(), f"power.{companion}"),
            (main_pdf.resolve(), "power.main"),
        }
        if edition == "proofs":
            proof_source = mask_comments((SOURCE_DIRECTORY / "proofs.tex").read_text(encoding="utf-8-sig"))
            referenced_ids = {
                normalized(proof_source[slice(*reference.args[0])])
                for reference in SOURCE_HELPERS["references"](proof_source)
            }
            referenced_ids.update(re.findall(r"\\PowerInnerProofStatement\s*\{([^}]+)\}", proof_source))
            # All seven independent helper headings and both official theorem headings
            # link back to their canonical statements. Legacy anchors are not
            # registered statements and impose no reverse-link requirement.
            cited_helpers = [item for item in active_inner_statements(data)
                             if item["id"] in referenced_ids]
            expected_links.update((main_pdf.resolve(), item["destination"])
                                  for item in active_main_statements(data) + cited_helpers)
        if missing := expected_links - links(pdf, reader):
            raise ValueError(f"{edition}: missing navigation: {sorted(missing)}")
        print(f"Power {edition}: {len(reader.pages)} pages; empty registry, canonical references and PDF links passed.")

    reader = PdfReader(main_pdf)
    publisher["assert_build_ready"](main_pdf, reader)
    publisher["audit_local_targets"](reader, main_pdf)
    audit_compatibility_targets(reader, "canonical_targets", "B28")
    older_retired_targets = {item["destination"] for item in data["retired_inner_statements"]["statements"]}
    if stale := older_retired_targets & set(reader.named_destinations):
        raise ValueError(f"B28: original ten retired canonical targets reappeared: {sorted(stale)}")
    expected_targets = {"power.main"} | {target for _, target in active_canonical_aux(data).values()}
    if missing := expected_targets - set(reader.named_destinations):
        raise ValueError(f"B28: original PDF targets missing: {sorted(missing)}")
    proof_pdf = (DIRECTORY / "_B28-power-proofs.pdf").resolve()
    expected_links = {
        ((DIRECTORY / "_B28-power-reading.pdf").resolve(), "power.reading"),
        (proof_pdf, "power.proofs"),
        (proof_pdf, "power.proof.conclusion"),
        *((proof_pdf, target) for target in proof_targets
          if target != "power.proof.NonemptyPowerSemigroup"),
    }
    if missing := expected_links - links(main_pdf, reader):
        raise ValueError(f"B28: missing companion/proof navigation: {sorted(missing)}")
    print("B28: seven active H1-H7 helpers and both original official theorems verified; the complete former official outer-product extension remains historical with both native PDF targets preserved as compatibility anchors; the original ten-helper retirement and new three-helper retirement remain explicit and historical; the three newly retired identities retain only their approved canonical/proof compatibility anchors; all retained formulas, semantic identities, labels, destinations and direct proof links verified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "audit", "audit-sources"))
    args = parser.parse_args()
    {"prepare": prepare, "audit": audit, "audit-sources": audit_sources}[args.mode]()
