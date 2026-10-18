"""Audit the canonical coordinate proof edition and its automatic reference lists.

No document is built or modified. Geometry is a separate audit with
check-proof-reference-layout.py (pypdf and pdfplumber are required there).
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import runpy
import sys
import unicodedata

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/coordinates"
BASE = DIRECTORY / "_B31-coordinates-proofs"
MANIFEST = ROOT / "scripts/coordinates-proofs-manifest.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical_records():
    with (ROOT / "band-dependencies.tsv").open(encoding="utf-8-sig", newline="") as stream:
        graph = {row["band"]: row for row in csv.DictReader(stream, delimiter="\t")}
    record = graph["B31"]
    predecessors = [band for band in re.split(r"[,\s]+", record["predecessors"].strip()) if band and band != "-"]
    # The graph contains all imported predecessors, in its canonical import order.
    records, identities = {}, {}
    for band in [*predecessors, "B31"]:
        base = ROOT / graph[band]["artifact_base"]
        for suffix in (".pdf", ".aux", ".registry.tsv"):
            require(base.with_suffix(suffix).is_file(), f"Missing canonical artifact: {base}{suffix}")
        for line in base.with_suffix(".registry.tsv").read_text(encoding="utf-8-sig").splitlines():
            fields = line.split("\t")
            if fields[0] == "ID":
                require(len(fields) >= 4, f"Malformed ID record in {base}")
                identities[fields[1]] = fields[3]
                if len(fields) >= 6:
                    records[fields[3]] = dict(kind=fields[2], number=fields[4],
                                              display=fields[5], delta=fields[6] if len(fields) >= 7 else "")
            else:
                require(len(fields) >= 7, f"Malformed canonical registry: {base}")
                records[fields[1]] = dict(kind=fields[2], number=fields[3],
                                          display=fields[7] if len(fields) >= 8 else "",
                                          delta=fields[8] if len(fields) >= 9 else "")
    # This phase runs only after canonical B31 artifacts exist. Source-only
    # relocation checks in the earlier B28 power build avoid an artifact cycle;
    # the actual compiled declarations and their full Delta metadata are
    # mandatory here and in the publisher's coordinate preflight.
    relocation = runpy.run_path(str(ROOT / "scripts/power-editions.py"))
    relocation["verify_coordinate_relocation"](
        relocation["manifest"](), relocation["registry"](ROOT / "registry/_B31.registry.tsv"))
    return records, identities


def audit_source():
    helpers = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))
    source = ROOT / "tex/b31/coordinates/proofs.tex"
    text = helpers["mask_comments"](source.read_text(encoding="utf-8-sig"))
    require(not re.search(r"\\Formula(?:Thm|Def|Ax|Rule)\w*\b", text),
            "The proof companion must not declare competing results")
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    anchors = list(re.finditer(r"\\hypertarget\{coordinates\.proof\.([^}]+)\}", text))
    observed = []
    for index, anchor in enumerate(anchors):
        body = text[anchor.end():anchors[index + 1].start() if index + 1 < len(anchors) else len(text)]
        rows = list(helpers["rows"](body))
        normalized = "\n".join(re.sub(r"\s+", "", body[row.start:row.end]) for row in rows)
        observed.append(dict(id=anchor[1], rows=len(rows),
                             parts=len(re.findall(r"\\proofpartwide\b", body)),
                             rows_sha256=hashlib.sha256(normalized.encode()).hexdigest()))
    require(observed == expected,
            "Coordinate proof identities, rows or reasons changed from the reviewed 397-row manifest")
    require(len(observed) == 16 and sum(item["rows"] for item in observed) == 397,
            "Expected sixteen coordinate proofs with 397 unchanged rows")
    criterion = next(item for item in observed if item["id"] == "SemigroupCoordinateIsoCriterion")
    require(criterion["rows"] == 102 and criterion["parts"] == 7,
            "The coordinate isomorphism criterion must retain 102 rows in seven parts")
    dependencies = runpy.run_path(str(ROOT / "scripts/proof-dependency-audit.py"))
    require(dependencies["check"](source) == 0, "Unresolved coordinate proof dependencies")
    return expected


def audit_events(manifest, records, identities):
    path = BASE.with_suffix(".proof-references.tsv")
    require(path.is_file(), f"Missing reference-renderer audit: {path}")
    groups, current = {}, None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split("\t")
        require(len(fields) >= 2, f"Malformed reference event on line {number}")
        event, index = fields[0], int(fields[1])
        require(1 <= index <= 16, f"Unexpected proof index: {index}")
        if event == "begin":
            require(len(fields) == 2 and index not in groups,
                    f"Duplicate or malformed proof begin: {line}")
            require(index == len(groups) + 1, "Reference proof scopes are reordered")
            require(current is None or groups[current]["closed"], "A previous proof scope is still open")
            groups[index] = dict(uses=[], entries=[], closed=False)
            current = index
        else:
            require(index in groups and index == current, f"Event escaped its proof scope: {line}")
            group = groups[index]
            if event == "use":
                require(len(fields) == 3 and not group["closed"], f"Reference use outside proof: {line}")
                group["uses"].append(fields[2])
            elif event == "closed":
                require(len(fields) == 2 and not group["closed"], f"Duplicate proof close: {line}")
                group["closed"] = True
            elif event == "entry":
                require(len(fields) == 7 and group["closed"], f"Entry printed before full proof closure: {line}")
                group["entries"].append(fields[2:])
            else:
                raise ValueError(f"Unknown reference event: {event}")
    require(list(groups) == list(range(1, 17)), "Expected all sixteen reference proof scopes")
    total = 0
    for index, item in enumerate(manifest, 1):
        group = groups[index]
        require(group["closed"], f"Unclosed proof: {item['id']}")
        expected = list(dict.fromkeys(group["uses"]))
        entries = group["entries"]
        labels = [entry[0] for entry in entries]
        require(expected and labels == expected,
                f"{item['id']}: missing, duplicated or reordered reference entries; expected {expected}, got {labels}")
        own = identities.get(item["id"])
        require(own and own not in expected,
                f"{item['id']}: its own statement header was captured as a proof dependency")
        for label, kind, number, display_length, delta_length in entries:
            require(label in records, f"No canonical statement for {label}")
            canonical = records[label]
            require(kind == canonical["kind"] and number == canonical["number"],
                    f"{item['id']}: incorrect kind/number for {label}: {kind} {number}")
            require(kind in {"theorem", "definition", "axiom", "rule"}, f"Unexpected statement kind: {kind}")
            require(int(display_length) > 0 and canonical["display"].strip(),
                    f"Original statement is empty: {label}")
            require(int(delta_length) >= 0 and (not canonical["delta"].strip() or int(delta_length) > 0),
                    f"Original premises/context were lost: {label}")
        total += len(entries)
    return total


def audit_pdf(manifest):
    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    pdf = BASE.with_suffix(".pdf")
    reader = PdfReader(pdf)
    publisher["assert_build_ready"](pdf, reader)
    log = BASE.with_suffix(".log").read_text(encoding="utf-8", errors="replace")
    require(not re.search(r"Overfull \\[hv]box|Missing character:|proof-references (?:WARNING|ERROR)", log),
            "Coordinate proof build has a layout, glyph or original-statement diagnostic")
    require(not BASE.with_suffix(".registry.tsv").read_text(encoding="utf-8-sig").strip(),
            "The proof companion must have no local result registrations")
    destinations = set(reader.named_destinations)
    required = {"coordinates.proofs", *("coordinates.proof." + item["id"] for item in manifest)}
    require(required <= destinations, f"Missing coordinate PDF destinations: {sorted(required - destinations)}")
    actual = {name for name in destinations if name.startswith("coordinates.proof.")}
    require(actual == required - {"coordinates.proofs"}, "Unexpected coordinate proof destinations")
    text = unicodedata.normalize("NFKC", "\n".join(page.extract_text() or "" for page in reader.pages))
    compact = "".join(text.split())
    heading = "VerwendeteSätzeundDefinitionen"
    count = compact.count(heading) - compact.count(heading + "(Fortsetzung)")
    require(count == 16, f"Expected sixteen rendered proof-reference overviews, found {count}")
    tagged = sum(b"/ProofReferenceCell" in page.get_contents().get_data()
                 for page in reader.pages if page.get_contents() is not None)
    require(tagged > 0, "No reference-table PDF geometry tags were emitted")
    publisher["audit"]([pdf], root=ROOT)
    return len(reader.pages)



def audit_reading(manifest):
    """The prose edition reuses B31 statements and the matching proof anchors."""
    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    base = DIRECTORY / "_B31-coordinates-reading"
    pdf = base.with_suffix(".pdf")
    reader = PdfReader(pdf)
    publisher["assert_build_ready"](pdf, reader)
    require(not base.with_suffix(".registry.tsv").read_text(encoding="utf-8-sig").strip(),
            "The reading companion must have no local result registrations")
    require("coordinates.reading" in reader.named_destinations,
            "Missing coordinate reading destination")
    proof_targets = set()
    for action in publisher["remote_actions"](reader):
        filename = Path(publisher["file_name"](action)).name
        require(not filename.startswith("_B28-coordinates-"),
                f"Stale B28 companion link in reading: {filename}")
        if filename == "_B31-coordinates-proofs.pdf":
            proof_targets.add(str(action.get("/D", "")))
    required = {"coordinates.proof." + item["id"] for item in manifest}
    require(required <= proof_targets,
            f"Reading misses proof-table links: {sorted(required - proof_targets)}")
    publisher["audit"]([pdf], root=ROOT)
    return len(reader.pages)


def audit(source_only=False):
    manifest = audit_source()
    records, identities = canonical_records()
    for item in manifest:
        label = identities.get(item["id"])
        require(label in records and records[label]["kind"] == "theorem"
                and records[label]["number"].startswith("31."),
                f"Missing canonical B31 theorem: {item['id']}")
    if source_only:
        print("Coordinates source audit passed: 16 canonical proofs, 397 unchanged rows; criterion 102 rows / 7 parts.")
        return
    entries = audit_events(manifest, records, identities)
    pages = audit_pdf(manifest)
    reading_pages = audit_reading(manifest)
    print(f"Coordinates proof audit passed: 16 complete reference overviews, {entries} entries, {pages} proof PDF pages, {reading_pages} reading PDF pages; no local result declarations.")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("audit", "source"), default="audit", nargs="?")
    args = parser.parse_args()
    audit(args.mode == "source")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
