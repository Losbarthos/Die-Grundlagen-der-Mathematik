"""Audit canonical B19 statements, companion links and physical booklet plans."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
CHANGED = {"RealCutUnionUpperBound", "RealCutUnionLeastUpperBound"}

def registry(path=ROOT / "registry/_B19.registry.tsv"):
    records = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        row = line.split("\t")
        if row[0] == "ID":
            if row[1] in records:
                raise ValueError(f"Duplicate semantic ID: {row[1]}")
            records[row[1]] = dict(kind=row[2], label=row[3], number=row[4], formula=row[5], context=row[6] if len(row)>6 else "")
    return records

def check_registry():
    baseline = json.loads((ROOT / "scripts/cuts-manifest.json").read_text(encoding="utf-8"))
    current = registry()
    assert current.keys() == baseline.keys(), "B19 semantic ID set changed"
    for identity, expected in baseline.items():
        for field, value in expected.items():
            if identity in CHANGED and field == "formula":
                continue
            assert current[identity][field] == value, f"Unexpected {field} change: {identity}"
    for identity in CHANGED:
        assert current[identity]['formula'] != baseline[identity]['formula'], f"Missing correction: {identity}"
    print(f"B19: {len(current)} unchanged IDs/numbers; formulas changed only for the two corrected auxiliary statements.")

def check_editions():
    directory = ROOT / "registry/cuts"
    proof = PdfReader(directory / "_B19-cuts-proofs.pdf")
    ids = ("DedekindCutPredicate", "DedekindCutCharacterization", "RealPrincipalCutIsCut", "RealCutInclusionComparable", "RationalToRealEmbeddingOrder", "RationalToRealEmbeddingInjective", "RealBoundedCutUnionIsCut", "RealLeastUpperBoundProperty", "RealCutSupremumUnion")
    for identity in ids:
        assert "cuts.proof." + identity in proof.named_destinations, f"Missing proof destination: {identity}"
    proof_registry = (directory / "_B19-cuts-proofs.registry.tsv").read_text(encoding="utf-8")
    assert not proof_registry.strip(), "The proof companion must not own statements"
    for kind, suffix, limit in (("reading", "booklet", 20), ("exercises", "exercises-booklet", 18)):
        reader = PdfReader(directory / f"_B19-cuts-{kind}.pdf")
        assert f"cuts.{kind}" in reader.named_destinations
        assert len(reader.pages) <= limit, f"{kind} exceeds the corresponding binomial booklet"
        plan = json.loads((ROOT / f"tmp/cuts-editions/{suffix}-page-plan.json").read_text(encoding="utf-8"))
        assert plan['source_pages'] == len(reader.pages)
        assert plan['a5_pages'] % 4 == 0
        assert plan['logical_pages'][0]['role'] == 'front-cover'
        assert plan['logical_pages'][-1]['role'] == 'back-cover'
        positions = [sheet[side][position] for sheet in plan['sheet_plan'] for side in ('front','back') for position in ('left','right')]
        assert sorted(positions) == list(range(1, plan['a5_pages']+1)), "Pages missing or duplicated in imposition"
        for page_number in range(2, len(reader.pages)+1):
            text = plan['logical_pages'][2*page_number-3]
            notes = plan['logical_pages'][2*page_number-2]
            assert (text['source_page'], text['half'], text['logical_page'] % 2) == (page_number,'left',0)
            assert (notes['source_page'], notes['half'], notes['logical_page'] % 2) == (page_number,'right',1)
        imposed = PdfReader(directory / f"_B19-cuts-{suffix}.pdf")
        assert len(imposed.pages) == plan['sheets']*2
        assert not any(page.get('/Annots') for page in imposed.pages)
        print(f"{kind}: {len(reader.pages)} source pages; {plan['a5_pages']} folded A5 pages; {plan['sheets']} A4 sheets; text faces its matching notes.")
    print(f"Proof companion: {len(proof.pages)} pages; no competing statement registry.")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry-only',action='store_true')
    parser.add_argument('--include-main', action='store_true')
    args = parser.parse_args()
    check_registry()
    if args.include_main:
        assert registry() == registry(ROOT / 'registry/main/_B19.registry.tsv'), 'Standalone/main B19 metadata differ'
        print('Main manuscript: B19 statement metadata agree with the standalone volume.')
    if not args.registry_only:
        check_editions()

if __name__ == '__main__':
    main()
