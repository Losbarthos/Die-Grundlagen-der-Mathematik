"""Prepare and audit the B37 overview reading edition.

Uses canonical B37 labels without declaring a second set of statements.
The checks cover imports and PDF navigation, not formal proof validity.
"""
from pathlib import Path
import argparse
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "registry/finite"
HELPERS = runpy.run_path(str(ROOT / "scripts/nullproducts-editions.py"))


def prepare():
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    rows = HELPERS["registry"](ROOT / "registry/_B37.registry.tsv")
    # The existing import helper uses the directory of its own module.
    labels = {HELPERS["row_label"](row) for row in rows}
    (DIRECTORY / "b37-external.registry.tsv").write_text(
        "".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")
    selected = []
    for line in (ROOT / "registry/_B37.aux").read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"\\newlabel\{([^}]+)\}", line)
        if match and match[1] in labels:
            selected.append(line)
    target = DIRECTORY / "b37-external.aux"
    target.write_text("\\relax\n" + "\n".join(selected) + "\n", encoding="utf-8")
    if set(HELPERS["aux_labels"](target)) != labels:
        raise ValueError("B37 reading import is incomplete")
    print("Finite semigroups: canonical B37 statements imported.")


def audit():
    from pypdf import PdfReader

    source = (ROOT / "tex/b37/finite/reading.tex").read_text(encoding="utf-8-sig")
    if re.search(r"\\Formula(?:Thm|Def|Axiom)(?:Delta\w*|Auto)\b", HELPERS["mask_comments"](source)):
        raise ValueError("Reading edition must not declare local numbered statements")
    if HELPERS["registry"](DIRECTORY / "b37-external.registry.tsv") != HELPERS["registry"](ROOT / "registry/_B37.registry.tsv"):
        raise ValueError("Stale B37 reading registry import")
    imported = HELPERS["aux_labels"](DIRECTORY / "b37-external.aux")
    canonical = HELPERS["aux_labels"](ROOT / "registry/_B37.aux")
    if any(canonical.get(label) != value for label, value in imported.items()):
        raise ValueError("Stale B37 reading AUX import")
    base = DIRECTORY / "_B37-finite-reading"
    if HELPERS["registry"](base.with_suffix(".registry.tsv")):
        raise ValueError("Reading edition has locally registered statements")
    publisher = runpy.run_path(str(ROOT / "scripts/publish-pdfs.py"))
    pdf = base.with_suffix(".pdf")
    reader = PdfReader(pdf)
    publisher["assert_build_ready"](pdf, reader)
    publisher["audit_local_targets"](reader, pdf)
    if "finite-semigroups.reading" not in reader.named_destinations:
        raise ValueError("Reading edition has no entry target")
    links, cache = set(), {}
    for action in publisher["remote_actions"](reader):
        target = (pdf.parent / publisher["file_name"](action)).resolve()
        if not target.is_relative_to(ROOT) or not target.is_file():
            raise ValueError(f"Missing or outside PDF target: {target}")
        if target not in cache:
            cache[target] = set(PdfReader(target).named_destinations)
        destination = str(action.get("/D"))
        if destination not in cache[target]:
            raise ValueError(f"Missing destination {destination} in {target.name}")
        links.add((target, destination))
    for target, destination in (
        (ROOT / "registry/_B37.pdf", "finite-semigroups.main"),
        (ROOT / "registry/nullproducts/_B37-nullproducts-reading.pdf", "nullproducts.reading"),
    ):
        if (target.resolve(), destination) not in links:
            raise ValueError(f"Missing navigation to {destination}")
    print(f"Finite semigroups reading: {len(reader.pages)} pages; imports, ownership and links passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "audit"))
    args = parser.parse_args()
    {"prepare": prepare, "audit": audit}[args.mode]()
