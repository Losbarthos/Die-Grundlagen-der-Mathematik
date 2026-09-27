"""Structural checks for the new, formally written B41 companion chapters.

Check declaration/proof coverage, backward references and the syntax of proof
reasons. This is an editorial guard, not a verifier of mathematical inference.
"""
from __future__ import annotations

from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
SOURCE_NAMES = ("product-example.tex", "product-integers.tex", "maximum-counterexample.tex", "necessary-conditions.tex")
SOURCES = tuple(ROOT / "tex/b41/differences" / name for name in SOURCE_NAMES)
CHAPTERS = {"product-example.tex": 2, "product-integers.tex": 2,
            "maximum-counterexample.tex": 3, "necessary-conditions.tex": 4}
P = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))
TABLE = re.compile(r"\\begin\{(tabproof\w*)\}.*?\\end\{\1\}", re.S)


def declarations():
    """Keep source order; offsets refer to each physical source file."""
    result = {}
    for source_index, path in enumerate(SOURCES):
        chapter = CHAPTERS[path.name]
        text = P["mask_comments"](path.read_text(encoding="utf-8-sig"))
        matches = list(re.finditer(r"\\Formula(Thm|Def)DeltaK\b", text))
        for i, match in enumerate(matches):
            call = P["call"](text, match.start(), 3)
            key = text[slice(*call.args[1])].strip()
            if not re.fullmatch(r"FD(?:Product|Max|Necessary)[A-Za-z0-9]+", key):
                raise ValueError(f"{path.name}: unexpected result ID {key}")
            if key in result:
                raise ValueError(f"Duplicate supplement declaration: {key}")
            stop = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            proof = TABLE.search(text, call.end, stop)
            kind = "theorem" if match[1] == "Thm" else "definition"
            if kind == "theorem" and proof is None:
                raise ValueError(f"{key}: no table proof before the next declaration")
            anchor = r"\hypertarget{differences.statement." + key + "}{}"
            if anchor not in text[:match.start()]:
                raise ValueError(f"{key}: missing explicit statement target")
            result[key] = {
                "path": path, "chapter": chapter, "source_index": source_index, "kind": kind,
                "start": match.start(), "available": proof.end() if kind == "theorem" else call.end,
            }
    return result


def audit_sources():
    declared = declarations()
    bookkeeping = runpy.run_path(str(ROOT / "scripts/proof-dependency-audit.py"))
    if sum(bookkeeping["check"](path) for path in SOURCES):
        raise ValueError("Supplement proof steps have inconsistent assumptions or line references")
    rule_text = (ROOT / "tex/impl/commands/rules.tex").read_text(encoding="utf-8")
    rules = set(re.findall(r"\\(?:providecommand|newcommand|renewcommand)\{\\(r[A-Za-z]+|UEI|UEE)\}", rule_text))
    wrappers = {"FormulaRefAuto", "BandXXIXProofRefStack", "begin", "end",
                "ensuremath", "left", "right", "quad", "qquad"}
    total_rows = total_tables = 0
    dependencies = set()
    for source_index, path in enumerate(SOURCES):
        text = P["mask_comments"](path.read_text(encoding="utf-8-sig"))
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
            raise ValueError(f"{path.name}: invalid control character")
        if r"\FormulaRefAutoFwd" in text:
            raise ValueError(f"{path.name}: forward-reference command")
        if re.search(r"\\FormulaAxiom\w*\b", text):
            raise ValueError(f"{path.name}: a new axiom cannot replace a proof")
        tables = list(TABLE.finditer(text))
        total_tables += len(tables)
        for row in P["rows"](text):
            total_rows += 1
            where = f"{path.name}:{text.count(chr(10), 0, row.start) + 1}"
            if not any(table.start() < row.start < table.end() for table in tables):
                raise ValueError(f"{where}: proof step outside an introduced table environment")
            formula = text[slice(*row.args[-2])]
            if re.search(r"\\(?:eqvdash|vdash|dashv)\b", formula):
                raise ValueError(f"{where}: a metalinguistic sequent used as a proof formula")
            a, b = row.args[-1]
            reason = text[a:b]
            refs = P["references"](text, a, b)
            spans = []
            for ref in refs:
                key = text[slice(*ref.args[0])].strip()
                dependencies.add(key)
                if key.startswith(("FDProduct", "FDMax", "FDNecessary")):
                    if key not in declared:
                        raise ValueError(f"{where}: missing local result {key}")
                    d = declared[key]
                    if d["source_index"] > source_index or (d["source_index"] == source_index and d["available"] >= row.start):
                        raise ValueError(f"{where}: {key} is not proved/defined before this step")
                # Ignore the mathematical key and [def]/[thm] selector, not its premises.
                spans.append((ref.start - a, (ref.args[1][0] - 1 if len(ref.args) > 1 else ref.end) - a))
            cleaned = reason
            for x, y in sorted(spans, reverse=True):
                cleaned = cleaned[:x] + r"\FormulaRefAuto" + cleaned[y:]
            for macro in re.findall(r"\\([A-Za-z@]+)", cleaned):
                if macro not in rules | wrappers:
                    raise ValueError(f"{where}: unintroduced proof-reason command \\{macro}")
            # Any remaining prose in the reason field would hide a proof step.
            remainder = re.sub(r"\\[A-Za-z@]+|\\.", "", cleaned)
            remainder = re.sub(r"\b(?:gathered|aligned|t)\b", "", remainder)
            if re.search(r"[A-Za-zÄÖÜäöüß]", remainder):
                raise ValueError(f"{where}: prose in proof reason: {reason.strip()}")
    print(f"B41 supplements: {len(declared)} declarations, {total_tables} tables, {total_rows} steps; "
          "proof coverage, backward local references and formal reason syntax passed.")
    return declared, dependencies


if __name__ == "__main__":
    audit_sources()
