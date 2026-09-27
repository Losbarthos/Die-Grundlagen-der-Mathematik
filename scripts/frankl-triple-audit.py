"""Check the printed rare-triple example and the new companion proof sources.

The exhaustive finite check validates this concrete set family. Source checks
only guard document structure; mathematical proof review remains separate.
"""
from pathlib import Path
from collections import Counter
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tex/b46/frankl"
P = runpy.run_path(str(ROOT / "scripts/proof-source-audit.py"))
TABLE = re.compile(r"\\begin\{(tabproof\w*)\}.*?\\end\{\1\}", re.S)


def example():
    text = (SOURCE / "reading-diagrams.tex").read_text(encoding="utf-8-sig")
    text = text.split(r"\newcommand{\FranklRareTripleTable}", 1)[1]
    text = text.split(r"\newcommand{\FranklInjectionDiagram}", 1)[0]
    a, b = frozenset("abc"), frozenset("defg")
    known = {r"\varnothing": frozenset(), "A": a, "B": b,
             "D_a": frozenset("deg"), "D_b": frozenset("dfg"),
             "D_c": frozenset("efg")}
    sets = []
    for line in text.splitlines():
        match = re.match(r"\s*\\\((.*?)\\\)\s*&\s*([01](?:\s*&\s*[01]){6})\\\\", line)
        if not match:
            continue
        name, entries = match.groups()
        entries = [int(x.strip()) for x in entries.split("&")]
        actual = frozenset(x for x, flag in zip("abcdefg", entries) if flag)
        expected = frozenset()
        for part in name.split(r"\cup"):
            part = part.strip()
            if part in known:
                expected |= known[part]
            elif part.startswith(r"\{") and part.endswith(r"\}"):
                expected |= frozenset(part[2:-2].split(","))
            else:
                raise ValueError(f"Unrecognized incidence row: {name}")
        if actual != expected:
            raise ValueError(f"Wrong incidence values for {name}")
        sets.append(actual)
    family = set(sets)
    if len(sets) != 19 or len(family) != 19 or a not in family:
        raise ValueError("The incidence table must display 19 distinct sets including A")
    for x in family:
        for y in family:
            if x | y not in family:
                raise ValueError(f"Union closure fails for {x}, {y}")
    frequencies = [sum(x in member for member in family) for x in "abcdefg"]
    if frequencies != [9, 9, 9, 14, 14, 14, 17]:
        raise ValueError(f"Unexpected frequencies: {frequencies}")
    if Counter(len(x & a) for x in family) != {0: 5, 1: 6, 2: 3, 3: 5}:
        raise ValueError("The four counting classes do not match the reading text")
    if min(len(x) for x in family if x) != 3:
        raise ValueError("The least nonempty member must have three elements")
    proof_text = (SOURCE / "triple-proofs.tex").read_text(encoding="utf-8-sig")
    proof_rows = {}
    for line in proof_text.splitlines():
        match = re.match(r"^.*?&\s*(\d+)\s*&.+?&\s*([01](?:\s*&\s*[01]){6})\\\\", line)
        if match:
            index = int(match[1])
            flags = [int(x.strip()) for x in match[2].split("&")]
            proof_rows[index] = frozenset(x for x, flag in zip("abcdefg", flags) if flag)
    if set(proof_rows) != set(range(1, 20)) or any(proof_rows[i] != sets[i - 1] for i in proof_rows):
        raise ValueError("The formal incidence certificate differs from the reading table")
    index_rows = {}
    for line in proof_text.splitlines():
        match = re.match(r"\s*([abc])\s*&\s*([\d,]+)\s*&\s*([\d,]+)\\\\", line)
        if match:
            index_rows[match[1]] = tuple(tuple(map(int, x.split(","))) for x in match.groups()[1:])
    for x in "abc":
        expected = (tuple(i for i in range(1, 20) if x in proof_rows[i]),
                    tuple(i for i in range(1, 20) if x not in proof_rows[i]))
        if index_rows.get(x) != expected:
            raise ValueError(f"The formal nine/ten lists are incorrect for {x}")
    print("Rare-triple example: 19 distinct rows, 361 unions, frequencies 9/9/9/14/14/14/17 and counting classes checked.")
    print("The formal incidence certificate and all six nine/ten index lists agree with the reading table.")


def declarations():
    path = SOURCE / "triple-proofs.tex"
    text = P["mask_comments"](path.read_text(encoding="utf-8-sig"))
    results = {}
    matches = list(re.finditer(r"\\Formula(Thm|Def)DeltaK\b", text))
    for index, match in enumerate(matches):
        call = P["call"](text, match.start(), 3)
        key = text[slice(*call.args[1])].strip()
        if not key.startswith("FranklTriple") or key in results:
            raise ValueError(f"Unexpected or duplicate local statement: {key}")
        stop = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        main_proof = text.find(r"\hypertarget{frankl.proof.FranklRareTripleExists}", call.end)
        if main_proof >= 0:
            stop = min(stop, main_proof)
        proofs = list(TABLE.finditer(text, call.end, stop))
        if match[1] == "Thm" and not proofs:
            raise ValueError(f"No table proof for {key}")
        results[key] = {"kind": "theorem" if match[1] == "Thm" else "definition",
                        "available": proofs[-1].end() if proofs else call.end}
    if not results:
        raise ValueError("The rare-triple example has no formal auxiliary statements")
    if re.search(r"\\FormulaAxiom\w*\b|\\FormulaRefAutoFwd\b", text):
        raise ValueError("New axioms and forward references cannot replace rare-triple proofs")
    for row in P["rows"](text):
        a, b = row.args[-1]
        for ref in P["references"](text, a, b):
            key = text[slice(*ref.args[0])].strip()
            if key.startswith("FranklTriple"):
                if key not in results or results[key]["available"] >= row.start:
                    raise ValueError(f"Local result is not yet proved or defined: {key}")
    return results


def audit_sources():
    example()
    declared = declarations()
    print(f"Rare-triple supplement: {len(declared)} local auxiliary statements with proof-table coverage.")
    return declared


if __name__ == "__main__":
    audit_sources()
