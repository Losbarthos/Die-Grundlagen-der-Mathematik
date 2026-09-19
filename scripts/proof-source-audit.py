"""Structural inventory of the active manuscript's proof tables.

The scanner balances TeX groups and ignores comments. It deliberately does not
claim to check mathematical validity; its JSON records support editorial review.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def mask_comments(text):
    return re.sub(r"(?<!\\)%[^\n]*", lambda m: " " * len(m[0]), text)


def skip(text, p):
    while p < len(text) and text[p].isspace():
        p += 1
    return p


def group(text, p, opener="{"):
    p = skip(text, p)
    if p >= len(text) or text[p] != opener:
        return None, p
    closer = "}" if opener == "{" else "]"
    start, depth = p + 1, 1
    p += 1
    braces = 0
    while p < len(text):
        if text[p] == "\\":
            m = re.match(r"\\(?:[A-Za-z@]+|.)", text[p:])
            p += len(m[0]) if m else 1
            continue
        if opener == "[":
            if text[p] == "{":
                braces += 1
            elif text[p] == "}":
                braces -= 1
        if not braces:
            if text[p] == opener:
                depth += 1
            elif text[p] == closer:
                depth -= 1
                if depth == 0:
                    return (start, p), p + 1
        p += 1
    raise ValueError(f"Unclosed group at {start - 1}")


@dataclass
class Call:
    name: str
    start: int
    end: int
    args: list
    opts: list
    star: bool = False


def call(text, pos, mandatory, optional_before=True, optional_after=0):
    m = re.match(r"\\([A-Za-z@]+)", text[pos:])
    if not m:
        raise ValueError(pos)
    p = skip(text, pos + len(m[0]))
    star = p < len(text) and text[p] == "*"
    if star:
        p += 1
    opts, args = [], []
    if optional_before:
        opt, q = group(text, p, "[")
        if opt:
            opts.append(opt)
            p = q
    for _ in range(mandatory):
        arg, p = group(text, p)
        if arg is None:
            raise ValueError(f"Missing argument of {m[1]} at {p}")
        args.append(arg)
    for _ in range(optional_after):
        opt, q = group(text, p, "[")
        if not opt:
            break
        opts.append(opt)
        p = q
    return Call(m[1], pos, p, args, opts, star)


def reference(text, pos):
    c = call(text, pos, 1, optional_after=1)
    arg, p = group(text, c.end)
    if arg:
        c.args.append(arg)
        c.end = p
    return c


def references(text, start=0, end=None):
    end = len(text) if end is None else end
    result = []
    for m in re.finditer(r"\\FormulaRefAuto(?:Fwd)?\b", text[start:end]):
        result.append(reference(text, start + m.start()))
    return result


ROW_RE = re.compile(r"\\(proofstep[A-Za-z]*|proofaxline)\b")


def rows(text):
    for m in ROW_RE.finditer(text):
        name = m[1]
        if name == "proofstepwide":
            n, optional = 4, True
        elif name in {"proofstep", "proofstepstar", "proofstepstarwide"}:
            n, optional = 3, False
        elif name.startswith("proofstepwidestar") or name == "proofsteppaired":
            n, optional = 2, True
        elif name == "proofaxline":
            n, optional = 2, False
        else:
            continue
        try:
            yield call(text, m.start(), n, optional)
        except ValueError:
            continue


def inventory(path):
    original = path.read_text(encoding="utf-8-sig")
    text = mask_comments(original)
    data = {"file": path.resolve().relative_to(ROOT).as_posix(), "lines": text.count("\n") + 1,
            "environments": dict(Counter(re.findall(r"\\begin\{(tabproof\w*|proof)\}", text))),
            "rows": 0, "nested_theorems": [], "inline_rows": [],
            "control_characters": [
                {"line": original.count("\n", 0, m.start()) + 1,
                 "codepoint": ord(m[0])}
                for m in re.finditer(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", original)
            ]}
    for row in rows(text):
        data["rows"] += 1
        if row.name == "proofstepwidestarinline":
            data["inline_rows"].append(text.count("\n", 0, row.start) + 1)
        if row.name == "proofaxline":
            continue
        a, b = row.args[-1]
        refs = references(text, a, b)
        for ref in refs:
            outer = [r for r in refs if r.start < ref.start and r.end >= ref.end]
            # A theorem nested in any inference argument also deserves review.
            prefix = text[a:ref.start].strip()
            if outer or (prefix and not re.fullmatch(r"\\(?:ensuremath|text)\{", prefix)):
                data["nested_theorems"].append({
                    "line": text.count("\n", 0, row.start) + 1,
                    "key": text[slice(*ref.args[0])].strip(),
                    "in_theorem": bool(outer),
                    "reason": original[a:b].strip(),
                    "formula": original[slice(*row.args[-2])].strip(),
                })
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="tmp/proof-audit/source-inventory.json")
    args = ap.parse_args()
    sources = sorted(ROOT.glob("Bd. *.tex"))
    examples = ROOT / "tex/B28-isomorphism-examples.tex"
    if examples.exists():
        sources.append(examples)
    # Scan the extracted CSB sources as physical files, without expanding TeX
    # inputs or macros: each row appears once and keeps its source line number.
    sources.extend(sorted((ROOT / "tex/b08/cantor-bernstein").glob("*.tex")))
    data = [inventory(p) for p in sources]
    target = ROOT / args.output
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print("file rows nested nested-in-theorem inline")
    for d in data:
        print(d["file"], d["rows"], len(d["nested_theorems"]),
              sum(x["in_theorem"] for x in d["nested_theorems"]), len(d["inline_rows"]))
    print("TOTAL", sum(d["rows"] for d in data),
          sum(len(d["nested_theorems"]) for d in data))
    controls = sum(len(d["control_characters"]) for d in data)
    print("INVALID CONTROL CHARACTERS", controls)
    if controls:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
