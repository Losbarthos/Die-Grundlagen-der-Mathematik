"""Inventory every Band 48 source; this is deliberately NOT a proof checker."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRY = ROOT / "Bd. 48 - Axiomatische Mengenlehre II.tex"
DECLARATION = re.compile(r"\\Formula(?P<kind>Thm|Def|Axiom)DeltaK(?:R)?\b")


def group(text, pos, left="{", right="}"):
    while pos < len(text) and text[pos].isspace():
        pos += 1
    if pos >= len(text) or text[pos] != left:
        return None, pos
    start = pos + 1
    depth = 1
    pos += 1
    while pos < len(text):
        if text[pos] == "\\":
            pos += 2
            continue
        if text[pos] == left:
            depth += 1
        elif text[pos] == right:
            depth -= 1
            if depth == 0:
                return text[start:pos], pos + 1
        pos += 1
    raise ValueError(f"Unclosed group at offset {start}")


def inputs(path, seen):
    resolved = path.resolve()
    if not resolved.is_relative_to(ROOT):
        raise ValueError(f"Input outside project: {path}")
    if resolved in seen:
        raise ValueError(f"Repeated or recursive input: {path}")
    seen.add(resolved)
    text = re.sub(
        r"(?<!\\)%[^\n]*", "", path.read_text(encoding="utf-8-sig")
    )
    offset = 0
    for match in re.finditer(r"\\input\{([^}]+)\}", text):
        yield path, text.count("\n", 0, offset), text[offset:match.start()]
        child = ROOT / match.group(1)
        if not child.suffix:
            child = child.with_suffix(".tex")
        yield from inputs(child, seen)
        offset = match.end()
    yield path, text.count("\n", 0, offset), text[offset:]


def declarations(text):
    for match in DECLARATION.finditer(text):
        title, pos = group(text, match.end(), "[", "]")
        formula, pos = group(text, pos)
        key, pos = group(text, pos)
        context, pos = group(text, pos)
        if formula is None or key is None or context is None:
            continue
        if not re.fullmatch(r"B48\w+", key):
            continue
        yield {
            "id": key, "kind": match.group("kind"), "title": title or "",
            "formula": formula, "start": match.start(), "body_start": pos,
        }


def references(text):
    for match in re.finditer(r"\\FormulaRefAuto\b", text):
        key, pos = group(text, match.end())
        if key is None:
            continue
        _, pos = group(text, pos, "[", "]")
        premises, _ = group(text, pos)
        yield key, premises, match.start()


def registry_numbers():
    labels = {}
    ids = {}
    for line in (ROOT / "registry/_B48.registry.tsv").read_text(
        encoding="utf-8-sig"
    ).splitlines():
        cells = line.split("\t")
        if cells[0] == "ID" and len(cells) >= 4:
            ids[cells[1]] = cells[3]
        elif len(cells) >= 4:
            labels[cells[1]] = cells[3]
    return {key: labels.get(label, label) for key, label in ids.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-formal", action="store_true",
                        help="Fail if prose sketches or their dependants remain.")
    args = parser.parse_args()
    seen = set()
    chunks = []
    origins = []
    length = 0
    for path, preceding_lines, chunk in inputs(ENTRY, seen):
        chunks.append(chunk)
        origins.append((length, length + len(chunk), path, preceding_lines, chunk))
        length += len(chunk)
    text = "".join(chunks)
    records = list(declarations(text))
    order = {item["id"]: item["start"] for item in records}
    for match in re.finditer(r"\\proofpartwideindR\b", text):
        _, pos = group(text, match.end(), "[", "]")
        _, pos = group(text, pos)
        _, pos = group(text, pos)
        key, _ = group(text, pos, "[", "]")
        if key and re.fullmatch(r"B48\w+", key.strip()):
            order[key.strip()] = match.start()
    numbers = registry_numbers()
    for index, item in enumerate(records):
        end = records[index + 1]["start"] if index + 1 < len(records) else len(text)
        body = text[item["body_start"]:end]
        item["number"] = numbers.get(item["id"], "")
        item["prose_cells"] = len(re.findall(r"\\BXLVIII(?:Text|Why)\b", body))
        item["text_in_statement"] = bool(re.search(r"\\text\b", item["formula"]))
        item["explicitly_open"] = bool(
            re.search(r"Beweisstand:|Herleitung ist noch offen", body)
        )
        item["references"] = sorted({
            key for key, _, _ in references(body) if key.startswith("B48")
        })
        item["forward_references"] = sorted({
            key for key, _, pos in references(body)
            if key in order and order[key] > item["body_start"] + pos
        })
        item["uncatalogued_local_ids"] = sorted({
            key for key in item["references"] if key not in order
        })
        for start, stop, path, preceding_lines, chunk in origins:
            if start <= item["start"] < stop:
                item["source"] = str(path.relative_to(ROOT)).replace("\\", "/")
                item["line"] = (
                    preceding_lines + chunk.count("\n", 0, item["start"] - start) + 1
                )
                break
        for internal in ("start", "body_start"):
            item.pop(internal)
    theorem_ids = {item["id"] for item in records if item["kind"] == "Thm"}
    open_ids = {
        item["id"] for item in records
        if item["kind"] == "Thm" and (item["prose_cells"] or item["explicitly_open"])
    }
    affected = set(open_ids)
    while True:
        expanded = affected | {
            item["id"] for item in records
            if item["kind"] == "Thm" and set(item["references"]) & affected
        }
        if expanded == affected:
            break
        affected = expanded
    for item in records:
        item["direct_open_dependencies"] = sorted(set(item["references"]) & affected)
        item["status"] = (
            "definition" if item["kind"] != "Thm"
            else "open-sketch" if item["id"] in open_ids
            else "depends-on-open-sketch" if item["id"] in affected
            else "no-prose-marker-detected-not-proof-verified"
        )
    report = {
        "scope": "All inputs of Band 48, in manuscript order",
        "limitation": "Source inventory only; no mathematical proof certification.",
        "files": sorted(str(path.relative_to(ROOT)).replace("\\", "/") for path in seen),
        "theorems": len(theorem_ids), "open_sketches": len(open_ids),
        "theorems_affected_by_open_sketches": len(affected), "records": records,
    }
    destination = ROOT / "tmp/b48-audit"
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "manuscript.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# Band 48: Quellen- und Beweisketteninventar", "",
        "Dies ist eine vollstaendige Erfassung der eingebundenen Quelldateien,",
        "aber **keine Zertifizierung der mathematischen Beweise**.",
        "Ein aufgeloester Verweis bedeutet nicht, dass sein Ziel bewiesen ist.", "",
        f"- Eingebundene Dateien: {len(seen)}",
        f"- Theoreme: {len(theorem_ids)}",
        f"- Theoreme mit Prosezellen oder ausdruecklich offener Herleitung: {len(open_ids)}",
        f"- Mit explizit erfassten abhaengigen Theoremen: {len(affected)}", "",
        "## Zentrale offene Voraussetzungen", "",
        "- B48SatisfactionExists: Formelcodes, Belegungsmengen, Rekursion und Eindeutigkeit.",
        "- B48Soundness: Koinzidenz, Substitution, alle Regelfaelle und Herleitungsinduktion.",
        "- B48HenkinWitness, B48HenkinCompletion, B48Completeness: syntaktische "
        "Beweisumformungen, Henkin-Erweiterung und Termmodell-Wahrheitslemma.",
        "- B48ConsistencyDeduction: Entladung und Zusammensetzung von Beweisobjekten.", "",
        "## Weitere inhaltliche Befunde", "",
        "- Transfinite Rekursion quantifiziert derzeit ueber eine Klassenfunktion "
        "wie ueber eine Menge; die schematische/beschraenkte Form ist auszuarbeiten.",
        "- Die Def-Konstruktion benutzt bei L_0 einen leeren Bereich, waehrend "
        "die bisherige Struktursemantik Nichtleerheit voraussetzt.",
        "- Reflexion fuer L muss fuer eine feste endliche Formelliste als Schema "
        "praezisiert werden; eine einheitliche Klassenwahrheit ist nicht definiert.",
        "- In mehreren Modellkonstruktionen fehlen explizite Zeugenentladungen "
        "und konkrete Zeilennummern bei nicht voraussetzungslosen Satzanwendungen.", "",
        "## Inventar", "",
        "| Nr. | ID | Status | Prosezellen | Vorwaertsverweise |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for item in records:
        if item["kind"] == "Thm":
            forward = ", ".join(item["forward_references"]) or "-"
            lines.append(
                f"| {item['number']} | {item['id']} | {item['status']} | "
                f"{item['prose_cells']} | {forward} |"
            )
    lines.extend([
        "", "Die vollstaendigen Fundstellen, Definitionen und expliziten Abhaengigkeiten",
        "stehen in manuscript.json. Nicht ausgeschriebene oder nur in Prosa",
        "genannte Abhaengigkeiten sind durch diesen Lauf nicht vollstaendig erfasst.", "",
    ])
    (destination / "manuscript.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "records"},
                     ensure_ascii=False, indent=2))
    print(f"Reports: {destination}")
    if args.require_formal and affected:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
