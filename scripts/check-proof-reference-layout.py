#!/usr/bin/env python3
"""Audit only automatic proof-reference tables in PDFs.

Final PDFs use /ProofReferenceCell and /ProofReferenceHeader marked content.
Each BDC dictionary supplies /PRBounds [left top right bottom] for its cell and
/PRTextBounds [left top right bottom] for the independent page text area, in PDF
points measured from the page's top-left corner. Characters, stroked paths and
images are checked against both rectangles and the physical CropBox. Requiring
tags also requires both bounds, so a table shifted as a whole cannot evade the
text-area check merely because its own cell bounds moved along with it.

Examples:
  python scripts/check-proof-reference-layout.py output --require-tags \
      --report tmp/proof-reference-layout.json
  python scripts/check-proof-reference-layout.py registry/_B18.pdf --legacy \
      --report tmp/proof-reference-layout-before.json

--legacy is an explicitly non-certifying investigation of older untagged PDFs:
title/header rules identify a table; the first larger body-text font terminates
its region. It must not be used as the final guarantee for rebuilt PDFs.
Requires pdfplumber and pypdf; no PDF or TeX source is modified.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
import glob
import json
from pathlib import Path
import re
import sys

import pdfplumber
import pdfplumber.page
from pdfminer.pdftypes import resolve1
from pypdf import PdfReader


TAGS = {"ProofReferenceCell", "ProofReferenceHeader"}
TITLE = "VerwendeteSätzeundDefinitionen"
VERSION = 1
_base_aggregator = pdfplumber.page.PDFPageAggregatorWithMarkedContent


class ProofReferenceAggregator(_base_aggregator):
    """Preserve explicit bounds and outer proof tags through nested PDF tags."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._proof_stack = []
        self._proof_context = None
        self._proof_serial = 0

    def begin_tag(self, tag, props=None):
        self._proof_stack.append(self._proof_context)
        super().begin_tag(tag, props)
        name = str(tag.name)
        if name in TAGS:
            self._proof_serial += 1
            properties = resolve1(props) if props is not None else {}
            bounds = properties.get("PRBounds") if isinstance(properties, dict) else None
            bounds = resolve1(bounds) if bounds is not None else None
            text_bounds = properties.get("PRTextBounds") if isinstance(properties, dict) else None
            text_bounds = resolve1(text_bounds) if text_bounds is not None else None
            self._proof_context = (name, bounds, text_bounds, self._proof_serial)

    def end_tag(self):
        super().end_tag()
        self._proof_context = self._proof_stack.pop() if self._proof_stack else None

    def tag_cur_item(self):
        super().tag_cur_item()
        if self._proof_context and self.cur_item._objs:
            item = self.cur_item._objs[-1]
            item.pr_tag, item.pr_bounds, item.pr_text_bounds, item.pr_serial = self._proof_context


pdfplumber.page.PDFPageAggregatorWithMarkedContent = ProofReferenceAggregator
pdfplumber.page.ALL_ATTRS.update({"pr_tag", "pr_bounds", "pr_text_bounds", "pr_serial"})


def bbox(obj):
    """Nominal glyph box, or path/image box including half the stroke width."""
    pad = float(obj.get("linewidth", 0) or 0) / 2 if obj.get("stroke") else 0
    return [float(obj["x0"]) - pad, float(obj["top"]) - pad,
            float(obj["x1"]) + pad, float(obj["bottom"]) + pad]


def overrun(box, bounds, tolerance):
    values = (bounds[0] - box[0], bounds[1] - box[1],
              box[2] - bounds[2], box[3] - bounds[3])
    return {side: round(value, 3) for side, value in
            zip(("left", "top", "right", "bottom"), values) if value > tolerance}


def title_indices(chars):
    letters, mapping = [], []
    for index, char in enumerate(chars):
        for letter in char.get("text", ""):
            if not letter.isspace():
                letters.append(letter)
                mapping.append(index)
    text = "".join(letters)
    return [(mapping[m.start()], mapping[m.end() - 1])
            for m in re.finditer(re.escape(TITLE), text)]


def valid_bounds(value):
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        return None
    try:
        result = list(map(float, value))
    except (ValueError, TypeError):
        return None
    return result if result[0] < result[2] and result[1] < result[3] else None


def legacy_regions(page, titles):
    """Conservative source-order/font heuristic; reports remain uncertified."""
    regions = []
    chars = page.chars
    for position, (start, title_end) in enumerate(titles):
        first = chars[start]
        size = float(first["size"])
        next_start = titles[position + 1][0] if position + 1 < len(titles) else len(chars)
        end = next_start
        for i in range(title_end + 1, next_start):
            char = chars[i]
            if ("Roman" in char.get("fontname", "")
                    and float(char.get("size", 0)) > size * 1.06
                    and char.get("text", "").strip()):
                end = i
                break
        selected = chars[start:end]
        rules = [obj for obj in page.lines + page.rects
                 if abs(obj["height"]) <= 1 and obj["width"] > page.width * .4
                 and first["top"] < obj["top"] < first["top"] + 45
                 and abs(obj["x0"] - first["x0"]) < 2]
        if not selected or not rules:
            continue
        rule = min(rules, key=lambda obj: obj["top"])
        bottom = max(obj["bottom"] for obj in selected)
        shapes = [obj for kind in ("line", "rect", "curve", "image")
                  for obj in page.objects.get(kind, [])
                  if first["top"] <= obj["top"] <= bottom and obj["bottom"] <= bottom + 2]
        # Existing canonical report pages use a footer below the text area.
        # Do not infer a vertical text bound: only physical bottom is conclusive.
        bounds = [rule["x0"], 0.0, rule["x1"], page.height]
        regions.append((selected + shapes, bounds, first["top"], bottom))
    return regions


def group_issues(objects, bounds, page_bounds, tolerance, page_number, label, text_bounds=None):
    grouped = defaultdict(list)
    limits = {"page_bounds": page_bounds, "declared_bounds": bounds, "text_bounds": text_bounds}
    for obj in objects:
        if obj.get("object_type") == "char" and not obj.get("text", "").strip():
            continue
        box = bbox(obj)
        for kind, limit in limits.items():
            if limit is None:
                continue
            excess = overrun(box, limit, tolerance)
            if excess:
                grouped[kind].append((obj, box, excess))
    issues = []
    for kind, entries in grouped.items():
        union = [min(x[1][0] for x in entries), min(x[1][1] for x in entries),
                 max(x[1][2] for x in entries), max(x[1][3] for x in entries)]
        maximum = {side: max(x[2].get(side, 0) for x in entries)
                   for side in ("left", "top", "right", "bottom")}
        issues.append({"kind": kind, "page": page_number, "region": label,
                       "count": len(entries), "bbox": [round(x, 3) for x in union],
                       "bounds": [round(x, 3) for x in limits[kind]],
                       "excess_pt": {key: value for key, value in maximum.items() if value},
                       "object_types": dict(Counter(x[0]["object_type"] for x in entries)),
                       "text": "".join(x[0].get("text", "") for x in entries)[:180]})
    return issues


def audit_pdf(args):
    path, tolerance, legacy, require_tags = args
    path = Path(path)
    result = {"pdf": str(path), "pages": 0, "table_pages": 0, "titles": 0,
              "tagged_regions": 0, "objects_checked": 0, "legacy_regions": 0,
              "certified": True, "issues": []}
    try:
        reader = PdfReader(path)
        candidates = []
        for i, page in enumerate(reader.pages):
            stream = page.get_contents()
            # ContentStream is dict-like and can be false even with valid bytes.
            raw = stream.get_data() if stream is not None else b""
            tagged = any(("/" + tag).encode() in raw for tag in TAGS)
            # Decode text only on older pages. Final tagged pages need no heuristic.
            text = "" if tagged else (page.extract_text() or "")
            has_title = TITLE in "".join(text.split())
            if tagged or has_title:
                candidates.append((i, tagged))
        result["pages"] = len(reader.pages)
        with pdfplumber.open(path) as pdf:
            for index, tagged in candidates:
                page = pdf.pages[index]
                page_number = index + 1
                result["table_pages"] += 1
                titles = title_indices(page.chars)
                result["titles"] += len(titles)
                physical = list(page.cropbox or page.bbox)
                objects = [obj for kind in ("char", "line", "rect", "curve", "image")
                           for obj in page.objects.get(kind, [])]
                if tagged:
                    groups = defaultdict(list)
                    for obj in objects:
                        if obj.get("pr_tag") in TAGS:
                            groups[obj["pr_serial"]].append(obj)
                    if not groups:
                        result["certified"] = False
                        result["issues"].append({"kind": "unreadable_tags", "page": page_number})
                    elif groups[min(groups)][0]["pr_tag"] != "ProofReferenceHeader":
                        # A longtable continuation must start with its repeated
                        # heading. A final row escaping the output routine can
                        # otherwise fit the page yet silently lose that heading.
                        first_serial = min(groups)
                        result["issues"].append({"kind": "missing_continuation_header",
                                                 "page": page_number,
                                                 "region": f"ProofReferenceCell:{first_serial}"})
                    for serial, tagged_objects in groups.items():
                        first = tagged_objects[0]
                        bounds = valid_bounds(first.get("pr_bounds"))
                        text_bounds = valid_bounds(first.get("pr_text_bounds"))
                        result["tagged_regions"] += 1
                        result["objects_checked"] += len(tagged_objects)
                        label = f'{first["pr_tag"]}:{serial}'
                        if bounds is None:
                            result["certified"] = False
                            result["issues"].append({"kind": "missing_bounds", "page": page_number,
                                                     "region": label})
                        if text_bounds is None:
                            result["certified"] = False
                            if require_tags:
                                result["issues"].append({"kind": "missing_text_bounds", "page": page_number,
                                                         "region": label})
                        result["issues"].extend(group_issues(tagged_objects, bounds, physical,
                                                           tolerance, page_number, label, text_bounds))
                    for start, _ in titles:
                        if page.chars[start].get("pr_tag") not in TAGS:
                            result["certified"] = False
                            result["issues"].append({"kind": "untagged_title", "page": page_number})
                else:
                    result["certified"] = False
                    if require_tags or not legacy:
                        result["issues"].append({"kind": "missing_tags", "page": page_number,
                                                 "titles": len(titles)})
                    if legacy:
                        for serial, (region, bounds, top, bottom) in enumerate(legacy_regions(page, titles), 1):
                            result["legacy_regions"] += 1
                            result["objects_checked"] += len(region)
                            result["issues"].extend(group_issues(region, bounds, physical, tolerance,
                                                               page_number, f"legacy:{serial}"))
                page.close()
    except Exception as exc:
        result["certified"] = False
        result["issues"].append({"kind": "parser_error", "message": str(exc)})
    if result["issues"]:
        result["certified"] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pdfs", nargs="+", help="PDF files, glob expressions or directories (recursive)")
    parser.add_argument("--report", type=Path, help="write the complete machine-readable JSON report")
    parser.add_argument("--tolerance", type=float, default=1.5, help="per-edge tolerance in PDF points (default: 1.5)")
    parser.add_argument("--legacy", action="store_true", help="investigate old untagged tables, without certification")
    parser.add_argument("--require-tags", action="store_true", help="fail if any table lacks final PDF tags/bounds")
    parser.add_argument("--jobs", type=int, default=1, help="independent PDF worker processes")
    args = parser.parse_args()
    if args.tolerance < 0 or args.jobs < 1:
        parser.error("tolerance must be nonnegative; jobs must be positive")
    paths = set()
    for expression in args.pdfs:
        matches = [Path(expression)] if Path(expression).exists() else map(Path, glob.glob(expression))
        for match in matches:
            paths.update(match.rglob("*.pdf") if match.is_dir() else [match])
    paths = sorted(path for path in paths if path.is_file() and path.suffix.lower() == ".pdf")
    if not paths:
        parser.error("no PDF files found")
    work = [(str(path), args.tolerance, args.legacy, args.require_tags) for path in paths]
    if args.jobs > 1:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(audit_pdf, work))
    else:
        results = list(map(audit_pdf, work))
    totals = {key: sum(result[key] for result in results)
              for key in ("pages", "table_pages", "titles", "tagged_regions", "legacy_regions", "objects_checked")}
    totals.update(pdfs=len(results), issues=sum(len(result["issues"]) for result in results),
                  certified=all(result["certified"] for result in results))
    report = {"schema_version": VERSION, "units": "PDF bp; coordinates from top left",
              "tolerance_pt": args.tolerance, "legacy": args.legacy, "totals": totals, "results": results}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for result in results:
        for issue in result["issues"]:
            print(f'{result["pdf"]}: {json.dumps(issue, ensure_ascii=True)}')
    print(json.dumps(totals, ensure_ascii=True))
    return 1 if totals["issues"] or (args.require_tags and not totals["certified"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
