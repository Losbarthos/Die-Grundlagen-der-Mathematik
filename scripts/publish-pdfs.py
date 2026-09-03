"""Publish the rebuilt PDFs with working links between their visible filenames.

Only remote PDF filenames change; pages, named destinations and metadata are
cloned from LuaLaTeX. --audit-only checks the published set without compiling.
"""
from __future__ import annotations

import argparse
import csv
import os
import shutil
import sys
import tempfile
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "output" / "pdf"


def remote_actions(reader):
    for page in reader.pages:
        for annotation in page.get("/Annots", []):
            action = annotation.get_object().get("/A")
            if action is not None:
                action = action.get_object()
                if action.get("/S") == "/GoToR":
                    yield action


def file_name(action):
    value = action["/F"]
    if isinstance(value, dict):
        value = value.get("/UF", value.get("/F", ""))
    return str(value).replace("\\", "/")


def audit_local_targets(reader, path):
    names = set(reader.named_destinations)
    total = 0
    for page in reader.pages:
        for reference in page.get("/Annots", []):
            annotation = reference.get_object()
            destination = annotation.get("/Dest")
            action = annotation.get("/A")
            if action is not None:
                action = action.get_object()
                if action.get("/S") == "/GoTo":
                    destination = action.get("/D")
            if isinstance(destination, str):
                if str(destination) not in names:
                    raise ValueError(f"{path.name}: missing local destination {destination!r}")
                total += 1
    return total


def audit(paths):
    cache = {}
    page_total = 0
    local_link_total = 0
    external_link_total = 0
    for path in paths:
        reader = PdfReader(path)
        local_total = audit_local_targets(reader, path)
        total = 0
        for action in remote_actions(reader):
            target = (path.parent / file_name(action)).resolve()
            if not target.is_relative_to(OUTPUT.resolve()):
                raise ValueError(f"{path.name}: link outside output/pdf: {target}")
            if not target.is_file():
                raise ValueError(f"{path.name}: missing linked PDF: {target.name}")
            if target not in cache:
                cache[target] = set(PdfReader(target).named_destinations)
            destination = action.get("/D")
            if isinstance(destination, str) and str(destination) not in cache[target]:
                raise ValueError(f"{path.name}: missing destination {destination!r} in {target.name}")
            if not isinstance(destination, str):
                raise ValueError(f"{path.name}: unsupported remote destination {destination!r}")
            total += 1
        page_total += len(reader.pages)
        local_link_total += local_total
        external_link_total += total
        print(f"PDF links passed: {path.name} ({len(reader.pages)} pages, {local_total} local links, {total} external links)", flush=True)
    print(f"PDF link audit passed: {len(paths)} files, {page_total} pages, "
          f"{local_link_total} local links, {external_link_total} external links.", flush=True)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--skip-main", action="store_true")
    parser.add_argument("--skip-remarkable", action="store_true")
    args = parser.parse_args()
    with (ROOT / "band-dependencies.tsv").open(encoding="utf-8-sig", newline="") as file:
        graph = list(csv.DictReader(file, delimiter="\t"))
    names = {f"_{row['band']}.pdf": Path(row["source"]).with_suffix(".pdf").name for row in graph}
    publications = [(ROOT / (row["artifact_base"] + ".pdf"), OUTPUT / names[f"_{row['band']}.pdf"]) for row in graph]
    if not args.skip_remarkable:
        publications.append((ROOT / "registry/_B37-remarkable.pdf", OUTPUT / "Bd. 37 - Endliche Halbgruppen - reMarkable.pdf"))
    if not args.skip_main:
        publications.append((ROOT / "main.pdf", OUTPUT / "Die Grundlagen der Mathematik - Gesamtband.pdf"))

    if not args.audit_only:
        missing = [str(source.relative_to(ROOT)) for source, _ in publications if not source.is_file()]
        if missing:
            raise FileNotFoundError("Missing build artifacts: " + ", ".join(missing))
        OUTPUT.mkdir(parents=True, exist_ok=True)
        for source, destination in publications:
            reader = PdfReader(source)
            writer = PdfWriter(clone_from=reader)
            for action in remote_actions(writer):
                old_name = Path(file_name(action)).name
                if old_name not in names:
                    raise ValueError(f"{source.name}: unknown external PDF {old_name}")
                action[NameObject("/F")] = DictionaryObject({
                    NameObject("/Type"): NameObject("/Filespec"),
                    NameObject("/F"): TextStringObject(names[old_name]),
                    NameObject("/UF"): TextStringObject(names[old_name]),
                })
            temporary = destination.with_suffix(".pdf.tmp")
            with temporary.open("wb") as file:
                writer.write(file)
            try:
                os.replace(temporary, destination)
            except PermissionError:
                # A Windows sharing mode can permit writes while denying a
                # rename. Validate the complete replacement and preserve the
                # existing PDF until this fallback has finished successfully.
                if not destination.is_file():
                    raise
                replacement = PdfReader(temporary)
                if len(replacement.pages) != len(reader.pages):
                    raise ValueError(f"{temporary.name}: incomplete replacement PDF")
                audit_local_targets(replacement, temporary)
                with tempfile.NamedTemporaryFile(prefix=destination.name + ".", suffix=".backup", dir=OUTPUT, delete=False) as file:
                    backup = Path(file.name)
                try:
                    shutil.copyfile(destination, backup)
                except Exception:
                    backup.unlink()
                    raise
                try:
                    shutil.copyfile(temporary, destination)
                except Exception:
                    shutil.copyfile(backup, destination)
                    raise
                backup.unlink()
                temporary.unlink()
            writer.close()
            print(f"Published: {destination.name}", flush=True)
    audit([destination for _, destination in publications])


if __name__ == "__main__":
    main()
