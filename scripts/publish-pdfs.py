"""Publish PDFs in subject folders with working relative links between volumes.

Only remote PDF paths change; pages, named destinations and metadata are
cloned from LuaLaTeX. --audit-only checks the published set without compiling.
--organize-existing sorts the current publications without rebuilding them.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "output"
MAIN_NAME = "Die Grundlagen der Mathematik - Gesamtband.pdf"
PUBLICATION_GROUPS = {
    "00 Einstieg und Gesamtband": (0,),
    "01 Logik": (1, 2),
    "02 Mengenlehre und Mengenfamilien": (3, 9, 20, 46, 48),
    "03 Relationen und Funktionen": (4, 5, 6, 7, 8, 11),
    "04 Zahlen und Folgen": (10, 17, 18, 19, 21),
    "05 Ordnungen und Verbände": (12, 13, 14, 15, 16, 45),
    "06 Graphen, Bäume und Wörter": (22, 23, 24, 25, 26, 27),
    "07 Halbgruppen und Monoide": tuple(range(28, 39)),
    "08 Gruppen": (40, 41, 42),
    "09 Halbringe und Ringe": (39, 43, 44),
    "10 Metrische Räume": (47,),
}
CSB_PILOT_NAMES = {
    "_B08-csb-reading.pdf": "Bd. 08 - Cantor-Bernstein - Lesefassung.pdf",
    "_B08-csb-proofs.pdf": "Bd. 08 - Cantor-Bernstein - Beweistabellen.pdf",
}
SUPPLEMENT_TOPICS = {name: "Cantor-Bernstein" for name in CSB_PILOT_NAMES.values()}


def publication_path(name):
    """Keep visible filenames stable; use the same layout for every publisher."""
    match = re.fullmatch(r"Bd\. (\d{2}) - .+\.pdf", name)
    band = 0 if name == MAIN_NAME else int(match[1]) if match else None
    groups = [group for group, bands in PUBLICATION_GROUPS.items() if band in bands]
    if len(groups) != 1:
        raise ValueError(f"No unique publication folder for {name!r}")
    directory = OUTPUT / groups[0]
    if name in SUPPLEMENT_TOPICS:
        directory = directory / "Ergänzungen" / SUPPLEMENT_TOPICS[name]
    return directory / name


def relative_pdf_target(action, source, destination, names):
    old_name = Path(file_name(action)).name
    if old_name not in names:
        raise ValueError(f"{source.name}: unknown external PDF {old_name}")
    relative = os.path.relpath(publication_path(names[old_name]), destination.parent)
    return Path(relative).as_posix()


def rewrite_remote_links(writer, source, destination, names):
    for action in remote_actions(writer):
        relative = relative_pdf_target(action, source, destination, names)
        action[NameObject("/F")] = DictionaryObject({
            NameObject("/Type"): NameObject("/Filespec"),
            NameObject("/F"): TextStringObject(relative),
            NameObject("/UF"): TextStringObject(relative),
        })


def install_organized(sources, staged_paths, backup_root):
    """Restore the previous layout if Windows locks interrupt installation."""
    installed = []
    removed = []
    try:
        for source, staged in zip(sources, staged_paths):
            destination = publication_path(source.name)
            if not destination.resolve().is_relative_to(OUTPUT.resolve()):
                raise ValueError(f"Destination outside output: {destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = None
            try:
                if os.name == "nt":
                    # Moving from mkdtemp preserves its private Windows ACL.
                    # A fresh file in the destination inherits its normal ACL.
                    with tempfile.NamedTemporaryFile(prefix=destination.name + ".", suffix=".tmp",
                                                     dir=destination.parent, delete=False) as file:
                        temporary = Path(file.name)
                        with staged.open("rb") as staged_file:
                            shutil.copyfileobj(staged_file, file)
                os.replace(temporary if temporary is not None else staged, destination)
                installed.append((source, destination))
                if temporary is not None:
                    staged.unlink()
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        # The replacement set is complete before removing any of the old paths.
        for source in sources:
            if source != publication_path(source.name):
                source.unlink()
                removed.append(source)
    except Exception as error:
        recovery_errors = []
        restore = removed + [source for source, destination in installed if source == destination]
        for source in restore:
            try:
                shutil.copy2(backup_root / source.relative_to(OUTPUT), source)
            except OSError as recovery_error:
                recovery_errors.append(str(recovery_error))
        for source, destination in installed:
            if source != destination:
                try:
                    destination.unlink()
                except OSError as recovery_error:
                    recovery_errors.append(str(recovery_error))
        status = "Previous layout restored." if not recovery_errors else (
            "Automatic recovery incomplete: " + "; ".join(recovery_errors)
        )
        raise RuntimeError(f"PDF organization failed. {status} Originals: {backup_root}") from error


def organize_existing(names):
    """Stage and audit all current files, retaining originals for recovery."""
    known = set(names.values()) | {MAIN_NAME}
    sources = sorted(OUTPUT.rglob("*.pdf"))
    if not sources:
        raise FileNotFoundError("No published PDFs found in output")
    by_name = {}
    for source in sources:
        if not source.resolve().is_relative_to(OUTPUT.resolve()):
            raise ValueError(f"PDF outside output: {source}")
        if source.name not in known:
            raise ValueError(f"Unknown PDF in output: {source}")
        if source.name in by_name:
            raise ValueError(f"Duplicate PDF in output: {source.name}")
        by_name[source.name] = source
    if all(source == publication_path(source.name) for source in sources):
        audit(sources)
        print("PDFs are already organized.", flush=True)
        return

    workspace = ROOT / "tmp"
    workspace.mkdir(exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="pdf-organization-", dir=workspace))
    backup_root = stage / "originals"
    staged_root = stage / "organized"
    print(f"Staging {len(sources)} PDFs; original snapshots: {backup_root}", flush=True)
    aliases = {**names, **{name: name for name in known}}
    hashes = {}
    staged_paths = []
    changed_sources = []
    changed_staged_paths = []
    for source in sources:
        backup = backup_root / source.relative_to(OUTPUT)
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, backup)
        hashes[source] = hashlib.sha256(backup.read_bytes()).digest()
        destination = publication_path(source.name)
        staged = staged_root / destination.relative_to(OUTPUT)
        staged.parent.mkdir(parents=True, exist_ok=True)
        reader = PdfReader(backup)
        needs_update = source != destination or any(
            file_name(action) != relative_pdf_target(action, source, destination, aliases)
            for action in remote_actions(reader)
        )
        if needs_update:
            writer = PdfWriter(clone_from=reader)
            rewrite_remote_links(writer, source, destination, aliases)
            with staged.open("wb") as file:
                writer.write(file)
            writer.close()
            changed_sources.append(source)
            changed_staged_paths.append(staged)
        else:
            shutil.copy2(backup, staged)
        staged_paths.append(staged)
    # All links must resolve within the staged tree before any source is changed.
    audit(staged_paths, root=staged_root)
    for source in sources:
        if hashlib.sha256(source.read_bytes()).digest() != hashes[source]:
            raise ValueError(f"Publication changed during organization: {source}")
    install_organized(changed_sources, changed_staged_paths, backup_root)
    print(f"Organized {len(sources)} PDFs in {len(PUBLICATION_GROUPS)} subject folders; "
          f"updated {len(changed_sources)} files.", flush=True)
    print(f"Original PDFs retained in: {backup_root}", flush=True)


def audit_reference_markers(reader, path):
    """A resolved PDF link alone does not detect printed lookup errors."""
    pattern = re.compile(
        r"(?:Theorem|Definition|Axiom|Regel|Referenz)\s+nicht\s+gefunden"
        r"|Mehrdeutige\s+(?:Theorem|Definition|Axiom|Regel)-Referenz"
        r"|Mehrdeutig:\s*bitte",
        re.IGNORECASE,
    )
    pdftotext = shutil.which("pdftotext")
    if pdftotext is None:
        page_texts = (page.extract_text() or "" for page in reader.pages)
    else:
        # Keep content-stream order: physical layout can interleave a wrapped
        # reference error with formulas from the neighbouring proof column.
        result = subprocess.run(
            [pdftotext, "-raw", "-enc", "UTF-8", str(path), "-"],
            stdout=subprocess.PIPE, encoding="utf-8", check=True,
        )
        pages = result.stdout.split("\f")
        if len(pages) != len(reader.pages) + 1 or pages[-1].strip():
            raise ValueError(f"{path.name}: pdftotext returned an unexpected page count")
        page_texts = pages[:-1]
    for number, text in enumerate(page_texts, 1):
        content = " ".join(text.split())
        match = pattern.search(content)
        if match:
            raise ValueError(
                f"{path.name}: unresolved reference on PDF page {number}: "
                f"{match.group(0)}"
            )


def assert_build_ready(source, reader):
    """Reject failed formula lookups before replacing a published volume."""
    if re.fullmatch(r"_B\d{2}", source.stem) or source.name in CSB_PILOT_NAMES:
        debug = source.with_suffix(".debug.log")
        log = source.with_suffix(".log")
        for required in (debug, log):
            if not required.is_file():
                raise FileNotFoundError(f"Missing build diagnostic: {required}")
        failed = re.search(
            r"^status:\s*(?:none|ambiguous[^\r\n]*|duplicate-register)\s*$",
            debug.read_text(encoding="utf-8", errors="replace"),
            re.MULTILINE | re.IGNORECASE,
        )
        if failed:
            raise ValueError(f"{source.name}: {debug.name}: {failed.group(0)}")
        diagnostics = " ".join(
            log.read_text(encoding="utf-8", errors="replace").split()
        )
        if re.search(
            r"There were undefined references|There were multiply-defined labels"
            r"|LABELS NOT IMPORTED|Rerun to get cross-references right"
            r"|(?:LaTeX Warning:\s*(?:Reference|Hyper reference).{0,1000}?undefined)"
            r"|thmlookup:\s*cannot open registry file",
            diagnostics,
            re.IGNORECASE,
        ):
            raise ValueError(f"{source.name}: unresolved build diagnostics in {log.name}")
    audit_reference_markers(reader, source)


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


def audit(paths, root=OUTPUT):
    cache = {}
    page_total = 0
    local_link_total = 0
    external_link_total = 0
    for path in paths:
        reader = PdfReader(path)
        audit_reference_markers(reader, path)
        local_total = audit_local_targets(reader, path)
        total = 0
        for action in remote_actions(reader):
            target = (path.parent / file_name(action)).resolve()
            if not target.is_relative_to(root.resolve()):
                raise ValueError(f"{path.name}: link outside output: {target}")
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
    parser.add_argument("--organize-existing", action="store_true",
                        help="Sort current output PDFs and repair their links without rebuilding; keep originals in tmp.")
    parser.add_argument("--skip-main", action="store_true")
    parser.add_argument("--csb-pilot", action="store_true",
                        help="Also publish both Cantor-Bernstein pilot editions; require both build artifacts.")
    parser.add_argument("--bands", nargs="+", metavar="Bnn",
                        help="Publish only these standalone volumes; still audit all current PDF links.")
    args = parser.parse_args()
    with (ROOT / "band-dependencies.tsv").open(encoding="utf-8-sig", newline="") as file:
        graph = list(csv.DictReader(file, delimiter="\t"))
    names = {f"_{row['band']}.pdf": Path(row["source"]).with_suffix(".pdf").name for row in graph}
    names.update(CSB_PILOT_NAMES)
    if args.organize_existing:
        if args.audit_only or args.skip_main or args.csb_pilot or args.bands:
            parser.error("--organize-existing cannot be combined with other options")
        organize_existing(names)
        return
    flat = [path for path in OUTPUT.glob("*.pdf") if path.name in set(names.values()) | {MAIN_NAME}]
    if flat:
        parser.error("Flat output PDFs remain; run --organize-existing first")
    if args.bands:
        unknown = set(args.bands) - {row["band"] for row in graph}
        if unknown:
            parser.error("Unknown volumes: " + ", ".join(sorted(unknown)))
    all_publications = [(ROOT / (row["artifact_base"] + ".pdf"), publication_path(names[f"_{row['band']}.pdf"])) for row in graph]
    publications = [publication for row, publication in zip(graph, all_publications)
                    if not args.bands or row["band"] in args.bands]
    if not args.skip_main:
        publications.append((ROOT / "main.pdf", publication_path(MAIN_NAME)))
        all_publications.append((ROOT / "main.pdf", publication_path(MAIN_NAME)))

    pilot_publications = [(ROOT / "registry" / "csb" / source, publication_path(destination))
                          for source, destination in CSB_PILOT_NAMES.items()]
    # A complete publishing run includes the pilot pair once either artifact
    # exists. The ordinary missing-artifact preflight then rejects a partial
    # pair before replacing any PDF. An audit-only run needs no build artifacts.
    publish_pilot = args.csb_pilot or (
        not args.bands and not args.audit_only
        and any(source.is_file() for source, _ in pilot_publications)
    )
    if publish_pilot:
        publications.extend(pilot_publications)
    # Restricted band runs and audits still check any already published pilots.
    all_publications.extend(publication for publication in pilot_publications
                            if publish_pilot or publication[1].is_file())

    if not args.audit_only:
        missing = [str(source.relative_to(ROOT)) for source, _ in publications if not source.is_file()]
        if missing:
            raise FileNotFoundError("Missing build artifacts: " + ", ".join(missing))
        OUTPUT.mkdir(parents=True, exist_ok=True)
        # Preflight every selected source before changing any publication.
        readers = {}
        for source, _ in publications:
            reader = PdfReader(source)
            assert_build_ready(source, reader)
            readers[source] = reader
        for source, destination in publications:
            reader = readers[source]
            writer = PdfWriter(clone_from=reader)
            rewrite_remote_links(writer, source, destination, names)
            destination.parent.mkdir(parents=True, exist_ok=True)
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
                with tempfile.NamedTemporaryFile(prefix=destination.name + ".", suffix=".backup", dir=destination.parent, delete=False) as file:
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
    audit([destination for _, destination in all_publications])


if __name__ == "__main__":
    main()
