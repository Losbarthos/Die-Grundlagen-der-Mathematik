"""Publish PDFs in subject folders with working relative links between volumes.

Remote PDF paths are adjusted, and local reading-legend links use explicit
whole-page destinations for reader compatibility. Pages, named destinations
and metadata are cloned from LuaLaTeX. --audit-only checks the published set
without compiling.
--organize-existing sorts the current publications without rebuilding them.
"""
from __future__ import annotations

import argparse
import csv
from functools import lru_cache
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, TextStringObject

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
MOGILJANSKAJA_NAMES = {
    "_B28-mog-reading.pdf": "Bd. 28 - Mogiljanskaja-Gegenbeispiel - Lesefassung.pdf",
    "_B28-mog-proofs.pdf": "Bd. 28 - Mogiljanskaja-Gegenbeispiel - Beweistabellen.pdf",
}
DEDEKIND_NAMES = {
    "_B10-dedekind-reading.pdf": "Bd. 10 - Dedekindscher Rekursionssatz - Lesefassung.pdf",
    "_B10-dedekind-proofs.pdf": "Bd. 10 - Dedekindscher Rekursionssatz - Beweistabellen.pdf",
}
BRACKETING_NAMES = {
    "_B28-bracketing-reading.pdf": "Bd. 28 - Klammerungsunabhängigkeit - Lesefassung.pdf",
    "_B28-bracketing-proofs.pdf": "Bd. 28 - Klammerungsunabhängigkeit - Beweistabellen.pdf",
}
POWER_NAMES = {
    "_B28-power-reading.pdf": "Bd. 28 - Halbgruppenbeweis der Potenzhalbgruppe - Lesefassung.pdf",
    "_B28-power-proofs.pdf": "Bd. 28 - Halbgruppenbeweis der Potenzhalbgruppe - Beweistabellen.pdf",
}
COORDINATES_NAMES = {
    "_B28-e-coordinates.pdf": "Bd. 28 - e-Koordinatenabbildung - Definitionen und Beweise.pdf",
}
PUBLICATION_ALIASES = {
    "Bd. 28 - Potenzhalbgruppe - Lesefassung.pdf": POWER_NAMES["_B28-power-reading.pdf"],
    "Bd. 28 - Potenzhalbgruppe - Beweistabellen.pdf": POWER_NAMES["_B28-power-proofs.pdf"],
}
DIFFERENCES_NAMES = {
    "_B41-differences-reading.pdf": "Bd. 41 - Formale Differenzen - Lesefassung.pdf",
    "_B41-differences-proofs.pdf": "Bd. 41 - Formale Differenzen - Beweistabellen.pdf",
}
INTEGERS_NAMES = {
    "_B17-integers-reading.pdf": "Bd. 17 - Ganze Zahlen - Lesefassung.pdf",
    "_B17-integers-proofs.pdf": "Bd. 17 - Ganze Zahlen - Beweistabellen.pdf",
}
SEMILATTICE_NAMES = {
    "_B45-semilattice-reading.pdf": "Bd. 45 - Halbverbände und Ordnung - Lesefassung.pdf",
    "_B45-semilattice-proofs.pdf": "Bd. 45 - Halbverbände und Ordnung - Beweistabellen.pdf",
}
FRANKL_NAMES = {
    "_B46-frankl-reading.pdf": "Bd. 46 - Frankls Spezialfälle - Lesefassung.pdf",
    "_B46-frankl-proofs.pdf": "Bd. 46 - Frankls Spezialfälle - Beweistabellen.pdf",
}
RECONSTRUCTION_NAMES = {
    "_B40-reconstruction-reading.pdf": "Bd. 40 - Gruppenrekonstruktion - Lesefassung.pdf",
    "_B40-reconstruction-proofs.pdf": "Bd. 40 - Gruppenrekonstruktion - Beweistabellen.pdf",
}
NULLPRODUCTS_NAMES = {
    "_B37-nullproducts-reading.pdf": "Bd. 37 - Nullprodukt-Rekonstruktion - Lesefassung.pdf",
    "_B37-nullproducts-proofs.pdf": "Bd. 37 - Nullprodukt-Rekonstruktion - Beweistabellen.pdf",
}
ZERO_TRANSPORT_NAMES = {
    "_B28-zero-transport-reading.pdf": "Bd. 28 - Nullelement-Transport - Lesefassung.pdf",
    "_B28-zero-transport-proofs.pdf": "Bd. 28 - Nullelement-Transport - Beweistabellen.pdf",
}
COMPACTNESS_NAMES = {
    "_B47-compactness-reading.pdf": "Bd. 47 - Totale Beschränktheit und Kompaktheit - Lesefassung.pdf",
    "_B47-compactness-proofs.pdf": "Bd. 47 - Totale Beschränktheit und Kompaktheit - Beweise.pdf",
}
FINITE_SEMIGROUPS_NAMES = {
    "_B37-finite-reading.pdf": "Bd. 37 - Endliche Halbgruppen erkennen - Lesefassung.pdf",
}
THREE_PRODUCTS_NAMES = {
    "_B37-three-products-reading.pdf": "Bd. 37 - Dreiprodukt-Rekonstruktion - Lesefassung.pdf",
}
TWO_PRODUCTS_NAMES = {
    "_B37-two-products-reading.pdf": "Bd. 37 - Zweiprodukt-Rekonstruktion - Lesefassung.pdf",
}
CONTEXT_PROFILES_NAMES = {
    "_B37-context-profiles-reading.pdf": "Bd. 37 - Kontextprofile und Induktion - Lesefassung.pdf",
}
INDEPENDENT_READINGS = {
    "three-products": THREE_PRODUCTS_NAMES,
    "two-products": TWO_PRODUCTS_NAMES,
    "context-profiles": CONTEXT_PROFILES_NAMES,
}
INDEPENDENT_READING_NAMES = {**THREE_PRODUCTS_NAMES, **TWO_PRODUCTS_NAMES, **CONTEXT_PROFILES_NAMES}
MANUAL_READING_NAMES = {
    "context-equivalence-reading.pdf": "Bd. 28 - Kontextäquivalenz - Experimentelle Lesefassung.pdf",
}
EXPERIMENTAL_NAMES = set(COMPACTNESS_NAMES.values()) | set(INDEPENDENT_READING_NAMES.values()) | set(MANUAL_READING_NAMES.values())
SUPPLEMENT_NAMES = {**CSB_PILOT_NAMES, **MOGILJANSKAJA_NAMES, **DEDEKIND_NAMES, **BRACKETING_NAMES, **POWER_NAMES, **COORDINATES_NAMES, **DIFFERENCES_NAMES, **INTEGERS_NAMES, **SEMILATTICE_NAMES, **FRANKL_NAMES, **RECONSTRUCTION_NAMES, **NULLPRODUCTS_NAMES, **ZERO_TRANSPORT_NAMES, **FINITE_SEMIGROUPS_NAMES, **COMPACTNESS_NAMES, **INDEPENDENT_READING_NAMES, **MANUAL_READING_NAMES}
SUPPLEMENT_TOPICS = {
    **{name: "Cantor-Bernstein" for name in CSB_PILOT_NAMES.values()},
    **{name: "Mogiljanskaja-Gegenbeispiel" for name in MOGILJANSKAJA_NAMES.values()},
    **{name: "Dedekindscher Rekursionssatz" for name in DEDEKIND_NAMES.values()},
    **{name: "Klammerungsunabhängigkeit" for name in BRACKETING_NAMES.values()},
    **{name: "Halbgruppenbeweis der Potenzhalbgruppe" for name in POWER_NAMES.values()},
    **{name: "e-Koordinatenabbildung" for name in COORDINATES_NAMES.values()},
    **{name: "Formale Differenzen" for name in DIFFERENCES_NAMES.values()},
    **{name: "Ganze Zahlen" for name in INTEGERS_NAMES.values()},
    **{name: "Halbverbände und Ordnung" for name in SEMILATTICE_NAMES.values()},
    **{name: "Frankls Spezialfälle" for name in FRANKL_NAMES.values()},
    **{name: "Gruppenrekonstruktion" for name in RECONSTRUCTION_NAMES.values()},
    **{name: "Nullprodukt-Rekonstruktion" for name in NULLPRODUCTS_NAMES.values()},
    **{name: "Nullelement-Transport" for name in ZERO_TRANSPORT_NAMES.values()},
    **{name: "Endliche Halbgruppen" for name in FINITE_SEMIGROUPS_NAMES.values()},
    **{name: "Dreiprodukt-Rekonstruktion" for name in THREE_PRODUCTS_NAMES.values()},
    **{name: "Zweiprodukt-Rekonstruktion" for name in TWO_PRODUCTS_NAMES.values()},
    **{name: "Kontextprofile und Induktion" for name in CONTEXT_PROFILES_NAMES.values()},
    **{name: "Kontextäquivalenz" for name in MANUAL_READING_NAMES.values()},
    **{name: "Totale Beschränktheit und Kompaktheit" for name in COMPACTNESS_NAMES.values()},
}


@lru_cache(maxsize=None)
def publication_band_folders(root):
    """Use the canonical volume titles for companion directories."""
    with (root / "band-dependencies.tsv").open(encoding="utf-8-sig", newline="") as file:
        rows = csv.DictReader(file, delimiter="\t")
        folders = {}
        for row in rows:
            band = int(row["band"][1:])
            title = Path(row["source"]).stem
            prefix = f"Bd. {band:02d} - "
            if not title.startswith(prefix):
                raise ValueError(f"Volume source has no canonical title: {row['source']!r}")
            folders[band] = f"Bd. {band:02d} {title[len(prefix):]}"
    return folders


def publication_path(name):
    """Keep visible filenames stable; use the same layout for every publisher."""
    name = PUBLICATION_ALIASES.get(name, name)
    match = re.fullmatch(r"Bd\. (\d{2}) - .+\.pdf", name)
    band = 0 if name == MAIN_NAME else int(match[1]) if match else None
    groups = [group for group, bands in PUBLICATION_GROUPS.items() if band in bands]
    if len(groups) != 1:
        raise ValueError(f"No unique publication folder for {name!r}")
    directory = OUTPUT / groups[0]
    if name in SUPPLEMENT_TOPICS:
        directory = directory / "Ergänzungen" / publication_band_folders(ROOT)[band]
        if name in EXPERIMENTAL_NAMES:
            directory = directory / "experimentell"
        directory = directory / SUPPLEMENT_TOPICS[name]
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


def rewrite_reading_legend_links(writer):
    """Use explicit Fit destinations for slreading links in this cloned PDF.

    The destination names remain available for other references. Resolve the
    cloned destination against the writer's actual page tree: source-reader
    object numbers need not survive cloning. Other local/remote links retain
    their original destination and zoom behavior.
    """
    destinations = writer.named_destinations
    pages = {(page.indirect_reference.idnum, page.indirect_reference.generation):
             page.indirect_reference for page in writer.pages}
    replacements = []
    for page in writer.pages:
        for reference in page.get("/Annots", []):
            annotation = reference.get_object()
            action = annotation.get("/A")
            if action is not None:
                action = action.get_object()
                if action.get("/S") != "/GoTo":
                    continue
                container, key = action, NameObject("/D")
            else:
                container, key = annotation, NameObject("/Dest")
            destination = container.get(key)
            if not isinstance(destination, str) or not destination.startswith("slreading:"):
                continue
            if destination not in destinations:
                raise ValueError(f"Missing reading introduction destination {destination!r}")
            target = destinations[destination].page
            if not isinstance(target, IndirectObject) or target.pdf is not writer:
                raise ValueError(f"Reading introduction has no document page: {destination!r}")
            page_reference = pages.get((target.idnum, target.generation))
            if page_reference is None:
                raise ValueError(f"Reading introduction is not in the page tree: {destination!r}")
            replacements.append((container, key, ArrayObject([
                page_reference, NameObject("/Fit"),
            ])))
    # Validate every target before changing any action in the cloned writer.
    for container, key, destination in replacements:
        container[key] = destination
    return len(replacements)


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


def remove_empty_publication_folders(sources):
    """Remove only empty former parents, never content or the output root."""
    output = OUTPUT.resolve()
    for source in sources:
        if source == publication_path(source.name):
            continue
        directory = source.parent.resolve()
        while directory != output:
            if not directory.is_relative_to(output):
                raise ValueError(f"Former publication directory outside output: {directory}")
            try:
                directory.rmdir()
            except OSError:
                # A nonempty, locked or already removed directory is retained.
                break
            directory = directory.parent


def organize_existing(names):
    """Stage and audit all current files, keeping originals only during recovery."""
    known = set(names.values()) | {MAIN_NAME} | set(PUBLICATION_ALIASES)
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
    if not stage.resolve().is_relative_to(workspace.resolve()):
        raise ValueError(f"Staging directory outside workspace: {stage}")
    backup_root = stage / "originals"
    staged_root = stage / "organized"
    print(f"Staging {len(sources)} PDFs with temporary recovery copies.", flush=True)
    aliases = {**names, **{name: name for name in known}, **PUBLICATION_ALIASES}
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
            rewrite_reading_legend_links(writer)
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
    audit([publication_path(source.name) for source in sources])
    remove_empty_publication_folders(changed_sources)
    # Recovery copies are temporary; successful organization creates no archive.
    if not stage.resolve().is_relative_to(workspace.resolve()):
        raise ValueError(f"Staging directory outside workspace: {stage}")
    shutil.rmtree(stage)
    print(f"Organized {len(sources)} PDFs in {len(PUBLICATION_GROUPS)} subject folders; "
          f"updated {len(changed_sources)} files.", flush=True)
    print("Temporary recovery copies removed.", flush=True)


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
        # Pass an open stream so Poppler does not need to open deep Windows
        # staging paths beyond its legacy path-length limit.
        with path.open("rb") as pdf:
            result = subprocess.run(
                [pdftotext, "-raw", "-enc", "UTF-8", "-", "-"],
                stdin=pdf, stdout=subprocess.PIPE, encoding="utf-8", check=True,
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
    if re.fullmatch(r"_B\d{2}", source.stem) or source.name in SUPPLEMENT_NAMES:
        debug = source.with_suffix(".debug.log")
        log = source.with_suffix(".log")
        required_logs = (log,) if source.name in INDEPENDENT_READING_NAMES else (debug, log)
        for required in required_logs:
            if not required.is_file():
                raise FileNotFoundError(f"Missing build diagnostic: {required}")
        failed = re.search(
            r"^status:\s*(?:none|ambiguous[^\r\n]*|duplicate-register)\s*$",
            debug.read_text(encoding="utf-8", errors="replace") if debug in required_logs else "",
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
    page_references = {(page.indirect_reference.idnum, page.indirect_reference.generation)
                       for page in reader.pages}
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
            elif isinstance(destination, ArrayObject):
                if len(destination) < 2 or not isinstance(destination[0], IndirectObject):
                    raise ValueError(f"{path.name}: malformed explicit local destination {destination!r}")
                reference = destination[0]
                if (reference.idnum, reference.generation) not in page_references:
                    raise ValueError(f"{path.name}: explicit local destination is not a document page")
                if destination[1] not in {"/XYZ", "/Fit", "/FitH", "/FitV", "/FitR", "/FitB", "/FitBH", "/FitBV"}:
                    raise ValueError(f"{path.name}: invalid explicit local view {destination[1]!r}")
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
                        help="Sort current output PDFs and repair their links without rebuilding; remove recovery copies after success.")
    parser.add_argument("--skip-main", action="store_true")
    parser.add_argument("--csb-pilot", action="store_true",
                        help="Also publish both Cantor-Bernstein pilot editions; require both build artifacts.")
    parser.add_argument("--mogiljanskaja", action="store_true",
                        help="Also publish both Mogiljanskaja companion editions; require both build artifacts.")
    parser.add_argument("--dedekind", action="store_true",
                        help="Also publish both Dedekind recursion companion editions; require both build artifacts.")
    parser.add_argument("--bracketing-editions", action="store_true",
                        help="Also publish both bracketing-independence editions; require both build artifacts.")
    parser.add_argument("--power", action="store_true",
                        help="Also publish both power-semigroup editions; require both build artifacts.")
    parser.add_argument("--e-coordinates", action="store_true",
                        help="Also publish the e-coordinate definitions and proofs; require its build artifact.")
    parser.add_argument("--differences", action="store_true",
                        help="Also publish both formal-difference companion editions; require both build artifacts.")
    parser.add_argument("--integers", action="store_true",
                        help="Also publish both integer-construction companion editions; require both build artifacts.")
    parser.add_argument("--semilattice", action="store_true",
                        help="Also publish both semilattice/order companion editions; require both build artifacts.")
    parser.add_argument("--frankl", action="store_true",
                        help="Also publish both Frankl special-case companion editions; require both build artifacts.")
    parser.add_argument("--reconstruction", action="store_true",
                        help="Also publish both group-reconstruction companion editions; require both build artifacts.")
    parser.add_argument("--nullproducts", action="store_true",
                        help="Also publish both null-product reconstruction editions; require both build artifacts.")
    parser.add_argument("--finite-semigroups", action="store_true",
                        help="Also publish the finite-semigroups reading edition; require its build artifact.")
    parser.add_argument("--zero-transport", action="store_true",
                        help="Also publish both general zero-transport editions; require both build artifacts.")
    parser.add_argument("--compactness", action="store_true",
                        help="Also publish both compactness editions; require both build artifacts.")
    edition_only = parser.add_mutually_exclusive_group()
    for directory in INDEPENDENT_READINGS:
        edition_only.add_argument(f"--{directory}-only", action="store_true",
                                  help=f"Publish only the independent {directory} reading; audit all current PDFs.")
    edition_only.add_argument("--e-coordinates-only", action="store_true",
                              help="Publish only the e-coordinate definitions and proofs; audit all current PDFs.")
    parser.add_argument("--bands", nargs="+", metavar="Bnn",
                        help="Publish only these standalone volumes; still audit all current PDF links.")
    args = parser.parse_args()
    with (ROOT / "band-dependencies.tsv").open(encoding="utf-8-sig", newline="") as file:
        graph = list(csv.DictReader(file, delimiter="\t"))
    names = {f"_{row['band']}.pdf": Path(row["source"]).with_suffix(".pdf").name for row in graph}
    names.update(SUPPLEMENT_NAMES)
    names.update(PUBLICATION_ALIASES)
    only_edition = args.e_coordinates_only or any(
        getattr(args, directory.replace("-", "_") + "_only") for directory in INDEPENDENT_READINGS)
    if args.organize_existing:
        if args.audit_only or args.skip_main or args.csb_pilot or args.mogiljanskaja or args.dedekind or args.bracketing_editions or args.power or args.e_coordinates or args.differences or args.integers or args.semilattice or args.frankl or args.reconstruction or args.nullproducts or args.zero_transport or args.finite_semigroups or args.compactness or args.bands or only_edition:
            parser.error("--organize-existing cannot be combined with other options")
        organize_existing(names)
        return
    if only_edition and (
        args.skip_main or args.bands or args.csb_pilot or args.mogiljanskaja
        or args.dedekind or args.bracketing_editions or args.power or args.e_coordinates or args.differences
        or args.integers or args.semilattice or args.frankl
        or args.reconstruction or args.nullproducts or args.zero_transport or args.finite_semigroups or args.compactness
    ):
        parser.error("Single-edition publication cannot be combined with other publication selections")
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
    if only_edition:
        publications = []
    if not args.skip_main:
        if not only_edition:
            publications.append((ROOT / "main.pdf", publication_path(MAIN_NAME)))
        all_publications.append((ROOT / "main.pdf", publication_path(MAIN_NAME)))
    full_publish = not args.bands and not args.audit_only and not only_edition

    pilot_publications = [(ROOT / "registry" / "csb" / source, publication_path(destination))
                          for source, destination in CSB_PILOT_NAMES.items()]
    # A complete publishing run includes the pilot pair once either artifact
    # exists. The ordinary missing-artifact preflight then rejects a partial
    # pair before replacing any PDF. An audit-only run needs no build artifacts.
    publish_pilot = args.csb_pilot or (
        full_publish
        and any(source.is_file() for source, _ in pilot_publications)
    )
    if publish_pilot:
        publications.extend(pilot_publications)
    # Restricted band runs and audits still check any already published pilots.
    all_publications.extend(publication for publication in pilot_publications
                            if publish_pilot or publication[1].is_file())

    mogiljanskaja_publications = [
        (ROOT / "registry" / "mogiljanskaja" / source, publication_path(destination))
        for source, destination in MOGILJANSKAJA_NAMES.items()
    ]
    publish_mogiljanskaja = args.mogiljanskaja or (
        full_publish
        and any(source.is_file() for source, _ in mogiljanskaja_publications)
    )
    if publish_mogiljanskaja:
        publications.extend(mogiljanskaja_publications)
    all_publications.extend(publication for publication in mogiljanskaja_publications
                            if publish_mogiljanskaja or publication[1].is_file())

    dedekind_publications = [
        (ROOT / "registry" / "dedekind" / source, publication_path(destination))
        for source, destination in DEDEKIND_NAMES.items()
    ]
    publish_dedekind = args.dedekind or (
        full_publish
        and any(source.is_file() for source, _ in dedekind_publications)
    )
    if publish_dedekind:
        publications.extend(dedekind_publications)
    all_publications.extend(publication for publication in dedekind_publications
                            if publish_dedekind or publication[1].is_file())

    bracketing_publications = [
        (ROOT / "registry" / "bracketing" / source, publication_path(destination))
        for source, destination in BRACKETING_NAMES.items()
    ]
    publish_bracketing = args.bracketing_editions or (
        full_publish
        and any(source.is_file() for source, _ in bracketing_publications)
    )
    if publish_bracketing:
        publications.extend(bracketing_publications)
    all_publications.extend(publication for publication in bracketing_publications
                            if publish_bracketing or publication[1].is_file())

    power_publications = [
        (ROOT / "registry" / "power" / source, publication_path(destination))
        for source, destination in POWER_NAMES.items()
    ]
    publish_power = args.power or (
        full_publish
        and any(source.is_file() for source, _ in power_publications)
    )
    if publish_power:
        publications.extend(power_publications)
    all_publications.extend(publication for publication in power_publications
                            if publish_power or publication[1].is_file())

    coordinates_publications = [
        (ROOT / "registry" / "e-coordinates" / source, publication_path(destination))
        for source, destination in COORDINATES_NAMES.items()
    ]
    publish_coordinates = args.e_coordinates or args.e_coordinates_only or (
        full_publish and any(source.is_file() for source, _ in coordinates_publications)
    )
    if publish_coordinates:
        publications.extend(coordinates_publications)
    all_publications.extend(publication for publication in coordinates_publications
                            if publish_coordinates or publication[1].is_file())

    differences_publications = [
        (ROOT / "registry" / "differences" / source, publication_path(destination))
        for source, destination in DIFFERENCES_NAMES.items()
    ]
    publish_differences = args.differences or (
        full_publish
        and any(source.is_file() for source, _ in differences_publications)
    )
    if publish_differences:
        publications.extend(differences_publications)
    all_publications.extend(publication for publication in differences_publications
                            if publish_differences or publication[1].is_file())

    integers_publications = [
        (ROOT / "registry" / "integers" / source, publication_path(destination))
        for source, destination in INTEGERS_NAMES.items()
    ]
    publish_integers = args.integers or (
        full_publish
        and any(source.is_file() for source, _ in integers_publications)
    )
    if publish_integers:
        publications.extend(integers_publications)
    all_publications.extend(publication for publication in integers_publications
                            if publish_integers or publication[1].is_file())

    semilattice_publications = [
        (ROOT / "registry" / "semilattice" / source, publication_path(destination))
        for source, destination in SEMILATTICE_NAMES.items()
    ]
    publish_semilattice = args.semilattice or (
        full_publish
        and any(source.is_file() for source, _ in semilattice_publications)
    )
    if publish_semilattice:
        publications.extend(semilattice_publications)
    all_publications.extend(publication for publication in semilattice_publications
                            if publish_semilattice or publication[1].is_file())

    frankl_publications = [
        (ROOT / "registry" / "frankl" / source, publication_path(destination))
        for source, destination in FRANKL_NAMES.items()
    ]
    publish_frankl = args.frankl or (
        full_publish
        and any(source.is_file() for source, _ in frankl_publications)
    )
    if publish_frankl:
        publications.extend(frankl_publications)
    all_publications.extend(publication for publication in frankl_publications
                            if publish_frankl or publication[1].is_file())

    reconstruction_publications = [
        (ROOT / "registry" / "reconstruction" / source, publication_path(destination))
        for source, destination in RECONSTRUCTION_NAMES.items()
    ]
    publish_reconstruction = args.reconstruction or (
        full_publish
        and any(source.is_file() for source, _ in reconstruction_publications)
    )
    if publish_reconstruction:
        publications.extend(reconstruction_publications)
    all_publications.extend(publication for publication in reconstruction_publications
                            if publish_reconstruction or publication[1].is_file())

    nullproducts_publications = [
        (ROOT / "registry" / "nullproducts" / source, publication_path(destination))
        for source, destination in NULLPRODUCTS_NAMES.items()
    ]
    publish_nullproducts = args.nullproducts or (
        full_publish
        and any(source.is_file() for source, _ in nullproducts_publications)
    )
    if publish_nullproducts:
        publications.extend(nullproducts_publications)
    all_publications.extend(publication for publication in nullproducts_publications
                            if publish_nullproducts or publication[1].is_file())

    zero_transport_publications = [
        (ROOT / "registry" / "zero-transport" / source, publication_path(destination))
        for source, destination in ZERO_TRANSPORT_NAMES.items()
    ]
    publish_zero_transport = args.zero_transport or (
        full_publish
        and any(source.is_file() for source, _ in zero_transport_publications)
    )
    if publish_zero_transport:
        publications.extend(zero_transport_publications)
    all_publications.extend(publication for publication in zero_transport_publications
                            if publish_zero_transport or publication[1].is_file())

    finite_publications = [
        (ROOT / "registry" / "finite" / source, publication_path(destination))
        for source, destination in FINITE_SEMIGROUPS_NAMES.items()
    ]
    publish_finite = args.finite_semigroups or (
        full_publish
        and any(source.is_file() for source, _ in finite_publications)
    )
    if publish_finite:
        publications.extend(finite_publications)
    all_publications.extend(publication for publication in finite_publications
                            if publish_finite or publication[1].is_file())

    compactness_publications = [
        (ROOT / "registry" / "compactness" / source, publication_path(destination))
        for source, destination in COMPACTNESS_NAMES.items()
    ]
    publish_compactness = args.compactness or (
        full_publish
        and any(source.is_file() for source, _ in compactness_publications)
    )
    if publish_compactness:
        publications.extend(compactness_publications)
    all_publications.extend(publication for publication in compactness_publications
                            if publish_compactness or publication[1].is_file())

    for directory, edition_names in INDEPENDENT_READINGS.items():
        independent_publications = [
            (ROOT / "registry" / directory / source, publication_path(destination))
            for source, destination in edition_names.items()
        ]
        selected = getattr(args, directory.replace("-", "_") + "_only")
        publish_reading = selected or (full_publish and any(source.is_file()
                                                           for source, _ in independent_publications))
        if publish_reading:
            publications.extend(independent_publications)
        all_publications.extend(publication for publication in independent_publications
                                if publish_reading or publication[1].is_file())

    # Self-contained manual readings are curated snapshots, never rebuilt here.
    all_publications.extend(
        (ROOT / "tmp/pdfs/context-equivalence" / source, publication_path(destination))
        for source, destination in MANUAL_READING_NAMES.items()
        if publication_path(destination).is_file()
    )

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
            rewrite_reading_legend_links(writer)
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
