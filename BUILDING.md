# Building the manuscript / Manuskript bauen

This document contains the technical material that used to dominate the main
README. The short version is: all document builds use LuaLaTeX, and the root
`latexmkrc` coordinates cross-volume references.

Dieses Dokument enthält die technischen Hinweise, die zuvor den größten Teil
der README ausmachten. Kurz gesagt: Alle Dokumente werden mit LuaLaTeX gebaut;
die `latexmkrc` im Projektwurzelverzeichnis koordiniert bandübergreifende
Verweise.

## Requirements / Voraussetzungen

- `latexmk` 4.84 or newer
- LuaLaTeX with the packages used by `main.tex`
- PowerShell or PowerShell 7 (`pwsh`) for the audited helper scripts
- `pdftotext` from Poppler for the PDF-text audit

The GitHub workflow lists the TeX Live packages installed in CI:
[`.github/workflows/registry-cache.yml`](.github/workflows/registry-cache.yml).

## Complete manuscript / Gesamtband

From the repository root, run:

```powershell
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error main.tex
```

The generated root-level `main.pdf` and normal LaTeX auxiliary files are local
build products and are ignored by Git. Curated per-volume PDF snapshots under
`output/pdf/` are intentionally versioned for readers.

## Rebuild every PDF / Alle PDFs neu bauen

For all 43 standalone volumes, the reMarkable edition, and the complete
manuscript, run:

```powershell
pwsh -NoProfile -File ./scripts/build-all.ps1
```

This builds the volumes in dependency order, audits their result registries,
and publishes the PDFs under `output/pdf/`. Python with `pypdf` is required
for publication; pass `-Python /path/to/python` to select its interpreter.
The publication step updates external PDF links to the visible neighbouring
filenames and verifies that every linked result destination exists.

Der Gesamtlauf baut alle Einzelbände, die reMarkable-Ausgabe und den Gesamtband.
Jeder Band wird nach seinem Build geprüft. Der Gesamtband verwendet eigene
Registries unter `registry/main/`; dadurch überschreibt er keine
Einzelbandindizes. Die Resultatnummern müssen in beiden Ausgaben übereinstimmen.

A stopped standalone build can resume at the first unfinished volume, for
example with `-From B21`. If an earlier source changes, resume at that earlier
volume so all subsequent references are rebuilt. To build only a range before
the full publication step, use:

```powershell
pwsh -NoProfile -File ./scripts/build-all.ps1 -From B03 -To B20 -SkipMain -SkipRemarkable -SkipPublish
```

Existing build products can also be audited without recompiling:

```powershell
pwsh -NoProfile -File ./scripts/audit-build.ps1 -IncludeMain -IncludeRemarkable
python ./scripts/publish-pdfs.py --audit-only
```

## Standalone volumes / Einzelbände

The root-level `latexmkrc` reads the dependency graph from
[`band-dependencies.tsv`](band-dependencies.tsv). For example, with
`Bd. 42 - Frankls Vermutung.tex` selected as the main file, run:

```powershell
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "Bd. 42 - Frankls Vermutung.tex"
```

The configuration builds the required predecessors topologically into
`registry/` using stable job names such as `_B04`. Because the Lua registry
files do not appear in the usual `.fls` dependency list, every predecessor is
given at least one LuaLaTeX run even when artifacts already exist.

The explicit source-to-registry mapping is intentional. Visible filenames
follow the document titles, while internal identifiers remain `B01` through
`B43`.

### Audited PowerShell build

For a clean standalone build with the full reference audit, use:

```powershell
pwsh -NoProfile -File ./scripts/build-b03.ps1 -Target B42
```

Valid targets are `B01` through `B43`; omitting `-Target` keeps `B03` as the
default. On Windows PowerShell 5.1, replace `pwsh` with `powershell` and add
`-ExecutionPolicy Bypass` if required.

For the selected dependency graph, the script removes known generated build
artifacts, rebuilds the predecessors under fixed job names, builds the target,
and then audits the result. Source files and the curated files under
`output/pdf/` are not build-cleanup targets.

## What the audit checks / Umfang des Audits

The build audit checks technical consistency, including:

- registry labels against the corresponding AUX files;
- undefined or ambiguous references;
- missing AUX or registry imports;
- duplicate destinations and registrations;
- known failure markers in extracted PDF text;
- external PDF actions and named destinations;
- at least one actually used predecessor link for every standalone target.

These checks protect the document and reference graph. They do not prove the
mathematical validity of a derivation and are not a substitute for peer review
or a proof assistant.

## Dependency graph / Abhängigkeitsgraph

[`band-dependencies.tsv`](band-dependencies.tsv) is the single source of truth
for transitive predecessor order and the mapping from visible TeX filenames to
registry job names. It is read by TeX/Lua, `latexmkrc`, and the PowerShell build
script.

Most volumes follow the main chain. Volume B43 deliberately opens an analytic
branch and depends only on B01 through B21. Later specialist volumes may use
examples of structures introduced earlier, while general constructions remain
in the earliest volume that can define them without a dependency cycle.

## Verified B05 registry cache

The optional B05 cache is an optimization for a direct standalone build. It is
not required for the general volume structure.

The workflow
[`registry-cache.yml`](.github/workflows/registry-cache.yml) clean-builds B05,
audits it, and publishes a commit-bound archive. The cache manifest validates:

- the exact source set declared in [`cache-inputs.tsv`](cache-inputs.tsv);
- size and SHA-256 of every source and cache artifact;
- the complete manifest and directory layout;
- the tool versions when `-RequireToolMatch` is used.

Local cache commands are:

```powershell
pwsh -NoProfile -File ./scripts/registry-cache.ps1 -Mode Pack
pwsh -NoProfile -File ./scripts/registry-cache.ps1 -Mode Verify
pwsh -NoProfile -File ./scripts/registry-cache.ps1 -Mode Restore
```

To force a complete B05 predecessor rebuild without using the cache:

```powershell
$env:DGM_LATEXMK_FORCE_DEPS = '1'
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "Bd. 05 - Funktionen.tex"
```

## Overleaf

Upload the complete repository and select the desired volume as Overleaf's main
document. The root-level `latexmkrc` follows the standard external-document
approach but uses the explicit filename-to-job-name mapping from
`band-dependencies.tsv`.

For B05, a verified cache archive may be unpacked at the repository root so
that `registry-cache/manifest.tsv` exists. If validation fails, the build stops
rather than using stale predecessor artifacts.

## PDF metadata

Each active volume sets `pdftitle` and `pdfauthor` in its standalone preamble.
This lets document managers use the PDF title even when the generated filename
changes. For a new public snapshot, rebuild the relevant volumes and use
`scripts/publish-pdfs.py` to publish them with updated external PDF targets.

## Generated files

Ignored local artifacts include root-level PDFs, ordinary LaTeX auxiliaries,
the generated `registry/` contents, cache staging directories, audit logs, and
the local `tmp/` workspace. Reader-facing snapshots in `output/pdf/` are an
explicit exception and remain under version control.

[Back to the README / Zurück zur README](README.md)
