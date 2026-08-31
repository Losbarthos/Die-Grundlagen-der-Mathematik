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

## Standalone volumes / Einzelbände

The root-level `latexmkrc` reads the dependency graph from
[`band-dependencies.tsv`](band-dependencies.tsv). For example, with
`Bd. 37 - Frankls Vermutung.tex` selected as the main file, run:

```powershell
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "Bd. 37 - Frankls Vermutung.tex"
```

The configuration builds the required predecessors topologically into
`registry/` using stable job names such as `_B04`. Because the Lua registry
files do not appear in the usual `.fls` dependency list, every predecessor is
given at least one LuaLaTeX run even when artifacts already exist.

The explicit source-to-registry mapping is intentional. Visible filenames
follow the document titles, while internal identifiers remain `B01` through
`B38`.

### Audited PowerShell build

For a clean standalone build with the full reference audit, use:

```powershell
pwsh -NoProfile -File ./scripts/build-b03.ps1 -Target B37
```

Valid targets are `B01` through `B38`; omitting `-Target` keeps `B03` as the
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

Most volumes follow the main chain. Volume B38 deliberately opens an analytic
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
changes. For a new public snapshot, rebuild the relevant volume before copying
its PDF to `output/pdf/`.

## Generated files

Ignored local artifacts include root-level PDFs, ordinary LaTeX auxiliaries,
the generated `registry/` contents, cache staging directories, audit logs, and
the local `tmp/` workspace. Reader-facing snapshots in `output/pdf/` are an
explicit exception and remain under version control.

[Back to the README / Zurück zur README](README.md)
