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
`output/` are intentionally versioned for readers.

## Rebuild every PDF / Alle PDFs neu bauen

For the opening overview (B00), all 48 subject volumes, and the complete manuscript, run:

```powershell
pwsh -NoProfile -File ./scripts/build-all.ps1
```

This builds the volumes in dependency order, audits their result registries,
and publishes the PDFs in the numbered thematic subfolders of `output/`.
Python with `pypdf` is required
for publication; pass `-Python /path/to/python` to select its interpreter.
The publication step updates external PDF links to relative paths between
the published files and verifies that every linked result destination exists.
Each current PDF is stored once, with its existing filename and volume
number. Main volumes sit directly in their thematic folder; companion editions
sit below `Ergänzungen/<topic>/`. `scripts/publish-pdfs.py` centrally defines
these publication paths. See [VOLUMES.md](VOLUMES.md) for the folder mapping.
Build logs and temporary files belong in `tmp/`, outside the publication
directory.

To organize existing published PDFs into this structure without a new build,
run once:

```powershell
python ./scripts/publish-pdfs.py --organize-existing
```

The command stages and audits the relative PDF links before moving the files.
It retains the original PDFs under `tmp/pdf-organization-*/originals` for recovery.
Normal publication
uses the thematic structure automatically. Both Cantor–Bernstein companion
editions are published under
`output/03 Relationen und Funktionen/Ergänzungen/Cantor-Bernstein/`;
B08 remains directly in `03 Relationen und Funktionen`.

Der Gesamtlauf baut den Überblicksband B00, alle 48 Fachbände und den Gesamtband.
B00 steht im Buch zuerst, wird wegen seiner Verweise aber nach B01 bis B48
gebaut. Kein Fachband importiert B00; die vorhandene Nummerierung bleibt erhalten.
Jeder Band wird nach seinem Build geprüft. Der Gesamtband verwendet eigene
Registries unter `registry/main/`; dadurch überschreibt er keine
Einzelbandindizes. Die Resultatnummern müssen in beiden Ausgaben übereinstimmen.

A stopped standalone build can resume at the first unfinished volume, for
example with `-From B21`. If an earlier source changes, resume at that earlier
volume so all subsequent references are rebuilt. To build only a range before
the full publication step, use:

```powershell
pwsh -NoProfile -File ./scripts/build-all.ps1 -From B03 -To B20 -SkipMain -SkipPublish
```

A resumed build that publishes PDFs also rebuilds B00 after the selected
subject volumes, so its printed result references stay current. Explicit
`-SkipPublish` range builds do not add B00 automatically.

To publish only selected revised volumes together with the complete manuscript,
while checking links in every current PDF, use for example:

```powershell
python ./scripts/publish-pdfs.py --bands B00 B27
```

Existing build products can also be audited without recompiling:

```powershell
pwsh -NoProfile -File ./scripts/audit-build.ps1 -IncludeMain
python ./scripts/publish-pdfs.py --audit-only
```

## Standalone volumes / Einzelbände

The root-level `latexmkrc` reads the dependency graph from
[`band-dependencies.tsv`](band-dependencies.tsv). For example, with
`Bd. 46 - Frankls Vermutung.tex` selected as the main file, run:

```powershell
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "Bd. 46 - Frankls Vermutung.tex"
```

The configuration builds the required predecessors topologically into
`registry/` using stable job names such as `_B04`. Because the Lua registry
files do not appear in the usual `.fls` dependency list, every predecessor is
given at least one LuaLaTeX run even when artifacts already exist.

The explicit source-to-registry mapping is intentional. Visible filenames
follow the document titles. Internal identifiers are `B00` for the overview
and `B01` through `B48` for the subject volumes.

### Audited PowerShell build

For a clean standalone build with the full reference audit, use:

```powershell
pwsh -NoProfile -File ./scripts/build-b03.ps1 -Target B46
```

Valid targets are `B01` through `B48`; omitting `-Target` keeps `B03` as the
default. On Windows PowerShell 5.1, replace `pwsh` with `powershell` and add
`-ExecutionPolicy Bypass` if required.

For the selected dependency graph, the script removes known generated build
artifacts, rebuilds the predecessors under fixed job names, builds the target,
and then audits the result. Source files and the curated files under
`output/` are not build-cleanup targets.

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

Most volumes follow the main chain. Volume B47 deliberately opens an analytic
branch and depends only on B01 through B21. Later specialist volumes may use
examples of structures introduced earlier, while general constructions remain
in the earliest volume that can define them without a dependency cycle.

## Cantor–Bernstein pilot / Lesefassung und Beweistabellen

The CSB section has a shared source package under
`tex/b08/cantor-bernstein/`. The regular B08 volume, the complete manuscript,
and the proof wrapper in `editions/` use the same main statements, contexts,
and IDs. B08 and the complete manuscript retain all nine main declarations
and the three registered auxiliary statements as compact notes with links
to the proofs in the companion editions. Their statement numbers and
destinations remain unchanged.

The reading edition contains the complete prose proof, the later application
in B11, and historical sources with a comparison of the proof constructions.
It starts directly with the mathematical content, without a separate usage
chapter. It imports B08 references but declares no local numbered statements;
the formal statement appendix and detailed reference list are omitted.
The proof edition
contains all proof tables, including the three auxiliary statements with H
numbers. The CSB prose proof and proof tables appear only in these companion
editions.

With the predecessor volumes already built, run:

```powershell
pwsh -NoProfile -File ./scripts/build-csb-pilot.ps1 -Python /path/to/python
```

This rebuilds B08, B11, both companion editions, B00 and the complete manuscript;
audits the results; and publishes six PDFs. `-SkipMain` omits the combined
manuscript, and `-SkipPublish` leaves the PDFs as build products.
`-EditionsOnly` builds and audits only the two companions from existing B08/B11
artifacts. This is also used by `build-all.ps1` in dependency order.
For a clean repository, run `build-all.ps1` first; the targeted script deliberately
requires the other predecessor registries and PDFs instead of rebuilding them.
For a partial build ending at B08, existing B11 artifacts are also required for
the reading edition's later application. Ranges without B00/B08/B11 and with
`-SkipMain -SkipPublish` do not build or require the companions.

The independent build products and generated filtered imports live under
`registry/csb/`. They never replace the canonical B08 registry.
`scripts/csb-pilot.py` derives the excerpt's section position from the current
B08 AUX and verifies the proof edition's full registry records and printed
numbers against B08. It also verifies that the reading edition has no local
statement declarations or removed editorial sections. The PDF audit checks
all result destinations, the reading entry point, and external links.

To publish already audited build products:

```powershell
python ./scripts/publish-pdfs.py --bands B00 B08 B11 --csb-pilot
```

The two companion filenames are mapped explicitly during publication. Existing
companion PDFs participate in every publication link audit. Full publication
includes the companion pair when its build products are present. The band
dependency graph continues to describe the mathematical volumes, not the
mutual navigation links between alternate editions.

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
the local `tmp/` workspace. Reader-facing snapshots in `output/` are an
explicit exception and remain under version control.

[Back to the README / Zurück zur README](README.md)
