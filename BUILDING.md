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
`tex/b08/cantor-bernstein/`. B08 and the complete manuscript contain the
main theorem and link directly to its proof at `csb.proof` in the proof edition.
The proof edition owns one definition, seven lemmas and three H auxiliary
results in the separate `8E` numbering namespace. It contains all eight
proof tables and refers back to the main theorem in B08 without declaring
it again. The shared declaration source preserves the formulas, contexts
and semantic IDs.

The reading edition contains the complete prose proof, the later application
in B11, and historical sources with a comparison of the proof constructions.
It starts directly with the mathematical content, without a separate usage
chapter. It imports references from B08 and the proof edition but declares
no local numbered statements; the formal statement appendix and detailed
reference list are omitted.
It links the main theorem in the volume to the auxiliary results and proofs
in the proof edition. The CSB prose proof and proof tables appear only in
these companion editions.

With the predecessor volumes already built, run:

```powershell
pwsh -NoProfile -File ./scripts/build-csb-pilot.ps1 -Python /path/to/python
```

This rebuilds B08, B11, B48, both companion editions, B00 and the complete manuscript;
audits the results; and publishes seven PDFs. `-SkipMain` omits the combined
manuscript, and `-SkipPublish` leaves the PDFs as build products.
`-EditionsOnly` builds and audits only the two companions from existing B08/B11
artifacts. This is also used by `build-all.ps1` in dependency order.
For a clean repository, run `build-all.ps1` first; the targeted script deliberately
requires the other predecessor registries and PDFs instead of rebuilding them.
For a partial build ending at B08, existing B11 artifacts are also required for
the reading edition's later application. Ranges without B00/B08/B11/B48 and with
`-SkipMain -SkipPublish` do not build or require the companions.

The independent build products and generated filtered imports live under
`registry/csb/`. They never replace the canonical B08 registry.
`scripts/csb-pilot.py` prepares the edition imports and verifies the separation
of the main theorem in B08 from the eleven auxiliary declarations in the
proof edition, including their semantic IDs and `8E` numbers. It also verifies
that the reading edition has no local statement declarations or removed
editorial sections. The PDF audit checks all result destinations, the reading
entry point, the direct final-proof target `csb.proof`, and external links.

To publish already audited build products:

```powershell
python ./scripts/publish-pdfs.py --bands B00 B08 B11 B48 --csb-pilot
```

The two companion filenames are mapped explicitly during publication. Existing
companion PDFs participate in every publication link audit. Full publication
includes the companion pair when its build products are present. The band
dependency graph continues to describe the mathematical volumes, not the
mutual navigation links between alternate editions.

## Bracketing independence / Klammerungsunabhängigkeit

The source package under `tex/b28/bracketing/` keeps the main theorem
`SemigroupBracketingIndependence` (28.2.3.4) in B28 and the complete
manuscript, alongside the notation remark and links to the companions.
The proof edition declares only the six auxiliary results: the block law,
tree normal form, and their four local induction cases, all with their
original numbers. It contains all seven proof tables; the final proof
references the main B28 theorem without declaring it again. The reference
section reserves six former declaration positions with `\phantomsection`;
the main theorem itself occupies the seventh position. This preserves the
numbering and PDF destinations of the other 340 B28 results, giving 341
results including the main theorem. General word and tree foundations remain
in B27.

With the predecessor volumes already built, run:

```powershell
pwsh -NoProfile -File ./scripts/build-bracketing-editions.ps1 -Python /path/to/python
```

This rebuilds B28, both companion editions, B00 and the complete manuscript,
audits their registries and PDF destinations, and publishes the five PDFs.
`-EditionsOnly` reuses the canonical B28 artifacts and builds only the
companions; `-SkipMain` and `-SkipPublish` have the same meaning as for the
other companion builders. `-SkipVolumeBuild` reuses both B28 and B00 but
still builds and publishes the complete manuscript unless the corresponding
skip switches are supplied. `build-all.ps1` includes the pair in dependency
order. The independent imports and build products live in
`registry/bracketing/`, separate from the Mogiljanskaja supplement.
The reading edition imports the six auxiliary results from `proofs-reading`
and the main theorem, together with its other B28 references, from
`b28-reading`. The proof edition imports the main theorem and its other
B28 dependencies through `b28-external`.

The companion audit checks the seven identities and original numbers with
one theorem owned by B28 and six auxiliary results owned by the proof edition.
It checks the absence of duplicate declarations across the two registers
and the lack of local declarations in the reading edition, as well as the
separate imports and PDF destinations. Both companions link back to the B28
notation remark. The final proof has the dedicated destination
`bracketing.proof.independence`; the old destination
`bracketing.statement.SemigroupBracketingIndependence` remains as an invisible
compatibility anchor, without a local theorem declaration.
To publish previously audited artifacts:

```powershell
python ./scripts/publish-pdfs.py --bands B00 B28 --bracketing-editions
```

The publication folder is
`output/07 Halbgruppen und Monoide/Ergänzungen/Klammerungsunabhängigkeit/`.
Existing companion PDFs participate in every publication link audit.

## Mogiljanskaja counterexample / Lesefassung und Beweistabellen

The counterexample uses a source package under `tex/b28/mogiljanskaja/`.
B28 and the complete manuscript contain only the public existence theorem
`MogiljanskajaPairCounterexample`, a short explanation of its significance,
and links to the companions. This theorem states the existence of infinite
non-isomorphic semigroups with isomorphic power semigroups of nonempty
subsets; it does not presuppose the companion's concrete construction.
B37 and the overview continue to reference this public B28 result.

The reading edition starts with the mathematical question and explains the
construction and its complete proof without local numbered declarations.
The proof edition owns 18 definitions and 42 theorem declarations, plus six
registered theorem-part aliases, under the independent number prefix
`28E`. Chapter 1 contains the example-specific layers, reserve sets and
parametrizations formerly in B21; chapters 2 and 3 contain the semigroup
construction and the detail arguments M1–M17. Its concrete final result has
the ID
`MogiljanskajaConstructedPairCounterexample`; its witnesses establish the
public B28 existence theorem. The other construction IDs are retained in
the companion, including the historical `B21` IDs of moved helper results.
Both companions link back to B28 and to one another. General results from
B08 and B21 remain in their original volumes. B21 retains a short application
note linking to the companions; it no longer prints the specialized construction.

With the other predecessor volumes already built, run:

```powershell
pwsh -NoProfile -File ./scripts/build-mogiljanskaja-editions.ps1 -Python /path/to/python
```

This rebuilds B21, B28, the proof companion, the reading companion, B37, B00
and the complete manuscript; audits their references; and publishes seven
PDFs. `-SkipMain` omits the combined manuscript, and `-SkipPublish` leaves
build products unpublished.
`-EditionsOnly` prepares, builds and audits just the companions from existing
B21, B28 and predecessor artifacts. `build-all.ps1` invokes this mode after
the last selected B21/B28 prerequisite and before auditing those volumes'
links. Partial ranges without B00/B21/B28 and with `-SkipMain -SkipPublish`
do not require these companions. On a clean checkout, use `build-all.ps1` to build
the predecessor volumes first.

Separate jobs `_B28-mog-reading` and `_B28-mog-proofs`, registry imports,
and the generated companion numbering setup live under
`registry/mogiljanskaja/`. The canonical B21 and B28 registries are never
overwritten by an edition build. `scripts/mogiljanskaja-editions.py prepare` imports
the full remaining B21 and B28 registries and generates the independent
`28E` setup. It rejects B21 artifacts that still own the moved declarations.
After the proof build, `prepare-reading` imports its canonical registry and AUX into
the reading edition. The `audit` mode checks the 66 companion identities
(60 declarations and six aliases), their disjoint ownership relative to
B21/B28, their numbering and chapter placement, current import records,
the absence of local declarations in the reading edition, and PDF destinations and
reciprocal navigation. The public theorem links directly to its concrete
proof result and to both edition entry points. Targeted builds use
`latexmk -g` to preserve existing AUX information while rebuilding.

To publish already audited artifacts:

```powershell
python ./scripts/publish-pdfs.py --bands B00 B21 B28 B37 --mogiljanskaja
```

The two companions are published under
`output/07 Halbgruppen und Monoide/Ergänzungen/Mogiljanskaja-Gegenbeispiel/`.
The main B28 PDF remains directly in the subject folder. The publisher
rewrites relative links for this hierarchy and includes existing companion
PDFs in every publication link audit. Full publication includes each
available companion pair and rejects incomplete pairs before replacing
any PDFs. The mathematical dependency graph remains a graph of volumes;
edition navigation is handled separately by the build scripts.

## Dedekind recursion theorem / Lesefassung und Beweistabellen

The source package under `tex/b10/dedekind/` separates the construction
from the public recursion theorem in B10. The theorem keeps the canonical
ID `DedekindRecursionTheorem`. B10 defines the named recursion function by
its uniquely satisfied recursion equations and retains its usable results;
applications do not need the private graph construction.

The proof companion owns the construction's three structural axioms, four
definitions, 19 theorems and 18 registered subsidiary proof statements,
using the independent number prefix `10E`. The final proof refers back to
the public B10 theorem without declaring a second local copy. The reading
edition provides a complete explanatory proof without local numbered
declarations. Both editions link to B10 and to each other.

With the predecessor artifacts already built, run:

```powershell
pwsh -NoProfile -File ./scripts/build-dedekind-editions.ps1 -Python /path/to/python
```

The targeted builder rebuilds B10, the proof and reading companions, the
volumes with references affected by the B10 renumbering, the Mogiljanskaja
companions, B00 and the complete manuscript. It then audits and publishes
these artifacts. The default affected volumes are B15, B16, B17, B19, B20,
B21, B22, B26, B27, B28, B29, B33, B34, B35, B37, B38, B39, B43, B47 and
B48. `-AffectedBands` can override this set after a new dependency review.
`-SkipMain` and `-SkipPublish` omit their respective stages.
`-SkipVolumeBuild` reuses existing, current volume artifacts; affected
Mogiljanskaja companions must then also have been rebuilt separately.

`-EditionsOnly` builds just the two Dedekind companions from current B10
artifacts. The full builder invokes this mode after the last selected B10
prerequisite, before checking the main volume's outgoing links. On a clean
checkout, build the predecessor volumes with `build-all.ps1` first.

The companion jobs are `_B10-dedekind-proofs` and `_B10-dedekind-reading`;
their generated imports, numbering setup, registries and PDFs stay under
`registry/dedekind/`. `scripts/dedekind-editions.py prepare` imports the
complete current B10 registry and AUX and writes the independent `10E`
numbering setup. `prepare-reading` imports the proof companion's records.
The `audit` mode verifies all 44 construction labels and six ID records,
disjoint ownership, current imports, the absence of reading-edition
declarations, PDF destinations, reciprocal navigation and direct links
from the public theorem to both editions and its final proof. These are
document-integrity checks, not a mathematical proof certification.
Targeted builds preserve existing AUX information with `latexmk -g`.

The publisher's `--dedekind` option includes both companions in a selected
publication. For example, after rebuilding every affected artifact:

```powershell
python ./scripts/publish-pdfs.py --bands B00 B10 B15 B16 B17 B19 B20 B21 B22 B26 B27 B28 B29 B33 B34 B35 B37 B38 B39 B43 B47 B48 --dedekind --mogiljanskaja
```

The companion PDFs are published under
`output/04 Zahlen und Folgen/Ergänzungen/Dedekindscher Rekursionssatz/`.
Existing Dedekind companions participate in every publication link audit;
a full publication includes the pair once its build products are present,
rejecting an incomplete pair before replacing any PDF.

## Integers / Lesefassung und Beweistabellen

The package `tex/b17/integers/` moves the concrete integer model up to the
abstraction boundary into two companions. Its reading covers the complete
integer structure: negation, addition, multiplication, order, normal forms,
discreteness and two-sided induction. The proof companion contains all 94
original proof tables and owns the 137 private IDs with prefix `17E`.
B17 retains the 85 public IDs: all axioms, the three axiom blocks, the
canonical model theorem `IntQuotientModelsIntegerPeano` and statements used
by other subject volumes. Their formulas, numbers and PDF destinations stay
stable. The B41 companions develop the general additive embedding theorem
for commutative cancellative monoids and refer to this integer construction.

With current predecessor artifacts and an existing B41 build, run:

```powershell
pwsh -NoProfile -File ./scripts/build-integers-editions.ps1 -Python /path/to/python
```

The helper rebuilds B17, prepares its filtered imports, builds the proof
companion, prepares the reading imports and builds the reading. It then
refreshes both B41 companions using the existing B41 artifacts, rebuilds B00
and the complete manuscript, audits and publishes the results. `-SkipMain`
and `-SkipPublish` omit those stages. `-SkipVolumeBuild` reuses B17 and B00
while still refreshing both pairs of companions. `-EditionsOnly` builds and
audits only the two B17 companions from current B17/predecessor artifacts;
it does not refresh B41, build the complete manuscript or publish.

The jobs `_B17-integers-proofs` and `_B17-integers-reading` keep their PDFs,
registries and filtered imports in `registry/integers/`.
`scripts/integers-editions.py` provides `prepare`, `prepare-reading` and
`audit`; `scripts/integers-manifest.json` records the migration. The checks
cover statement ownership, preserved formulas and public numbers/anchors,
imports and PDF navigation. They do not certify mathematical inference rules.
`build-all.ps1` schedules these companions after the last selected B17
dependency and before B41's companions. It also builds them when B41, B00 or
the complete manuscript is requested without selecting B17 itself.

To publish existing audited artifacts, including the updated B41 companions:

```powershell
python ./scripts/publish-pdfs.py --bands B00 B17 --integers --differences
```

The new pair is published in
`output/04 Zahlen und Folgen/Ergänzungen/Ganze Zahlen/`. A complete publishing
run includes it automatically once either build artifact exists; an incomplete
pair is rejected before output files are replaced. Restricted runs and
`--audit-only` still check already published integer companions.

## Formal differences / Lesefassung und Beweistabellen

The package `tex/b41/differences/` separates the formal-difference construction
from the canonical embedding theorem `GroupCompletionEmbeddingTheorem` in
B41. The main theorem retains number `41.4.5.4` and its original PDF destination;
the following results also retain their numbers and destinations, so their
consumers need no renumbering. The B17 companions explain the complete
integer construction; B41's reading, “Wie aus Monoiden Gruppen werden”,
develops the general additive construction for commutative cancellative monoids.
The proof companion owns the extracted local statements with prefix `41E`;
its final table refers to the public B41 theorem without redeclaring it.

With existing predecessor artifacts, run:

```powershell
pwsh -NoProfile -File ./scripts/build-differences-editions.ps1 -Python /path/to/python
```

This rebuilds B41, the proof and reading companions, B00 and the complete
manuscript, audits the artifacts and publishes them. `-SkipMain` and
`-SkipPublish` omit those stages. `-EditionsOnly` builds and audits the two
companions from current B41/predecessor artifacts; `-SkipVolumeBuild` reuses
both B41 and B00. The full builder schedules the companions after the last
selected B41 dependency and before auditing their referring volumes.

The jobs `_B41-differences-proofs` and `_B41-differences-reading` keep their
PDFs, registries, filtered imports and numbering setup in
`registry/differences/`. `scripts/differences-editions.py` provides the modes
`prepare`, `prepare-reading` and `audit`. The migration manifest checks the
40 extracted structural registry records and 43 IDs against their original formulas,
titles and identities, allowing only the companion numbering change.
These represent seven definitions, 26 theorems and ten named subsidiary results;
definition records include both the source key and its normalized formula.
Audits also check disjoint ownership, unchanged public B41 numbers/anchors,
current imports, PDF destinations and reciprocal navigation. These checks
do not certify the mathematical inference rules.

The added product, maximum and necessary-condition chapters are checked by
`scripts/differences-supplements.py`. This checks that every new theorem has
a table proof, that local lemmas are proved before use, and that reason cells
contain introduced rules or result references. `scripts/proof-dependency-audit.py`
checks line references and the bookkeeping of open assumptions. Both checks
run with the B41 edition audit; mathematical inference and layout still require
independent review. The three corrected B17 prerequisite tables are recorded
separately in `scripts/integers-proof-corrections-2026-09-21.json`; the original
migration manifest remains unchanged.

To publish existing audited artifacts:

```powershell
python ./scripts/publish-pdfs.py --bands B00 B41 --differences
```

The companions are published in
`output/08 Gruppen/Ergänzungen/Formale Differenzen/`. The publisher rewrites
their relative links, includes existing companion PDFs in publication audits
and rejects incomplete pairs before replacing output files.

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

## Semilattices and order / Halbverbände und Ordnung

Build Band 45, both companions, the overview and the complete manuscript:

```powershell
pwsh -NoProfile -File ./scripts/build-semilattice-editions.ps1 -Python /path/to/python
```

`-EditionsOnly` builds and audits the companions using the existing Band 45
and predecessor artifacts, without publication. `-SkipMain` omits the complete
manuscript; `-SkipPublish` omits publication. The complete build integrates
the companions after their selected dependencies have been built.

The sources are in `tex/b45/semilattice/`, with entry points under `editions/`.
All 23 canonical statements remain registered in Band 45; the proof edition
displays the same statements without registering them again. Both companions
import Band 45 and its predecessor registries. The source manifest records
the original statements, tables, registry records and named destinations.

```powershell
python ./scripts/semilattice-editions.py prepare
python ./scripts/semilattice-editions.py audit
python ./scripts/publish-pdfs.py --bands B00 B45 --semilattice
```

The audit checks preservation of the 23 statements and table bodies,
unchanged canonical numbering and destinations, empty local companion
registries, and PDF navigation. These checks do not verify inference rules.
The publisher places both companions under
`output/05 Ordnungen und Verbände/Ergänzungen/Halbverbände und Ordnung/`
and rewrites their relative links to the published files.

## Frankl special cases / Frankls Spezialfälle

Build Band 46, both companions, the overview and the complete manuscript:

```powershell
pwsh -NoProfile -File ./scripts/build-frankl-editions.ps1 -Python /path/to/python
```

`-EditionsOnly` builds and audits the companions using the existing Band 46
and predecessor artifacts, without publication. `-SkipMain` omits the complete
manuscript; `-SkipPublish` omits publication. The complete build integrates
the companions after Band 46 and its selected dependencies, before auditing
the overview and complete-manuscript links.

The sources are in `tex/b46/frankl/`, with entry points under `editions/`.
The 17 extracted tables cover the singleton case (one table), nonempty
intersection (two tables), and the two-element-member case (14 tables).
All canonical statements remain registered in Band 46 with their existing
numbers and destinations. The proof edition displays the same statements
without registering them again. The reading edition ends with a historical
account followed by a concluding section.

The rare-triple example adds exactly one canonical existence theorem at the
end of Band 46. Its auxiliary results and proofs are confined to the proof
edition and use the independent `46E` number space. The original manifest
continues to protect all pre-existing statements, numbers and destinations;
the new theorem is an explicitly checked addition, not a replacement baseline.

```powershell
python ./scripts/frankl-editions.py prepare
python ./scripts/frankl-editions.py audit
python ./scripts/publish-pdfs.py --bands B00 B46 --frankl
```

Build artifacts are `registry/frankl/_B46-frankl-reading.pdf` and
`registry/frankl/_B46-frankl-proofs.pdf`. The publisher requires both when
`--frankl` is selected and includes the pair in a complete publication once
either artifact exists. It publishes them under
`output/02 Mengenlehre und Mengenfamilien/Ergänzungen/Frankls Spezialfälle/`
and rewrites remote links to the published filenames. The source audit also
scans the extracted companion files. Structural audits and link checks do
not verify mathematical inference rules.

## Group reconstruction / Gruppenrekonstruktion

Build Band 40, both companions, the overview and the complete manuscript:

```powershell
pwsh -NoProfile -File ./scripts/build-reconstruction-editions.ps1 -Python /path/to/python
```

`-EditionsOnly` builds and audits the companions using current Band 40 and
predecessor artifacts. `-SkipMain` and `-SkipPublish` omit their respective
stages. `build-all.ps1` schedules the companions after the last selected
Band 40 dependency and before auditing links from the canonical volume.

The sources are in `tex/b40/reconstruction/`, with entry points under
`editions/`. Twelve table proofs are extracted; seven general unit-group
tables remain in Band 40. All canonical statements retain their numbers
and named destinations. This includes the registered inner result
`GroupPowerFullCarrierAbsorptionProductMember`. Both companions import
canonical statements and do not create competing theorem registrations.

```powershell
python ./scripts/reconstruction-editions.py prepare
python ./scripts/reconstruction-editions.py audit
python ./scripts/publish-pdfs.py --bands B00 B40 --reconstruction
```

The manifest preserves the original statements, table bodies and registry
identities. The audits check their preservation, canonical numbers and
destinations, imports, and reciprocal PDF navigation. These checks do not
certify mathematical inference rules. The reading edition has a complete
explanatory proof, a historical account and a final concluding section.

The jobs `_B40-reconstruction-reading` and `_B40-reconstruction-proofs` live
under `registry/reconstruction/`. Both are published under
`output/08 Gruppen/Ergänzungen/Gruppenrekonstruktion/`. Complete publication
includes the pair once either build artifact exists, rejecting an incomplete
pair before replacing output files. Restricted runs still audit already
published companions.

## Null-product reconstruction / Nullprodukt-Rekonstruktion

The source package `tex/b37/nullproducts/` proves reconstruction for finite
semigroups with zero and exactly two product values. B37 owns the public
statement `FiniteTwoProductZeroReconstruction`; the proof companion owns its
private auxiliary results with number prefix `37E`. The reading companion
imports both sources and registers no local statements. General prerequisites
remain in the earlier subject volumes.

With current predecessor artifacts, build the companions and their referring
volumes with:

```powershell
pwsh -NoProfile -File ./scripts/build-nullproducts-editions.ps1 -Python /path/to/python
```

`-EditionsOnly` builds and audits only the companions from existing B37 and
predecessor artifacts. `-SkipMain`, `-SkipPublish` and `-SkipVolumeBuild` follow
the other companion builders. After changing prerequisites, first rebuild the
affected dependency range with `build-all.ps1`; the targeted builder deliberately
does not refresh all predecessors. The complete builder schedules the new pair
after B37's last selected dependency and before auditing outgoing volume links.

The jobs `_B37-nullproducts-proofs` and `_B37-nullproducts-reading` keep all
generated files under `registry/nullproducts/`. The preparation script first
imports B37, then imports the proof registry into the reading edition. Its
manifest protects the original B37 records, numbers and named destinations;
private IDs and direct proof destinations are recorded separately.

```powershell
python ./scripts/nullproducts-editions.py prepare
python ./scripts/nullproducts-editions.py prepare-reading
python ./scripts/nullproducts-editions.py audit
python ./scripts/publish-pdfs.py --bands B00 B37 --nullproducts
```

Run `prepare-reading` after the proof companion has been built, and `audit`
after both builds. The audits check statement ownership, numbering, imports and
PDF navigation. They do not certify mathematical inference rules. Both PDFs
are published under
`output/07 Halbgruppen und Monoide/Ergänzungen/Nullprodukt-Rekonstruktion/`.
Complete publication includes the pair once either build artifact exists;
incomplete pairs are rejected before replacing PDFs. Restricted publication
and audit runs also check already published null-product companions.

## Total boundedness and compactness companions

The source package `tex/b47/compactness/` adds seven public definitions and
theorems to B47. Detailed prose proofs live in a separate companion, with three
private lemmas numbered `47E`. The reading edition declares no numbered statements.

```powershell
pwsh -NoProfile -File ./scripts/build-compactness-editions.ps1 -Python /path/to/python
```

The targeted build refreshes B47, the proofs, the reading edition, B00 and the
combined manuscript, then publishes the PDFs. It uses existing predecessor
artifacts; rebuild changed prerequisites first. `-EditionsOnly` builds only the
companions from existing B47 artifacts. `-SkipVolumeBuild`, `-SkipMain` and
`-SkipPublish` have the same meanings as for the other companion builders.
`build-all.ps1` schedules these companions after B47's last selected dependency,
before auditing outgoing volume links.

The jobs `_B47-compactness-proofs` and `_B47-compactness-reading` write to
`registry/compactness/`. `scripts/compactness-manifest.json` preserves the
pre-existing B47 registry, statement numbers and named destinations. Do not
replace this baseline when adding results. The source and PDF audits verify
statement ownership, semantic references, canonical imports and navigation;
they do not check mathematical validity.

```powershell
python ./scripts/compactness-editions.py prepare
python ./scripts/compactness-editions.py prepare-reading
python ./scripts/compactness-editions.py audit
python ./scripts/publish-pdfs.py --bands B00 B47 --compactness
```

Run `prepare` after B47, `prepare-reading` after the proof companion, and `audit`
after both companions have been built. The published pair appears under
`output/10 Metrische Räume/Ergänzungen/Totale Beschränktheit und Kompaktheit/`.
Full publication includes both companions once either artifact exists; both
must pass preflight before publication. Restricted runs also audit existing
published companions.

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
