# Die Grundlagen der Mathematik

**A German-language LaTeX manuscript with 48 subject volumes and an opening
overview that develops mathematics from
logic and set theory using explicit natural-deduction proof tables in the style
of E. J. Lemmon.**

**Ein deutschsprachiges LaTeX-Manuskript in 48 Fachbänden mit vorangestelltem
Überblick, das Mathematik aus Logik
und Mengenlehre mithilfe expliziter Beweistabellen im Stil von E. J. Lemmon
aufbaut.**

[English](#english) · [Deutsch](#deutsch) ·
[PDF catalogue / PDF-Verzeichnis](VOLUMES.md) · [Building](BUILDING.md) ·
[Contributing](CONTRIBUTING.md) · [License / Lizenz](LICENSE.md)

Die PDFs unter `output/` sind in elf nummerierte Themenordner gegliedert.
Die Hauptbände stehen direkt im jeweiligen Themenordner; ergänzende
Ausarbeitungen liegen darunter in `Ergänzungen/<Thema>/`.
Die Bandnummern bleiben erhalten; die Ordnerzuordnung und Hinweise für
reMarkable stehen im [Bandverzeichnis](VOLUMES.md).

[Band 00: Überblick über die Bände](<output/00 Einstieg und Gesamtband/Bd. 00 - Überblick über die Bände.pdf>)
stellt Definitionen und Strukturaxiome den zentralen Resultaten gegenüber.
Gruppen und Ringe sind ab Band 40 nach Strukturklassen auf eigene Bände verteilt. Die bisherige Übersicht
„Band 27 auf einen Blick“ steht jetzt im Überblicksband.

Als Pilot einer zusätzlichen Lesefassung ist der Satz von Cantor–Bernstein
aus Band 08 in zwei verknüpften Auszügen verfügbar:
[Lesefassung](<output/03 Relationen und Funktionen/Ergänzungen/Cantor-Bernstein/Bd. 08 - Cantor-Bernstein - Lesefassung.pdf>) und
[Beweistabellen](<output/03 Relationen und Funktionen/Ergänzungen/Cantor-Bernstein/Bd. 08 - Cantor-Bernstein - Beweistabellen.pdf>).
Die reguläre Band- und Gesamtausgabe enthält die Aussagen und verweist für
die Beweise auf diese beiden Begleitfassungen. Die bisherigen Kennungen,
Satznummern und Sprungziele einschließlich der Hilfsresultate bleiben erhalten.
Der Pilot umfasst diesen Abschnitt und den Anschluss an die
Gleichmächtigkeit in Band 11; er ist keine Lesefassung aller Fachbände.
Die Lesefassung enthält einen zusammenhängenden Beweis, eine knappe
Konstruktionsübersicht und einen Vergleich mit historischen Originalbeweisen.
Die ausführlichen formalen Aussagen und Ableitungstabellen stehen in den
verknüpften Fach- und Beweisfassungen.

Ein [Ausbauvorschlag bis zu Gödels Unvollständigkeitssätzen](docs/goedel-ausbau.md)
beschreibt mögliche zusätzliche Fachbände und ihre Voraussetzungen.

---

## English

### What this project is

*Die Grundlagen der Mathematik* (*Foundations of Mathematics*) is a work in
progress that makes proof dependencies unusually explicit. Its current scope
runs from propositional and predicate logic through ZFC set theory, functions,
number systems, order theory and graph theory to semigroups, lattices, Frankl's
conjecture, and metric spaces.

The combined manuscript currently contains more than 1,700 pages. The project
is written primarily in German; formulas and proof tables are largely
language-independent.

### What makes it different

- Proofs are displayed as Lemmon-style tables recording open assumptions,
  inference rules, and referenced lines.
- Definitions, axioms, and theorems are arranged in an explicit dependency
  order rather than only by conventional subject boundaries.
- Each volume can be built separately while retaining verified cross-volume
  references.
- The LaTeX/Lua tooling audits labels, destinations, registries, and build
  dependencies.

This is a human-written mathematical manuscript, not a Lean, Coq, or Isabelle
formalization. The automated checks verify document and reference integrity;
they do **not** certify mathematical correctness.

### Where to start

- [Volume 01: Foundations of Logic](<output/01 Logik/Bd. 01 - Grundlagen der Logik.pdf>)
  introduces the formal language and explains how to read the proof tables.
- [Volume 03: Set Theory](<output/02 Mengenlehre und Mengenfamilien/Bd. 03 - Mengenlehre.pdf>) shows the
  foundational method on a substantial body of mathematics.
- [Volume 26: Trees](<output/06 Graphen, Bäume und Wörter/Bd. 26 - Bäume.pdf>) develops the axiomatic
  tree language used by the subsequent construction of bracketing trees.
- [Volume 46: Frankl's Conjecture](<output/02 Mengenlehre und Mengenfamilien/Bd. 46 - Frankls Vermutung.pdf>)
  is a research-oriented application collecting set-theoretic, quotient, and
  semilattice formulations and proved special cases.
- [Volume 47: Metric Spaces and Completeness](<output/10 Metrische Räume/Bd. 47 - Metrische Räume und Vollständigkeit.pdf>)
  is a comparatively compact entry into the analytic branch.
- [Volume 48: Axiomatic Set Theory II](<output/02 Mengenlehre und Mengenfamilien/Bd. 48 - Axiomatische Mengenlehre II.pdf>)
  is a meta-methodological supplement for power set, cardinality, and continuum
  arguments.
- The [complete bilingual volume catalogue](VOLUMES.md) links all current PDFs.

[![A page with Lemmon-style proof tables from Volume 46](docs/assets/lemmon-proof-example.png)](<output/02 Mengenlehre und Mengenfamilien/Bd. 46 - Frankls Vermutung.pdf>)

*Example: explicit proof tables in Volume 46. Click the image to open the
volume.*

### Intended audience

The manuscript is most likely to be useful to readers interested in
mathematical logic, foundations, explicit proof dependencies, proof pedagogy,
or one of the later specialist topics. Despite starting from first principles,
it is not currently designed as a conventional beginner textbook: it is dense,
contains few exercises, and prioritizes explicit derivation over intuition and
examples.

### Status and limitations

- Active work in progress; organization, notation, and proofs may change.
- Not peer reviewed and not machine checked by a proof assistant.
- Some construction principles are temporarily isolated as explicit axiomatic
  interfaces while their derivation is still being developed.
- Current published PDF snapshots are in German.

Corrections and focused mathematical criticism are welcome. Please see
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a substantial pull request.

### Building and citation

The complete manuscript is built with LuaLaTeX:

```powershell
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error main.tex
```

Standalone builds, cross-volume dependencies, the verified registry cache, and
Overleaf notes are documented in [BUILDING.md](BUILDING.md). Citation metadata
is available in [CITATION.cff](CITATION.cff).

The original manuscript and editorial content are licensed under
[CC BY 4.0](LICENSE.md#manuscript-and-project-content-cc-by-40); the software
and build infrastructure are licensed under the
[MIT License](LICENSE.md#software-and-build-infrastructure-mit). See
[LICENSE.md](LICENSE.md) for the exact file scope and attribution guidance.

---

## Deutsch

### Worum es in diesem Projekt geht

*Die Grundlagen der Mathematik* ist ein im Aufbau befindliches Manuskript, das
Beweisabhängigkeiten ungewöhnlich explizit sichtbar macht. Der derzeitige
Umfang reicht von Aussagen- und Prädikatenlogik über ZFC-Mengenlehre,
Funktionen, Zahlbereiche, Ordnungs- und Graphentheorie bis zu Halbgruppen,
Verbänden, Frankls Vermutung und metrischen Räumen.

Der Gesamtband umfasst gegenwärtig mehr als 1.700 Seiten. Der Text ist
überwiegend deutsch; Formeln und Beweistabellen sind weitgehend
sprachunabhängig.

### Was das Projekt besonders macht

- Beweise erscheinen als Tabellen im Lemmon-Stil mit offenen Annahmen,
  Schlussregeln und Zeilenverweisen.
- Definitionen, Axiome und Sätze folgen einer expliziten Abhängigkeitsordnung
  und nicht nur der üblichen Fächereinteilung.
- Jeder Band kann einzeln gebaut werden und behält dabei geprüfte Verweise auf
  frühere Bände.
- Die LaTeX-/Lua-Infrastruktur prüft Marken, Sprungziele, Registries und
  Build-Abhängigkeiten.

Das Projekt ist ein von Menschen geschriebenes mathematisches Manuskript und
keine Formalisierung in Lean, Coq oder Isabelle. Die automatischen Prüfungen
sichern Dokument- und Referenzintegrität, **nicht** die mathematische
Korrektheit.

### Empfohlene Einstiege

- [Band 01: Grundlagen der Logik](<output/01 Logik/Bd. 01 - Grundlagen der Logik.pdf>)
  führt die formale Sprache ein und erklärt die Beweistabellen.
- [Band 03: Mengenlehre](<output/02 Mengenlehre und Mengenfamilien/Bd. 03 - Mengenlehre.pdf>) zeigt die
  Methode an einem umfangreichen mathematischen Gebiet.
- [Band 26: Bäume](<output/06 Graphen, Bäume und Wörter/Bd. 26 - Bäume.pdf>) entwickelt die
  axiomatische Baumsprache für die anschließende Konstruktion der
  Klammerungsbäume.
- [Band 46: Frankls Vermutung](<output/02 Mengenlehre und Mengenfamilien/Bd. 46 - Frankls Vermutung.pdf>) ist
  eine forschungsnahe Anwendung mit Mengen-, Quotienten- und
  Halbverbandsfassungen sowie bewiesenen Spezialfällen.
- [Band 47: Metrische Räume und Vollständigkeit](<output/10 Metrische Räume/Bd. 47 - Metrische Räume und Vollständigkeit.pdf>)
  bietet einen vergleichsweise kompakten Einstieg in den analytischen Zweig.
- [Band 48: Axiomatische Mengenlehre II](<output/02 Mengenlehre und Mengenfamilien/Bd. 48 - Axiomatische Mengenlehre II.pdf>)
  ergänzt die formale Methodik für Aussagen zu Potenzmengen, Kardinalität und
  Kontinuum.
- Das [vollständige zweisprachige Bandverzeichnis](VOLUMES.md) verlinkt alle
  aktuellen PDFs.

### Zielgruppe

Das Manuskript richtet sich vor allem an Menschen mit Interesse an
mathematischer Logik, Grundlagenfragen, expliziten Beweisabhängigkeiten,
Beweisdidaktik oder einzelnen späteren Fachgebieten. Trotz des Aufbaus von den
Grundlagen her ist es derzeit kein gewöhnliches Anfängerlehrbuch: Die
Darstellung ist dicht, enthält nur wenige Übungen und priorisiert explizite
Herleitungen gegenüber Anschauung und Beispielen.

### Stand und Grenzen

- Aktives Work in Progress; Gliederung, Notation und Beweise können sich ändern.
- Nicht begutachtet und nicht durch einen Beweisassistenten maschinell geprüft.
- Einige Konstruktionsprinzipien sind vorläufig als ausdrücklich bezeichnete
  axiomatische Schnittstellen isoliert, solange ihre Herleitung noch entwickelt
  wird.
- Die veröffentlichten PDF-Schnappschüsse sind derzeit deutschsprachig.

Korrekturen und konkrete mathematische Kritik sind willkommen. Vor einem
umfangreichen Pull Request bitte [CONTRIBUTING.md](CONTRIBUTING.md) lesen.

### Bauen und Zitieren

Der Gesamtband wird mit LuaLaTeX gebaut:

```powershell
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error main.tex
```

Standalone-Builds, Bandabhängigkeiten, der verifizierte Registry-Cache und
Overleaf-Hinweise stehen in [BUILDING.md](BUILDING.md). Zitiermetadaten enthält
[CITATION.cff](CITATION.cff).

Die ursprünglichen Manuskript- und Redaktionsinhalte stehen unter
[CC BY 4.0](LICENSE.md#manuscript-and-project-content-cc-by-40); Software und
Build-Infrastruktur stehen unter der
[MIT-Lizenz](LICENSE.md#software-and-build-infrastructure-mit). Die genaue
Dateizuordnung und Hinweise zur Namensnennung enthält
[LICENSE.md](LICENSE.md).
