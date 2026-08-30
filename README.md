# Die Grundlagen der Mathematik

Deutsch:
Dieses Repository enthält mein LaTeX-Projekt zum systematischen Aufbau der Mathematik auf Basis natürlicher Deduktion im Stil von E. J. Lemmon.

English:
This repository contains my LaTeX project on developing mathematics from the ground up using natural deduction in the style of E. J. Lemmon.

## Sprache / Language

Der Haupttext des Buchprojekts ist derzeit überwiegend auf Deutsch.
Die formalen Teile sind weitgehend sprachunabhängig und konzentrieren sich auf Definitionen, Sätze, Axiome und tabellarische Beweise.

The main text of the book project is currently mostly written in German.
Many formal parts are largely language-independent and focus on definitions, theorems, axioms, and structured proof tables.

## Projektidee / Project Idea

Ziel dieses Projekts ist es, zentrale Teile der Mathematik schrittweise aus logischen Grundregeln aufzubauen.
Im Mittelpunkt steht nicht nur das Ergebnis einzelner Sätze, sondern auch ihre explizite Herleitung im Stil natürlicher Deduktion.

The aim of this project is to develop core parts of mathematics step by step from logical proof rules.
The focus is not only on final results, but also on their explicit derivation in a natural deduction style.

## Status / Status

Dieses Projekt ist Work in Progress.
Inhalte werden fortlaufend erweitert, umgestellt, präzisiert und vereinheitlicht.

This project is a work in progress.
Content is continuously being extended, reorganized, refined, and unified.

## Build

Alle Builds verwenden LuaLaTeX. Der Gesamtband entsteht mit:

```powershell
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error main.tex
```

### Standalone-Bände B03 bis B37

Der einzige Abhängigkeitsgraph steht in `band-dependencies.tsv`:

| Zielband | transitive Vorgänger in Build-Reihenfolge |
| --- | --- |
| B03 | B01, B02 |
| B04 | B01, B02, B03 |
| B05 | B01, B02, B03, B04 |
| B06 | B01, B02, B03, B04, B05 |
| B07 | B01, B02, B03, B04, B05, B06 |
| B08 | B01, B02, B03, B04, B05, B06, B07 |
| B09 | B01, B02, B03, B04, B05, B06, B07, B08 |
| B10 | B01, B02, B03, B04, B05, B06, B07, B08, B09 |
| B11 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 |
| B12 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 |
| B13 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12 |
| B14 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13 |
| B15 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14 |
| B16 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15 |
| B17 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16 |
| B18 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17 |
| B19 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18 |
| B20 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19 |
| B21 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20 |
| B22 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21 |
| B23 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22 |
| B24 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23 |
| B25 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24 |
| B26 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25 |
| B27 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26 |
| B28 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27 |
| B29 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28 |
| B30 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28, B29 |
| B31 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28, B29, B30 |
| B32 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28, B29, B30, B31 |
| B33 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28, B29, B30, B31, B32 |
| B34 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28, B29, B30, B31, B32, B33 |
| B35 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28, B29, B30, B31, B32, B33, B34 |
| B36 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28, B29, B30, B31, B32, B33, B34, B35 |
| B37 | B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21 |

Die chronologische Gliederung folgt den Begriffsabhängigkeiten:

| Band | Thema |
| --- | --- |
| B01 | Grundlagen der Logik |
| B02 | Theoreme der Logik |
| B03 | Mengenlehre und funktionsfreie ZFC-Schemata |
| B04 | Totale Relationen |
| B05 | Funktionen |
| B06 | Injektive Funktionen |
| B07 | Surjektive Funktionen |
| B08 | Bijektive Funktionen |
| B09 | Auswahlprinzip |
| B10 | Natürliche Zahlen |
| B11 | Äquivalenzrelationen und Quotienten |
| B12 | Halbordnungen |
| B13 | Schranken, Infima und Suprema |
| B14 | Paarinfima und Paarsuprema |
| B15 | Totale Ordnungen |
| B16 | Wohlordnungen und Auswahlaxiom |
| B17 | Ganze Zahlen |
| B18 | Rationale Zahlen |
| B19 | Reelle Zahlen |
| B20 | Endliche Mengen |
| B21 | Folgen |
| B22 | Halbgruppen |
| B23 | Kommutative Halbgruppen |
| B24 | Idempotente Halbgruppen |
| B25 | Rechtecksbänder |
| B26 | Kommutative idempotente Halbgruppen |
| B27 | Halbgruppen mit Nullelement |
| B28 | Linkskürzbare Halbgruppen |
| B29 | Rechtskürzbare Halbgruppen |
| B30 | Kürzbare Halbgruppen |
| B31 | Endliche Halbgruppen |
| B32 | Monoide |
| B33 | Halbringe |
| B34 | Gruppen und Ringe |
| B35 | Halbverbände und Verbände |
| B36 | Frankls Vermutung |
| B37 | Metrische Räume und Vollständigkeit |

Spätere Fachbände dürfen Beispiele früher eingeführter Strukturen enthalten.
Eigenschaftsneutrale allgemeine Funktionskonstruktionen stehen in B05.
Allgemeine Standardkonstruktionen mit kennzeichnender Abbildungseigenschaft
werden dagegen erstmals im passenden Eigenschaftsband eingeführt:
Inklusionsabbildungen und die injektive Adjunktionsabbildung in B06,
Projektionen in B07 sowie Identitäts- und Umkehrfunktionen in B08. Das
Auswahlprinzip steht getrennt in B09, damit die elementare
Surjektionstheorie nicht vom Auswahlaxiom abhängt.
Fachspezifische Funktionen bleiben in dem Band, der die für ihre Definition
benötigten Gegenstände einführt; insbesondere bleiben natürliche
arithmetische Funktionen in B10 und ganzzahlige Funktionen in B17. B11
entwickelt danach die für die Ganzzahlkonstruktion benötigte Äquivalenz- und
Quotiententheorie. Die Bände B12--B16 gliedern die Ordnungstheorie in
Halbordnungen, Schranken, Infima und Suprema, Paarinfima und Paarsuprema, totale
Ordnungen sowie Wohlordnungen. B17 konstruiert die ganzen Zahlen, B18 die
rationalen Zahlen und B19 die reellen Zahlen folgenfrei aus
Dedekind-Schnitten, sodass B21 anschließend Folgen, endliche Folgen, Familien
und reelle Grenzwerte ohne Abhängigkeitszirkel einführen kann. B20 behandelt
zuvor die endlichen Mengen. Nach dem jeweiligen Modellnachweis stellen B17
und B18 die arithmetischen Gesetze als einzeln registrierte Axiomschnittstellen
bereit; die anschließenden Sätze verwenden diese Schnittstellen statt erneut
mit Paarrepräsentanten zu rechnen. Ganzzahlige und rationale Zahlzeichen
werden typisiert, aber ohne sichtbaren Trägerindex geschrieben
(beispielsweise `\IntNumeral{2}` und `\RatNumeral{2}`); für mehrdeutige
Kontexte bleiben die expliziten Einbettungen `\IntOfNat`, `\RatOfInt` und
`\RatOfNat` verfügbar.
Die Bände B22--B31 untersuchen Halbgruppen und ihre zusätzlichen
Axiomstrukturen getrennt. Die Bände B32--B34 behandeln Monoid-, Halbring-,
Gruppen- und Ringstrukturen. Ihre allgemeinen
Abbildungseigenschaften werden mit den
Sätzen aus B06--B08 nachgewiesen. Die Nummerierung bezeichnet damit eine
Beweisreihenfolge, keine ausschließliche thematische Zuordnung. B37 eröffnet
einen analytischen Zweig, der nur B01--B21 voraussetzt: Der reelle Abstand
wird zu einer allgemeinen Metrik abstrahiert; Konvergenz, Cauchy-Folgen,
metrische Vollständigkeit, Stetigkeit und Folgenkompaktheit werden darauf
aufgebaut. Normen werden bis zur späteren Vektorraumtheorie zurückgestellt.

TeX/Lua, `latexmkrc` und das PowerShell-Skript lesen dieselbe Datei. Die dort
ebenfalls festgelegte explizite Zuordnung lautet beispielsweise
`Bd. 04 - Totale Relationen.tex` → `registry/_B04`; sie ist absichtlich keine
unveränderte tex→aux-Standardregel.
Die Dateinamen folgen dem sichtbaren Dokumenttitel. Nur die unter Windows
unzulässigen Doppelpunkte in den Titeln von Band 01 und Band 02 sind im
Dateinamen durch ` - ` ersetzt. Die internen Bandkennungen `B01` bis `B37`
und die daraus erzeugten Artefaktnamen bleiben davon unberührt.

### PDF-Titel und File Juggler

Jede aktive Banddatei setzt im Subfile-Vorspann `pdftitle` und `pdfauthor`
explizit mit `\hypersetup`. Dadurch überschreibt ein Standalone-Build den in
der gemeinsamen Präambel gesetzten Titel des Gesamtbandes zuverlässig. File
Juggler kann beim Umbenennen deshalb direkt **PDF properties → Title**
verwenden; die Dateiendung bleibt dabei erhalten. Bei Namenskonflikten sollte
**Rename new file** gewählt werden, damit keine vorhandene PDF überschrieben
wird.

Vorausgesetzt werden PowerShell, `latexmk`, `lualatex` und `pdftotext` im
`PATH`. Ein sauberer Build samt vollständigem Referenzaudit ist jeweils ein
Befehl:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B03
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B04
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B05
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B06
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B07
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B08
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B09
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B10
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B11
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B12
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B13
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B14
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B15
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B16
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B17
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B18
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B19
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B20
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B21
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B22
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B23
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B24
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B25
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B26
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B27
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B28
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B29
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B30
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B31
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B32
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B33
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B34
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B35
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B36
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B37
```

Mit PowerShell 7 kann `powershell` durch `pwsh` ersetzt werden. Ohne
`-Target` bleibt B03 der Standard.

Das Skript löscht für den gewählten Graphen alle bekannten Altartefakte und
baut jeden Vorgänger mit festem Jobnamen, zum Beispiel:

```text
latexmk -norc -gg -lualatex ... -outdir=registry -jobname=_B04 "Bd. 04 - Totale Relationen.tex"
```

Erst danach wird der Zielband im Projektverzeichnis gebaut. Für jeden
Vorgänger müssen anschließend
`registry/_Bxx.{aux,pdf,registry.tsv,debug.log}` frisch vorhanden sein. Das
Audit prüft zusätzlich:

- Registry-Labels gegen die jeweilige AUX-Datei;
- alle Stufenlogs auf undefinierte oder mehrdeutige Referenzen, fehlende
  AUX-/Registry-Importe und doppelte Ziele;
- alle Debuglogs auf `none`, `ambiguous-*` und `duplicate-register`;
- den extrahierten PDF-Text auf die bekannten Fehlermarker;
- jede externe PDF-Aktion auf eine vorhandene Datei und Named Destination.

Für jeden Zielband ist mindestens ein erfolgreicher Link zu einem in seiner
Abhängigkeitszeile aufgeführten Vorgänger zwingend. Dadurch prüft das Audit
eine tatsächlich verwendete Abhängigkeit, ohne einen künstlichen Verweis auf
den numerisch letzten Vorgänger zu verlangen.

### Overleaf und direkter latexmk-Aufruf

Die root-level `latexmkrc` setzt LuaLaTeX und führt vor einem Standalone-Ziel
alle Vorgänger topologisch aus. Sie folgt dem
[offiziellen xr/latexmk-Prinzip von Overleaf](https://www.overleaf.com/learn/how-to/Cross_referencing_with_the_xr_package_in_Overleaf),
verwendet wegen der abweichenden Basispfade aber eine explizite
Zuordnung der titelbasierten Quelldateien zu `registry/_Bxx` im dokumentierten
`before_xlatex`-Hook.
Benötigt wird latexmk 4.84 oder neuer.

Damit genügt lokal wie auf Overleaf, bei ausgewählter Hauptdatei
`Bd. 36 - Frankls Vermutung.tex`:

```powershell
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "Bd. 36 - Frankls Vermutung.tex"
```

Auch bei vorhandenen Artefakten erhält jeder Vorgänger mindestens einen
LuaLaTeX-Lauf, weil direkt aus Lua gelesene Registry-Dateien nicht in der
üblichen `.fls`-Abhängigkeitsliste erscheinen. Der optionale verifizierte
Cache betrifft derzeit nur B05 als direktes Ziel. Ein vollständiger erzwungener
B05-Neuaufbau ohne Cache ist möglich mit:

```powershell
$env:DGM_LATEXMK_FORCE_DEPS = '1'
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "Bd. 05 - Funktionen.tex"
```

### Verifizierter Registry-Cache für B05

Die bestehende Cache-Infrastruktur bleibt für einen direkten
Standalone-Build von B05 nutzbar; sie ist für die neue Bandgliederung jedoch
nicht erforderlich. Der Workflow `.github/workflows/registry-cache.yml`
baut B05 in CI sauber, auditiert ihn und veröffentlicht
`registry-cache-<commit>.tar.gz`. Das Archiv enthält den äußeren Ordner
`registry-cache/` und ist genau an den angegebenen Commit gebunden.

Für Overleaf wird das zum Commit passende Archiv im Projektwurzelverzeichnis
entpackt, sodass `registry-cache/manifest.tsv` existiert. Der normale
`latexmk`-Aufruf für B05 validiert vor jeder Verwendung:

- die exakte, zentral in `cache-inputs.tsv` beschriebene Quellmenge;
- Größe und SHA-256 jeder Quelle und jedes Cache-Artefakts;
- die vollständige Manifest- und Verzeichnisstruktur.

Erst nach vollständiger Prüfung werden die 16 Pflichtartefakte für B01–B04
transaktional nach `registry/` übernommen. Ein falscher Hash, eine zusätzliche
Datei, ein unvollständiges Manifest oder ein falsches Entpacklayout bricht den
Build laut ab; ein Cache wird nie stillschweigend veraltet benutzt.

Lokal besitzt der Pack-Befehl den sauberen B05-Build selbst und vergleicht die
Quellhashes vor und nach dem Lauf:

```powershell
pwsh -NoProfile -File ./scripts/registry-cache.ps1 -Mode Pack
pwsh -NoProfile -File ./scripts/registry-cache.ps1 -Mode Verify
pwsh -NoProfile -File ./scripts/registry-cache.ps1 -Mode Restore
```

Die PDFs, LaTeX-Nebendateien, Registries, Debuglogs und Cachearchive sind
generiert und werden nicht versioniert.

## Mitwirkung / Contributing

Hinweise, Korrekturen und konstruktive Vorschläge sind willkommen, insbesondere zu:

- Tippfehlern und sprachlichen Unklarheiten
- Beweisverkürzungen oder eleganteren Beweisideen
- fehlenden Verweisen auf frühere Resultate
- Struktur und Gliederung des Manuskripts
- verwandten Projekten oder Literaturhinweisen

Suggestions, corrections, and constructive feedback are welcome, especially regarding:

- typos and unclear wording
- shorter or cleaner proofs
- missing references to earlier results
- structure and organization of the manuscript
- related projects or literature references

Für Rückmeldungen oder Diskussionen bitte ein GitHub-Issue eröffnen.

For feedback or discussion, please open a GitHub issue.

## Ziel auf längere Sicht / Long-Term Aim

Langfristig soll das Projekt eine konsistente und wachsende Darstellung grundlegender Mathematik auf Basis expliziter Beweisregeln bieten.
Ein weiteres mögliches Ziel ist die teilweise Automatisierung solcher Beweise.

In the long run, the project aims to become a coherent and growing presentation of foundational mathematics based on explicit proof rules.
A further possible goal is partial automation of such proofs.

## Lizenz / License

Eine Lizenzdatei ist derzeit noch nicht hinzugefügt.
Sie sollte ergänzt werden, bevor externe Beiträge in größerem Umfang einfließen.

A license file has not yet been added.
It should be included before larger-scale external contributions are invited.
