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

### Standalone-Bände B03 bis B05

Der einzige Abhängigkeitsgraph steht in `band-dependencies.tsv`:

| Zielband | transitive Vorgänger in Build-Reihenfolge |
| --- | --- |
| B03 | B01, B02 |
| B04 | B01, B02, B03 |
| B05 | B01, B02, B03, B04 |

TeX/Lua, `latexmkrc` und das PowerShell-Skript lesen dieselbe Datei. Die dort
ebenfalls festgelegte explizite Zuordnung lautet beispielsweise
`B04.tex` → `registry/_B04`; sie ist absichtlich keine unveränderte
tex→aux-Standardregel.

Vorausgesetzt werden PowerShell, `latexmk`, `lualatex` und `pdftotext` im
`PATH`. Ein sauberer Build samt vollständigem Referenzaudit ist jeweils ein
Befehl:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B03
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B04
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-b03.ps1 -Target B05
```

Mit PowerShell 7 kann `powershell` durch `pwsh` ersetzt werden. Ohne
`-Target` bleibt B03 der Standard.

Das Skript löscht für den gewählten Graphen alle bekannten Altartefakte und
baut jeden Vorgänger mit festem Jobnamen, zum Beispiel:

```text
latexmk -norc -gg -lualatex ... -outdir=registry -jobname=_B04 B04.tex
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

Für B05 ist mindestens ein erfolgreicher Link nach `registry/_B04.pdf`
zwingend.

### Overleaf und direkter latexmk-Aufruf

Die root-level `latexmkrc` setzt LuaLaTeX und führt vor einem Standalone-Ziel
alle Vorgänger topologisch aus. Sie folgt dem
[offiziellen xr/latexmk-Prinzip von Overleaf](https://www.overleaf.com/learn/how-to/Cross_referencing_with_the_xr_package_in_Overleaf),
verwendet wegen der abweichenden Basispfade aber eine explizite
`Bxx.tex`→`registry/_Bxx`-Zuordnung im dokumentierten `before_xlatex`-Hook.
Benötigt wird latexmk 4.84 oder neuer.

Damit genügt lokal wie auf Overleaf, bei ausgewählter Hauptdatei `B05.tex`:

```powershell
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error B05.tex
```

Auch bei vorhandenen Artefakten erhält jeder Vorgänger mindestens einen
LuaLaTeX-Lauf, weil direkt aus Lua gelesene Registry-Dateien nicht in der
üblichen `.fls`-Abhängigkeitsliste erscheinen. Ein vollständiger erzwungener
Neuaufbau ohne Cache ist möglich mit:

```powershell
$env:DGM_LATEXMK_FORCE_DEPS = '1'
latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error B05.tex
```

### Verifizierter Registry-Cache für B05

Ein sauberer B05-Vorlauf ist lang und kann ein Overleaf-Zeitlimit
überschreiten. Der Workflow `.github/workflows/registry-cache.yml` baut B05
deshalb in CI sauber, auditiert ihn und veröffentlicht
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
