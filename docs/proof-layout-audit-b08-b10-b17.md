# Layout-Audit B08, B10, B17

Stand: 2026-09-06. Individuelle Registry-Builds strikt seriell mit `latexmk -norc -gg -lualatex -interaction=nonstopmode -halt-on-error -file-line-error`, ohne Publikation. Gegenstand sind die Beweistabellen nach Vereinheitlichung der Formel- und Begründungsspalten auf 0,59 / 0,23 der Zeilenbreite.

## B08 – Bijektive Funktionen

- Erfolgreicher Baseline- und Korrekturbau (80 Seiten).
- Zwei Tabellen mit unabhängig breiten Kettenspalten: insgesamt vier vollständige Gleichungen in die normale Formelspalte überführt. Aussagen, Zeilennummern und Kettenverweise erhalten.
- In der Schlussäquivalenz zur C-Verträglichkeit den starren 30-mm-Einzug auf einen normalen Folgezeileneinzug verkürzt.
- Elf reine Textbegründungen im Transpositionsbeweis in umbrechbare Absatzboxen gesetzt. Die gemeinsame math-kompatible Begründungsspalte hatte die bisherigen textnormal-Texte untrennbar gemacht.
- Abschließender Log: keine überbreiten Beweistabellen mehr. Außerhalb der Tabellen verbleiben drei Displaywarnungen beim Kerntransport / der Schichtfortsetzung sowie eine Gliederungszeile. Diese sind nicht durch die neue Tabellenspalte verursacht.
- PDF visuell geprüft: physische Seiten 37, 45, 79; lesbare Formeln und feste, getrennte Begründungsspalte. Vorher-/Nachherbilder in `tmp/pdfs/B08-layout/`.
- Mathematischen Nebenfund an Root gemeldet: Selbstbezug rIE{4,7} im Kompositionshilfslemma; Root hat ihn separat zu rIE{4,\rII} korrigiert.

## B10 – Natürliche Zahlen

- Baseline-Build: 218 Seiten, sieben Overfull-hbox-Meldungen in Beweistabellen.
- Acht Zeilen gezielt formatiert: zwei vollständige Äquivalenzen statt überbreiter Kettenspalten; die lokale Induktionsregel zweizeilig; vier lange Induktionsformeln an Konjunktion bzw. Quantorenblock gebrochen; Fallterm-Gleichung nach dem Gleichheitszeichen gebrochen.
- Keine Zeilennummern, Voraussetzungen oder Theoremschlüssel durch diese Layoutedits geändert.
- Finalbuild erfolgreich, anschließend eigenständige latexmk-Aktualitätsprüfung: Nothing to do. Null Overfull-Warnungen im gesamten Log. Root hat parallel drei mathematische Indexfehler korrigiert; diese sind im aktualisierten Finalbuild enthalten.
- PDF visuell geprüft: physische Seiten 63, 64, 70, 71; lesbare Induktionsformeln und Fallterm-Auswertung. Bilder in `tmp/pdfs/B10-layout/`.

## B17 – Ganze Zahlen

- Baseline-Build: 99 Seiten und 14 überbreite Tabellenstellen.
- 16 Formelzeilen korrigiert: drei Kettenschritte als vollständige zweizeilige Gleichungen; acht Existenz-/Eindeutigkeitsformeln vor der letzten Bedingung geteilt; sechs lange Zahlenpaar-Vorkommen in fünf Formelzeilen mit getrennten Koordinaten gesetzt. Die sichtbare Paarnotation bleibt mathematisch identisch; nur diese Anzeigeformen verwenden explizite umgebrochene eckige Klammern.
- Eigener Finalbuild erfolgreich, 99 Seiten, null Overfull-Warnungen im gesamten Log.
- PDF visuell geprüft: physische Seiten 25, 26, 32, 40, 41, 42, 43. Die Sichtkontrolle fand sechs weitere vollständige Gleichungen, die ohne Logwarnung bis unmittelbar an ihre Begründung reichten; diese haben zusätzlich einen expliziten Gleichheitsumbruch erhalten (22 geänderte Formelzeilen insgesamt).
- Die sechs abschließenden Sichtkorrekturen sind gespeichert und an Root zur Mitnahme in der bereits gestarteten finalen Gesamtkette gemeldet; kein weiterer paralleler Build durch diesen Agenten. Bisheriger Finalbuild und Bilder gehen diesen letzten sechs Umbrüchen voraus.
- Bildbelege in `tmp/pdfs/B17-layout/`, Änderungszeilen in `tmp/proof-audit/B17-layout-edits.json` und `B17-layout-visual-extra.json`.

## Quellenprüfung

Alle drei Quellen haben ausgeglichene TeX-Gruppen; die Tabellenzeilen bleiben vollständig parsebar. Zeilennummern und Theoremschlüssel wurden bei den Layoutedits nicht verändert. Die letzte globale Kompilation und Veröffentlichung übernimmt Root seriell.
