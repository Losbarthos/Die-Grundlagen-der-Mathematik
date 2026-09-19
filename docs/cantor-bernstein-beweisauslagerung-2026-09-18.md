# Cantor–Bernstein: Beweise in den Begleitfassungen

Stand: 18. September 2026. Fortschreibung des
[ersten Piloten](lesefassung-und-beweise-umsetzung-2026-09-18.md) auf Wunsch
des Autors.

Die anschließende Überarbeitung der Lesefassung anhand der handschriftlichen
PDF-Anmerkungen ist separat dokumentiert:
[Korrekturen vom 19. September 2026](csb-lesefassung-anmerkungen-2026-09-19.md).
Die folgenden Seitenzahlen und Angaben zum Aussagenanhang beschreiben den
Stand der Auslagerung am 18. September.

## Redaktionelle Entscheidung

Die Auslagerung ist sinnvoll, weil die beiden Begleitfassungen bereits die
vollständigen Beweise enthalten. Die erneute Wiedergabe in Band 08 und im
Gesamtband verlängerte den Haupttext, ohne einen zusätzlichen Nachweis
bereitzustellen. Im Hauptwerk bleiben die mathematischen Aussagen erhalten;
sichtbare Links führen zu beiden Beweisdarstellungen.
Diese Links stehen sowohl am Abschnittsanfang als auch unmittelbar unter
dem Hauptsatz, damit sie nach einem direkten Sprung aus einem anderen Band
sofort erreichbar sind.

Der Abschnitt in Band 08 enthält nun eine kurze Einordnung, die unveränderten
neun Hauptdeklarationen und drei knappe Verweise auf die Hilfsresultate.
Die Prosabeweise und Tabellen stehen ausschließlich in den Begleitfassungen.
Die Übertragung auf Gleichmächtigkeit in Band 11 bleibt an ihrem bisherigen Ort.

Die Lesefassung beginnt nach der Titelseite unmittelbar mit der mathematischen
Motivation. Das Kapitel „Zur Benutzung“ und der redundante Absatz „Lesepfad“
sind entfernt. Vollständiger Lesebeweis, Aussagen und Anschluss an Band 11
bleiben erhalten.

## Quellen und Verweise

- `referenzabschnitt.tex` enthält die kompakte Darstellung für B08 und den
  Gesamtband. Die gemeinsame Datei `aussagen.tex` bleibt unverändert.
- Der neue Schalter `CSBReferenz` wählt diese Darstellung. Beide
  Begleit-Einstiegspunkte deaktivieren ihn ausdrücklich.
- Die drei H-Identitäten behalten im Hauptwerk ihre alten Nummern, Labels
  und PDF-Anker. Die dortigen Hinweise führen zu eigenen semantischen
  Sprungzielen bei den jeweiligen Hilfsbeweisen in der Tabellenfassung.
- Die thematische Ordnerstruktur unter `output/` und die relative
  Verlinkung zwischen diesen Ordnern bleiben erhalten.

Die neun Hauptdeklarationen müssen in derselben Reihenfolge bleiben, weil
B00, B11 und B48 bereits darauf verweisen. Die drei H-Resultate werden
außerhalb des Beweispakets derzeit nicht verwendet; ihre bisherigen
Identitäten bleiben dennoch vollständig erreichbar.

## Prüfstand

Die Prüfungen der Einzel- und Begleitfassungen bestätigen:

- Alle 248 Zeilen des B08-Registers sowie Drucknummern und Sprunganker
  aller 154 registrierten Aussagen stimmen mit dem Stand vor der
  Auslagerung überein.
- Alle 145 bisherigen Tabellenzeilen und neun Hauptaussagen sind unverändert.
- Die Lesefassung enthält weder „Zur Benutzung“ noch den alten Lesepfad-Absatz.
- Alle drei direkten Hilfsbeweis-Links aus B08 führen zu den passenden
  semantischen Zielen in der Tabellenfassung.
- Beide Begleitfassungen sind unmittelbar auf der Seite des Hauptsatzes
  verlinkt (B08, PDF-Seite 77; Gesamtband, PDF-Seite 700). Für B08 prüft
  der dauerhafte Audit diese Position ausdrücklich; für den Gesamtband
  wurde sie am fertigen PDF ebenfalls geprüft.
- Der Register- und Verweisaudit für B00, B08 und den Gesamtband ist
  bestanden. Die Ergebnisregister und Drucknummern des Gesamtbands
  stimmen mit allen 49 Einzelbänden überein.
- Der abschließende Linkaudit aller 52 veröffentlichten PDFs ist bestanden:
  5.719 Seiten, 66.288 lokale und 38.732 dateiübergreifende Links.
  Die Seiteninhalte der fünf aktualisierten Ausgabedateien stimmen mit
  den geprüften Build-Produkten überein.
- Die 17 Seiten der beiden Begleitfassungen sowie die geänderten Abschnitte
  in B00, B08 und dem Gesamtband wurden visuell geprüft. Ungünstige
  Umbrüche vor der ersten Definition und am Beweisanfang wurden korrigiert.

Band 08 hat nun 88 statt 96 Seiten. Die Lesefassung hat sieben statt acht
Seiten; die Beweistabellen behalten ihre zehn Seiten. Der Überblick hat
unverändert 113 Seiten. Der Gesamtband hat 2.837 statt 2.845 Seiten.
Alle fünf aktualisierten PDF-Ausgaben liegen in den thematischen
Unterordnern von `output/`.

Die technischen Prüfungen sichern die Dokumentverknüpfung; die Auslagerung
verändert die mathematischen Beweise nicht.
