# Cantor–Bernstein: Umsetzung der Lesefassung

Stand: 18. September 2026. Umsetzung des begrenzten Piloten aus der
[Konzeption](lesefassung-und-beweise-konzept-2026-09-18.md).

**Fortschreibung:** Auf Wunsch wurden die ausführlichen Beweise anschließend
aus B08 und dem Gesamtband entfernt und durch Verweise auf die Begleitfassungen
ersetzt. Das Benutzungskapitel der Lesefassung entfällt ebenfalls. Der folgende
Bericht dokumentiert den ersten Pilotstand; die aktuelle Fassung und ihre
Prüfungen stehen im [Nachtrag zur Beweisauslagerung](cantor-bernstein-beweisauslagerung-2026-09-18.md).

## Ergebnis und Umfang

Der Cantor–Schröder–Bernstein-Abschnitt in Band 08 besitzt nun einen
zusammenhängenden mathematischen Lesebeweis. Die reguläre Band- und
Gesamtausgabe enthalten diesen Text und die vorhandenen Beweistabellen.
Zwei ergänzende PDFs stellen dieselben Aussagen mit unterschiedlicher
Beweistiefe dar:

- [Lesefassung](<../output/03 Relationen und Funktionen/Ergänzungen/Cantor-Bernstein/Bd. 08 - Cantor-Bernstein - Lesefassung.pdf>) (8 Seiten):
  Motivation, vollständiger Prosabeweis, nummerierte Aussagen und der
  spätere Anschluss an Gleichmächtigkeit in Band 11.
- [Beweistabellen](<../output/03 Relationen und Funktionen/Ergänzungen/Cantor-Bernstein/Bd. 08 - Cantor-Bernstein - Beweistabellen.pdf>) (10 Seiten):
  sämtliche bisherigen Aussagen und Ableitungen des Abschnitts aus Band 08,
  einschließlich der drei registrierten Hilfsresultate mit H-Nummern.

Band 11 erklärt die Anwendung des funktionalen Satzes auf Gleichmächtigkeit
vor der vorhandenen Ableitung. Band 00 führt in die Darstellungstiefen ein
und verlinkt die beiden Fassungen in den Übersichten zu Band 08 und Band 11.
Die Übertragungstabellen aus Band 11 bleiben dort; die ergänzende
Tabellenfassung enthält die Konstruktion aus Band 08.

Der Pilot umfasst einen Beweisabschnitt und seine Anwendung. Eine
Lesefassung aller Fachbände, der nächste Pilot in Band 27 und ein
maschineller Beweisprüfer sind weitere Ausbauschritte.

## Mathematische Ausarbeitung

Der Lesebeweis folgt der vorhandenen nichtrekursiven Konstruktion:

1. Die Familie der Teilmengen von A, die den Startbereich A ohne G[B]
   enthalten und unter dem Doppelschritt G nach F abgeschlossen sind,
   enthält A und ist daher nicht leer.
2. Ihr Durchschnitt C ist die kleinste solche Teilmenge. Die Minimalität
   liefert die Fixpunktgleichung C = (A ohne G[B]) vereinigt mit G[F[C]].
3. Aus der Fixpunktgleichung und der Injektivität von G folgt
   G[B ohne F[C]] = A ohne C.
4. Die Einschränkung von F auf C und die Umkehrung der entsprechenden
   Einschränkung von G sind Bijektionen auf disjunkte Bildbereiche. Sie
   setzen sich zur Bijektion von A nach B zusammen.

Der Text begründet jeden dieser Übergänge, behandelt auch leere Mengen
und setzt weder natürliche Rekursion noch das Auswahlaxiom voraus.
Die Umkehrfunktion wird erst nach Einschränkung auf eine Bijektion gebildet.
Der Anschluss in Band 11 ist ausdrücklich eine spätere Anwendung und
keine Voraussetzung des Beweises in Band 08.

Die tragenden Schritte wurden unabhängig gegen die vorhandenen Aussagen
und Tabellen gelesen. Die neun Hauptdeklarationen und acht Tabellenkörper
wurden bei der Auslagerung außerdem mit dem vorherigen Quelltext verglichen;
sie sind bis auf Zeilenenden unverändert.

## Gemeinsame Quellen und stabile Identitäten

Das Paket `tex/b08/cantor-bernstein/` gliedert sich in:

| Datei | Aufgabe |
| --- | --- |
| `inhalt.tex` | Gemeinsamer Abschnitt und Auswahl der Darstellung |
| `aussagen.tex` | Neun gemeinsame Hauptdeklarationen mit Voraussetzungen und IDs |
| `motivation.tex` | Vorhandene Einführung und Anschauung |
| `lesebeweis.tex` | Zusammenhängender Beweis mit Zuordnung zu den Resultaten |
| `beweistabellen.tex` | Gemeinsame Reihenfolge der Aussagen und unveränderte Tabellen |
| `b11-anschluss.tex` | Spätere Anwendung im Anhang der Lesefassung |
| `edition-setup.tex` | Getrennte Register und gezielte externe Importe |

Die beiden Einstiegspunkte liegen unter `editions/`.
`tex/impl/csb-editions.tex` definiert Darstellungsschalter und Begleitlinks.
Zusätzliche Textüberschriften erzeugen keine neuen Nummern oder
Hyperref-Abschnittsanker. Alle registrierten Aussagen, Drucknummern und
Sprungziele in B08 und B11 stimmen mit dem Arbeitsstand vor diesem Piloten
überein; vorhandene Verweise aus späteren Bänden bleiben gültig.

Die Lesefassung registriert die neun Hauptaussagen. Die Tabellenfassung
registriert zusätzlich alle drei bisherigen H-Resultate. Ausgeblendete
Tabellen löschen somit keine Identität aus der Beweisbibliothek.
Jede Fassung führt zur anderen; die Verweise auf allgemeine Werkzeuge
führen zum jeweiligen Fachband.

## Build und Prüfungen

[`build-csb-pilot.ps1`](../scripts/build-csb-pilot.ps1) baut den Piloten und
die betroffenen regulären Ausgaben. Der vollständige Build bindet diesen
Schritt ebenfalls ein. [`csb-pilot.py`](../scripts/csb-pilot.py) erzeugt
gefilterte Importe unter `registry/csb/` und vergleicht anschließend die
vollständigen Registereinträge, IDs, Drucknummern und PDF-Ziele mit B08.
Die kanonischen Register werden durch die Auszüge nicht überschrieben.

Die Veröffentlichung unter `output/` verwendet die vorhandene Pipeline
mit expliziten Dateinamenzuordnungen für beide Begleitfassungen.
Vorhandene Begleitfassungen nehmen an den allgemeinen Linkprüfungen teil.
Die Buildoptionen und Voraussetzungen sind in [BUILDING.md](../BUILDING.md)
beschrieben.

Prüfungen des aktuellen Arbeitsstands:

- B08 und B11: vollständige Register vor/nach Umsetzung identisch;
  alle registrierten Drucknummern und Sprunganker unverändert.
- Beide Begleitfassungen: Aussagen, Voraussetzungen, IDs, Nummern,
  lokale Ziele, bandübergreifende Verweise und gegenseitige Navigation geprüft.
- Buildintegration: isolierte Ablaufproben einschließlich Teilbereichen,
  Veröffentlichung und fehlendem zweiten Begleit-PDF geprüft.
- Alle 49 Einzelbände: technischer Register- und Verweisaudit bestanden.
- Quellinventar: die ausgelagerten 145 Tabellenzeilen in acht Tabellen
  werden weiterhin vollständig erfasst. Der Scan umfasst 57 Quelldateien
  mit 36.640 Tabellenzeilen und findet keine ungültigen Steuerzeichen.
  Dateipfade und Zeilenangaben beziehen sich auf die tatsächlichen Quelldateien.
- Sichtprüfung: alle 18 Seiten beider Begleitfassungen sowie die ergänzten
  Abschnitte in B00, B08, B11 und im Gesamtband geprüft. Verwaiste Überschriften wurden
  durch eine Platzreservierung vor den neuen Textüberschriften behoben.
- Gesamtband: nach drei LuaLaTeX-Durchläufen mit 2.845 Seiten gebaut;
  Registerabgleich mit allen Einzelbänden sowie technischer Verweisaudit bestanden.
- Abschließender Audit der veröffentlichten Sammlung bestanden: 52 PDFs,
  5.736 Seiten, 66.488 lokale und 38.855 externe Links. Die geprüften
  Seiteninhalte der Begleitfassungen und des Gesamtbands bleiben bei der
  Dateinamensumschreibung unverändert.

Die sechs aktualisierten PDFs liegen unter `output/`. Der Gesamtband hat
2.845 Seiten; B00 hat 113, B08 hat 96 und B11 hat 59 Seiten. Die übrigen
Fachband-PDFs wurden für diesen Piloten nicht neu veröffentlicht; ihre
Verweise wurden in der vollständigen Sammlung mitgeprüft.

Diese Prüfungen sichern Textzuordnung und Dokumenttechnik. Der manuelle
mathematische Abgleich ist keine maschinelle Verifikation der einzelnen
Schlussregeln und keine erneute Prüfung aller Fachbände.
