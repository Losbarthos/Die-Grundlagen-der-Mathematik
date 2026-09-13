# Umsetzung der beiden B21-Schlusslisten

Abgeschlossen: Theorem 21.5.5.1 (`RealSequenceLinearLimitRules`) enthält jetzt drei nummerierte neue Zeilen nach den einmalig aufgeführten gemeinsamen Prämissen. Der registrierte Hilfssatz 21.6.2.2(H2) (`B21ReserveMarkerDistinct`) enthält zwei Punkte: Typisierung der Marker und Verschiedenheitskonjunktion.

Die Quelle und das fertige Register wurden vor der Änderung unter `b21-before/` gesichert. Die alte Anzeige von 21.5.5.1 ist im neuen `FormulaThmDeltaKR` unverändert als Strukturargument erhalten. Beim Hilfssatz wurde nur das erste Anzeige-Argument geändert; sein R-Strukturargument und seine ID sind unverändert.

Unabhängige Quellenprüfung bestanden: beide ursprünglichen Strukturargumente exakt erhalten, Titel/IDs/DeltaRows unverändert, Teilnummern vollständig (3 und 2), mathematischer Inhalt nach Entfernen der Darstellungsbefehle identisch. Die gesamte Quelle außerhalb der zwei betroffenen Makroaufrufe ist bytegleich mit der Ausgangsquelle. Insbesondere sämtliche Beweise und Beweisschrittnummern bleiben unverändert. Das Register ist weiterhin bytegleich mit der Ausgangskopie.

Prüfbelege: `b21-list-changes.json`, `b21-list-changes.diff` und `b21-list-verification.json`; eigenständiger Prüfer `verify-b21-lists.py`. Keine Builds gestartet, keine PDFs erzeugt oder geändert, kein PDF-Marker erneut ausgeführt. Die PDF-Prüfung erfolgt nach dem zentral koordinierten Nachbau.
