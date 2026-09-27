# Mogiljanskaja-Gegenbeispiel: Auslagerung und PDF-Anmerkungen

Stand: 20. September 2026.

## Ergebnis

Band 28 enthält zum Gegenbeispiel ausschließlich den eigenständigen
Existenzsatz 28.2.16.7, seine Bedeutung und die Verweise auf beide
Ergänzungen. Er umfasst 229 PDF-Seiten, gegenüber ursprünglich 255 Seiten.
Die Ergänzungen liegen unter
`output/07 Halbgruppen und Monoide/Ergänzungen/Mogiljanskaja-Gegenbeispiel/`.

Die handschriftlichen Bemerkungen in der angehängten Lesefassung wurden
visuell gelesen; sie sind als Zeichnungen in die PDF-Seiten eingebettet
und keine separat extrahierbaren PDF-Kommentare. Die Häkchen bestätigen
vorhandene Beweisschritte. Die konkreten Änderungswünsche sind umgesetzt:

- Die Lage von U, V, D' und den markierten Punkten wird in einem Gitter
  gezeigt. Eine zweite Ansicht verdeutlicht die fehlende Rechteckecke.
- Die Bedeutung der Indizes in b_(n+2,j) ist ausdrücklich erklärt.
- Die Verschiebungen sigma und theta sind mit gerichteten Pfeilen dargestellt.
- Die beiden Zweige von psi sind als Abbildung zwischen vier Mengenfamilien
  gezeichnet. Für beide Zweige werden beliebige Zielmengen, ihre eindeutigen
  Urbilder und konkrete Beispiele ausführlich erläutert.
- Das ausschließlich dem Gegenbeispiel dienende Schlusskapitel aus Band 21
  ist vollständig in die Beweistabellen übernommen. Band 21 umfasst nun
  58 statt 79 PDF-Seiten und verweist auf die Ergänzungen.

Die Lesefassung umfasst nach der zweiten Anmerkungsrunde elf PDF-Seiten
einschließlich Titelblatt.
Die Beweistabellen umfassen 43 PDF-Seiten und enthalten alle 60 nummerierten Deklarationen
(18 Definitionen und 42 Theoreme), sechs zusätzliche Teilbeweis-IDs und
44 vollständige Beweistabellen. Die eigene Nummerierung beginnt mit `28E`.

## Quellen und Verweise

`tex/b28/mogiljanskaja/main-result.tex` enthält den unabhängigen Existenzsatz
im Hauptband. Er quantifiziert beide Trägermengen und beide Operationen.
Die Potenzhalbgruppenoperationen werden daraus abgeleitet.

Die Beweistabellen bestehen aus drei Kapiteln:

1. `foundations.tex`: die vormals in Band 21 stehenden speziellen Familien,
   Marker, Parametrisierungen und Bijektionen;
2. `statements.tex`: die Konstruktion der Halbgruppen und das Gegenbeispiel;
3. `details.tex`: die Einzelargumente M1 bis M17.

`reading.tex` entwickelt den Beweis in Prosa. Die drei Vektordiagramme
stehen in `reading-diagrams.tex` und werden ausschließlich von der
Lesefassung geladen. Die Wrapper liegen unter
`editions/b28-mog-{reading,proofs}.tex`.

Die allgemeinen Ergebnisse aus Band 8 und die allgemeine Folgentheorie
in Band 21 bleiben dort. Alle gegenbeispielspezifischen Aussagen besitzen
ihre maßgeblichen Verweisziele nun in der Tabellenfassung. Historische IDs
bleiben erhalten; ihre Nummern und PDF-Ziele werden über die Register
aufgelöst. Der Hauptsatz behält die ID `MogiljanskajaPairCounterexample`,
der Satz über das konkrete Paar verwendet
`MogiljanskajaConstructedPairCounterexample`.

## Erstellung und Prüfungen

Der gezielte Build erstellt B21 und B28 vor den Beweistabellen, danach die
Lesefassung sowie die betroffenen Verweisbände und den Gesamtband.
`scripts/mogiljanskaja-editions.py` importiert die vollständigen verbleibenden
Register von B21 und B28 und anschließend das Register der Beweistabellen
in die Lesefassung. Der Audit prüft 66 IDs, ihre Kapitelzuordnung, alle
semantischen Ziele und die gegenseitigen PDF-Verweise.

- Die 33 aus Band 21 übernommenen Deklarationen und die mathematischen
  Inhalte seiner 21 Tabellen sind unverändert. Lediglich Herkunftstexte,
  Verweisziele und Umbruchhilfen wurden angepasst. Die Tabellen enthalten
  316 Beweiszeilen.
- Die bisherigen 27 Konstruktionsdeklarationen und 23 Tabellen mit
  211 Beweiszeilen bleiben vollständig erhalten.
- Die neuen Erklärungen, Beispiele und Pfeilrichtungen wurden unabhängig
  mathematisch geprüft.
- Der vollständige PDF-Abhängigkeitscheck zeigt: Auf das entfernte
  B21-Schlusskapitel verweisen außerhalb der Ergänzungen nur die
  Überblicksseiten. Andere Fachbände benötigen deswegen keinen Neubau.
- Beide Ergänzungen wurden vollständig gerendert und visuell geprüft.
  Verwaiste Abschnitts- und Teilbeweisüberschriften wurden behoben.
  Die Lesefassung enthält keine lokalen nummerierten Deklarationen.
- Die geänderte Überblicksseite und das Ende von Band 21 wurden auch
  in ihrer endgültigen Darstellung geprüft, einschließlich der
  entsprechenden Seite im Gesamtband.
- Die Referenzprüfungen für B00, B21, B28, B37 und den Gesamtband sind
  bestanden. Ergebnisregister und Nummern stimmen für sämtliche Bände
  zwischen Einzel- und Gesamtausgabe überein. Der Gesamtband umfasst
  nach dem stabilen Satz 2.765 PDF-Seiten.
- Die fünf betroffenen PDFs wurden im Ausgabeordner aktualisiert.
  Die abschließende Linkprüfung aller 56 veröffentlichten PDFs ist
  bestanden: 65.009 interne und 38.715 externe Verweise.

Die technischen Prüfungen sichern Vollständigkeit, Nummerierung und
Navigation; sie sind keine maschinelle Prüfung der mathematischen Schlüsse.

## Zweite Anmerkungsrunde vom 20. September 2026

Grundlage ist die neue annotierte Downloads-PDF vom 20. September,
08:56 Uhr (315.307 Bytes, zehn Seiten). Auch diese Datei enthält die
Bemerkungen als Seitengrafik und keine extrahierbaren Kommentarobjekte.
Alle Seiten wurden gerendert und die handschriftlichen Hinweise gelesen.

- U, V und D' haben nun jeweils eine eigene Gitteransicht mit schattierter
  Zugehörigkeit. Die Rahmen des Diagramms für die beiden psi-Zweige sind
  entfernt. Die gestrichene Erklärung `n+2=(n+1)+1` entfällt.
- Vor der Zerlegung in C0 und C1 stehen das Ziel der Reserveumordnung
  und die Aufgabe beider Zweige. Wohldefiniertheit und das Kriterium
  „Jede Zielmenge hat genau ein Urbild“ sind ausdrücklich erläutert.
- Die Einschränkung von Phi auf nichtleere Mengen berücksichtigt
  Nichtleerheit von Bild und Urbild. Das L-Kriterium, die Gleichheit der
  Rechtecke und die Gleichheit der Nullanteile werden einzeln begründet.
- Die Gleichungen (*), (**), (***), (IV) und (V) sind bezeichnet und
  in den abschließenden Rechnungen direkt verknüpft.
- Ein neuer Schlussabschnitt verlinkt die
  [Originalarbeit von 1973](https://doi.org/10.1007/BF02389140).
  Er unterscheidet deren allgemeinen nilpotenten Ansatz und die Wahl
  einer Bijektion über Mächtigkeiten von unserem Spezialfall mit anderer
  Reservefamilie und ausdrücklich angegebenen Abbildungen.

Geändert wurden ausschließlich die Lesefassung und ihre Diagrammquelle.
Die Beweisschritte und der Quellenvergleich wurden unabhängig geprüft.
Der Neubau hat keine übervollen oder untervollen Boxen und keine
unaufgelösten Verweise. Alle elf Seiten wurden visuell kontrolliert.
Der Ergänzungs-Audit bestätigt weiterhin null lokale Deklarationen in der
Lesefassung, 66 Identitäten in den Beweistabellen und die beiden Verweise
am Hauptsatz in Band 28. Die Veröffentlichung ist abgeschlossen: Die
eingehenden Verweise aller Ausgabe-PDFs bleiben gültig. Auch die sieben
internen und 18 externen PDF-Verweise der neuen Lesefassung sowie der
klickbare DOI-Link sind geprüft.
